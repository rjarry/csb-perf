#!/usr/bin/env python3

"""
A/B git benchmark: the wall-clock cost of the EDR sensors on three everyday git
operations against the real Linux kernel tree: a fresh `git clone` (heavy on
object writes and file creation), a `git pull --rebase` on an
already-up-to-date branch (no objects to transfer, but git still lstat()s
every tracked file in the working tree to confirm there is nothing to do -
exactly the kind of per-file syscall that EDR hooks tax), and a `git worktree`
add+remove cycle (checks out and then deletes every tracked file, a burst of
file creation and removal).

Runs every operation (clone, pull, worktree) for all repetitions with the
sensors ON (falcon-sensor + osquery + splunk), then disables them once and
re-runs every operation with them OFF, so the sensors are stopped and started
only once for the whole benchmark. Verifies that falcon's eBPF programs
actually detached before the "off" runs and that no eBPF ran during them. Each
timed run happens inside a throwaway cgroup so the whole process tree's
user/system CPU and peak RSS are captured, and is bracketed by RAPL energy and
eBPF run-time deltas.

The machine is pinned to the "performance" governor for the duration (restored
on exit) so wall-clock is not confounded by frequency scaling. Services and
governor are always restored, even on error or Ctrl-C.

The clone test clones and deletes the full upstream repository on every
repetition, so it is slow and network-bound; keep --clone-reps low, or pass
--clone-args '--depth 1' (or a --reference to a local mirror) to speed up
iteration. The pull and worktree tests share a single clone made once up front:
the pull test resyncs to the upstream tip before each timed `git pull --rebase`
(so the timed command is always a no-op fast-forward check), and the worktree
test times a full `git worktree add --detach ... HEAD && git worktree remove`
cycle.

Reports per-run medians and the ON-OFF delta in wall-clock, kernel CPU, energy
and eBPF run-time, then projects the daily/annual time lost.

Must run as root (service control, cgroups, eBPF stats). git itself runs as
--user so it does not create root-owned files.
"""

import argparse
import datetime
import json
import os
import pathlib
import pwd
import shlex
import shutil
import statistics
import subprocess
import sys
import time
import uuid

import bpfstats

RAPL_BASE = pathlib.Path("/sys/class/powercap")
CPUFREQ = pathlib.Path("/sys/devices/system/cpu")
CGROUP_BASE = pathlib.Path("/sys/fs/cgroup")


def find_rapl():
    best = None
    for path in RAPL_BASE.glob("intel-rapl:*"):
        name = (path / "name").read_text().strip()
        if name == "psys":
            return path
        if best is None:
            best = path
    return best


def read_energy_uj(rapl):
    return int((rapl / "energy_uj").read_text())


def energy_wrap(rapl):
    try:
        return int((rapl / "max_energy_range_uj").read_text())
    except (OSError, ValueError):
        return None


def bpf_runtime_ns():
    return sum(p["run_time_ns"] for p in bpfstats.iter_progs())


def falcon_prog_ids(comm):
    # Plain-Python equivalent of
    #   bpftool prog show -j | jq '.[] | select(.pids[0].comm == comm)'
    # A loaded eBPF program is "owned" by every process holding an fd to it, and
    # each such fd appears in /proc/<pid>/fdinfo/<fd> as a "prog_id:" line (this
    # is exactly how bpftool builds its pids[].comm field). We map those program
    # ids back to the owning process's comm and keep the sensor's. The kernel
    # truncates comm to 15 bytes, so "falcon-sensor-bpf" shows up as
    # "falcon-sensor-b".
    ids = set()
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm") as f:
                if f.read().strip() != comm:
                    continue
            fdinfo = f"/proc/{pid}/fdinfo"
            for fd in os.listdir(fdinfo):
                try:
                    with open(f"{fdinfo}/{fd}") as f:
                        for line in f:
                            if line.startswith("prog_id:"):
                                ids.add(int(line.split()[1]))
                                break
                except OSError:
                    continue
        except OSError:
            continue
    return ids


def verify_detached(comm, timeout):
    # Falcon's eBPF programs take a moment to unload after the service stops, and
    # a watchdog restart reloads them (possibly under a fresh pid). Poll until no
    # program is owned by the sensor process any more. We gate on this rather
    # than on systemctl is-active, which a managed sensor flips back to active
    # while its hooks stay down; a mid-window reload is still caught afterwards by
    # the eBPF run-time gate.
    deadline = time.monotonic() + timeout
    while True:
        remaining = len(falcon_prog_ids(comm))
        if remaining == 0:
            return True, 0
        if time.monotonic() >= deadline:
            return False, remaining
        time.sleep(0.5)


def verify_attached(comm, timeout, settle):
    # The reverse of verify_detached, but the stop condition is different. Going
    # down there is an absolute target (0 programs); going up the final count N
    # is unknown (it varies by sensor version/config) and falcon loads its
    # programs progressively, so "count > 0" can fire mid-load and leave the ON
    # run only half-armed. Instead we wait for the count to plateau: nonzero and
    # unchanged for `settle` seconds. A watchdog reload that bumps the count
    # mid-startup resets the plateau, so we wait for it to settle again.
    deadline = time.monotonic() + timeout
    last = -1
    stable_since = None
    while True:
        n = len(falcon_prog_ids(comm))
        now = time.monotonic()
        if n != last:
            last = n
            stable_since = now if n > 0 else None
        if stable_since is not None and now - stable_since >= settle:
            return True, n
        if now >= deadline:
            return n > 0, n
        time.sleep(0.5)


def systemctl(action, services, check=True):
    for svc in services:
        subprocess.run(["systemctl", action, svc], check=check)


def get_governors():
    govs = {}
    for g in CPUFREQ.glob("cpu[0-9]*/cpufreq/scaling_governor"):
        try:
            govs[g] = g.read_text().strip()
        except OSError:
            pass
    return govs


def set_governor(gov):
    n = 0
    for g in CPUFREQ.glob("cpu[0-9]*/cpufreq/scaling_governor"):
        try:
            g.write_text(gov)
            n += 1
        except OSError:
            pass
    return n


def restore_governors(saved):
    for g, v in saved.items():
        try:
            g.write_text(v)
        except OSError:
            pass


def run_user(cmd, user, cwd):
    full = [
        "runuser",
        "-u",
        user,
        "--",
        "bash",
        "-lc",
        f"cd {shlex.quote(cwd)} && {cmd}",
    ]
    return subprocess.run(full, capture_output=True, text=True, check=False)


def resolve_user(explicit):
    if explicit:
        return explicit
    raise SystemExit("error: cannot determine git user; pass --user")


def ensure_owned_dir(path, user):
    path.mkdir(parents=True, exist_ok=True)
    pw = pwd.getpwnam(user)
    os.chown(path, pw.pw_uid, pw.pw_gid)


def repo_name(url):
    name = url.rstrip("/").rsplit("/", 1)[-1]
    return name.removesuffix(".git")


def ensure_repo(path, url, user, base):
    # one-time clone shared by the pull and worktree tests (both need an
    # existing working tree, not a fresh transfer)
    if (path / ".git").exists():
        return
    print(f"cloning once into {path.name}...", file=sys.stderr)
    c = run_user(
        f"git clone --quiet {shlex.quote(url)} {shlex.quote(str(path))}",
        user,
        str(base),
    )
    if c.returncode != 0:
        raise SystemExit(f"setup clone failed:\n{c.stderr[-2000:]}")


def measure_cmd(cmd, dirty_cmd, user, cwd, rapl, wrap):
    # dirty step is not part of the measurement
    if dirty_cmd and dirty_cmd.strip():
        d = run_user(dirty_cmd, user, cwd)
        if d.returncode != 0:
            return {
                "rc": d.returncode,
                "err": (d.stderr or d.stdout)[-800:],
                "phase": "dirty",
            }

    cg = CGROUP_BASE / f"gab-{uuid.uuid4().hex[:8]}"
    try:
        cg.mkdir()
    except OSError:
        cg = None

    def preexec():
        if cg is not None:
            with open(cg / "cgroup.procs", "w") as f:
                f.write(str(os.getpid()))

    full = [
        "runuser",
        "-u",
        user,
        "--",
        "bash",
        "-lc",
        f"cd {shlex.quote(cwd)} && {cmd}",
    ]

    e0 = read_energy_uj(rapl)
    b0 = bpf_runtime_ns()
    t0 = time.monotonic()
    p = subprocess.run(
        full, capture_output=True, text=True, preexec_fn=preexec, check=False
    )
    t1 = time.monotonic()
    b1 = bpf_runtime_ns()
    e1 = read_energy_uj(rapl)

    user_s = sys_s = peak = None
    if cg is not None:
        try:
            for line in (cg / "cpu.stat").read_text().splitlines():
                k, _, v = line.partition(" ")
                if k == "user_usec":
                    user_s = int(v) / 1e6
                elif k == "system_usec":
                    sys_s = int(v) / 1e6
        except OSError:
            pass
        try:
            peak = int((cg / "memory.peak").read_text())
        except (OSError, ValueError):
            pass
        for _ in range(20):
            try:
                cg.rmdir()
                break
            except OSError:
                time.sleep(0.1)

    de = e1 - e0
    if wrap and de < 0:
        de += wrap
    return {
        "rc": p.returncode,
        "err": (p.stderr or "")[-800:] if p.returncode else "",
        "wall_s": t1 - t0,
        "user_s": user_s,
        "sys_s": sys_s,
        "peak_rss": peak,
        "energy_j": de / 1e6,
        "ebpf_s": (b1 - b0) / 1e9,
    }


def med(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def fmt(x, u="", n=1):
    return f"{x:.{n}f}{u}" if x is not None else "n/a"


def measure_reps(spec, state, user, rapl, wrap, ebpf_off_max):
    # Run every repetition of one test with the sensor in its current state
    # ("ON" or "OFF"). The caller toggles the sensor once around the whole batch
    # of tests, not here. OFF runs whose eBPF run-time exceeds ebpf_off_max are
    # discarded as contaminated by a mid-window sensor reload.
    name = spec["name"]
    reps = spec["reps"]
    runs = []
    discarded = 0
    for rep in range(reps):
        print(f"\n=== {name} {state} rep {rep + 1}/{reps} ===", file=sys.stderr)
        m = measure_cmd(spec["cmd"], spec["dirty"], user, spec["cwd"], rapl, wrap)
        if m.get("rc", 1) != 0:
            print(f"  {state} run failed: {m.get('err','')}", file=sys.stderr)
            continue
        if state == "OFF" and m["ebpf_s"] > ebpf_off_max:
            discarded += 1
            print(
                f"  OFF contaminated (ebpf={fmt(m['ebpf_s'],'s',2)} "
                f"> {ebpf_off_max:g}s); discarded",
                file=sys.stderr,
            )
            continue
        runs.append(m)
        print(
            f"  {state:<3}: wall={fmt(m['wall_s'],'s',2)} "
            f"sys={fmt(m['sys_s'],'s',1)} ebpf={fmt(m['ebpf_s'],'s',2)} "
            f"E={fmt(m['energy_j'],'J',0)}",
            file=sys.stderr,
        )
    return runs, discarded


def summarize(on_runs, off_runs, discarded):
    def agg(runs, key):
        return med([r[key] for r in runs])

    keys = ("wall_s", "user_s", "sys_s", "energy_j", "ebpf_s", "peak_rss")
    return {
        "reps_on": len(on_runs),
        "reps_off": len(off_runs),
        "discarded_off": discarded,
        "on": {k: agg(on_runs, k) for k in keys},
        "off": {k: agg(off_runs, k) for k in keys},
        "on_wall_all": [r["wall_s"] for r in on_runs],
        "off_wall_all": [r["wall_s"] for r in off_runs],
    }


def print_report(name, s, ops_per_day):
    on, off = s["on"], s["off"]
    wo, wf = on["wall_s"], off["wall_s"]
    print(f"\n================= {name} RESULT =================")
    print(
        f"reps: ON={s['reps_on']} OFF={s['reps_off']} "
        f"(discarded OFF={s['discarded_off']})"
    )
    print(f"wall-clock   ON {fmt(wo,'s',2)}   OFF {fmt(wf,'s',2)}")
    if wo and wf:
        dw = wo - wf
        print(f"  -> EDR costs {dw:+.2f}s per run " f"({dw / wf * 100:+.1f}% slower)")
        print(
            f"  -> at {ops_per_day:g} runs/day: {dw * ops_per_day / 60:.1f} min/day, "
            f"{dw * ops_per_day * 230 / 3600:.1f} h/year/engineer"
        )
    print(
        f"kernel CPU   ON {fmt(on['sys_s'],'s',1)}   " f"OFF {fmt(off['sys_s'],'s',1)}",
        end="",
    )
    so, sf = on["sys_s"], off["sys_s"]
    if so and sf:
        print(f"   (+{so - sf:.1f}s system time per run)")
    else:
        print()
    print(
        f"energy/run   ON {fmt(on['energy_j'],'J',0)}   "
        f"OFF {fmt(off['energy_j'],'J',0)}",
        end="",
    )
    eo, ef = on["energy_j"], off["energy_j"]
    if eo and ef:
        print(f"   (+{eo - ef:.0f} J per run)")
    else:
        print()
    print(
        f"eBPF CPU     ON {fmt(on['ebpf_s'],'s',2)}   "
        f"OFF {fmt(off['ebpf_s'],'s',2)} (should be ~0)"
    )


class HelpFormatter(
    argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter
):
    pass


def main():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=HelpFormatter,
        epilog="""\
examples:
  # default: full A/B of clone + pull + worktree against the Linux kernel repo
  sudo ./git-ab.py

  # only the pull and worktree tests, more reps
  sudo ./git-ab.py --skip-clone --pull-reps 10 --worktree-reps 10

  # faster clone iterations: shallow clone, fewer reps
  sudo ./git-ab.py --skip-pull --skip-worktree --clone-reps 2 \\
                   --clone-args '--depth 1'

  # a different agent / service set
  sudo ./git-ab.py --falcon-services falcon-sensor \\
                   --other-services SplunkForwarder,orbit
""",
    )
    p.add_argument(
        "--repo-url",
        default="https://github.com/torvalds/linux",
        help="repository to clone/pull",
    )
    p.add_argument(
        "--workdir",
        default="/var/tmp/git-ab",
        help="scratch directory holding the clone and pull trees",
    )
    p.add_argument(
        "--user",
        default=os.environ.get("SUDO_USER"),
        help="run git as this user (default: $SUDO_USER)",
    )
    p.add_argument("--skip-clone", action="store_true", help="skip the git-clone test")
    p.add_argument("--skip-pull", action="store_true", help="skip the git-pull test")
    p.add_argument(
        "--skip-worktree", action="store_true", help="skip the git-worktree test"
    )
    p.add_argument(
        "--clone-reps", type=int, default=3, help="number of clone test repetitions"
    )
    p.add_argument(
        "--pull-reps", type=int, default=5, help="number of pull test repetitions"
    )
    p.add_argument(
        "--worktree-reps",
        type=int,
        default=5,
        help="number of worktree test repetition",
    )
    p.add_argument(
        "--clone-args",
        default="",
        help="""
        extra args spliced into 'git clone <args> <url> <dir>', e.g. '--depth
        1' or '--reference /path --dissociate' to speed up repeated runs
        """,
    )
    p.add_argument(
        "--falcon-services",
        default="falcon-sensor",
        help="eBPF sensor service(s); detachment is verified for OFF",
    )
    p.add_argument(
        "--other-services",
        default="SplunkForwarder,orbit",
        help="other agents stopped for the OFF run (with falcon)",
    )
    p.add_argument(
        "--pause-services",
        default="osquery-trace",
        help="local instrument service(s) to stop for the whole run",
    )
    p.add_argument(
        "--governor", default="performance", help="CPU governor to set during tests"
    )
    p.add_argument("--detach-timeout", type=float, default=15.0)
    p.add_argument(
        "--falcon-comm",
        default="falcon-sensor-b",
        help="process name (comm, truncated to 15 bytes by the kernel) that owns "
        "the sensor's eBPF programs; its program count gates the ON/OFF runs",
    )
    p.add_argument(
        "--ebpf-off-max",
        type=float,
        default=0.5,
        help="""
        max eBPF CPU-seconds tolerated during an OFF run before it is discarded
        as contaminated
        """,
    )
    p.add_argument("--settle", type=float, default=3.0)
    p.add_argument("--clones-per-day", type=float, default=5.0)
    p.add_argument("--pulls-per-day", type=float, default=20.0)
    p.add_argument("--worktrees-per-day", type=float, default=10.0)
    p.add_argument("--out", default="/var/lib/power-exporter/git-ab.json")
    args = p.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("error: must run as root")

    user = resolve_user(args.user)
    falcon = [s for s in args.falcon_services.split(",") if s]
    others = [s for s in args.other_services.split(",") if s]
    paused = [s for s in args.pause_services.split(",") if s]

    rapl = find_rapl()
    if not rapl:
        raise SystemExit("error: no RAPL domain")
    wrap = energy_wrap(rapl)

    stats_fd = bpfstats.enable_stats()
    if stats_fd is None:
        raise SystemExit("error: could not enable eBPF run-time stats")

    base = pathlib.Path(args.workdir)
    ensure_owned_dir(base, user)

    saved_gov = get_governors()
    results = {}

    print(f"repo={args.repo_url} user={user} workdir={base}", file=sys.stderr)

    try:
        set_governor(args.governor)
        systemctl("stop", paused, check=False)

        # Build the list of tests (with their one-time setup) up front, then run
        # every test with the sensor ON, stop it once, and run every test again
        # with it OFF - toggling the sensor a single time for the whole benchmark
        # instead of once per test.
        tests = []
        cleanups = []

        if not args.skip_clone:
            print("\n### clone test ###", file=sys.stderr)
            clone_parent = base / "clone-ab"
            ensure_owned_dir(clone_parent, user)
            target = repo_name(args.repo_url)

            dirty = f"rm -rf {shlex.quote(target)}"
            clone_args = args.clone_args.strip()
            cmd = "git clone --quiet"
            if clone_args:
                cmd += f" {clone_args}"
            cmd += f" {shlex.quote(args.repo_url)} {shlex.quote(target)}"

            tests.append(
                {
                    "name": "clone",
                    "cmd": cmd,
                    "dirty": dirty,
                    "cwd": str(clone_parent),
                    "reps": args.clone_reps,
                }
            )
            cleanups.append(clone_parent / target)

        repo_dir = base / "repo-ab"

        if not args.skip_pull:
            print("\n### pull test ###", file=sys.stderr)
            ensure_repo(repo_dir, args.repo_url, user, base)

            # resync to the upstream tip before each timed pull, so that
            # 'git pull --rebase' always starts from an already-up-to-date
            # branch and has nothing to fetch or replay.
            dirty = "git fetch --quiet origin && git reset --quiet --hard @{u}"
            cmd = "git pull --rebase"

            tests.append(
                {
                    "name": "pull",
                    "cmd": cmd,
                    "dirty": dirty,
                    "cwd": str(repo_dir),
                    "reps": args.pull_reps,
                }
            )

        if not args.skip_worktree:
            print("\n### worktree test ###", file=sys.stderr)
            ensure_repo(repo_dir, args.repo_url, user, base)
            wt = str(base / "wt-ab")

            # clean up any worktree left behind by an interrupted run (no-op
            # otherwise); a full cycle leaves nothing on disk itself
            dirty = f"rm -rf {shlex.quote(wt)} && git worktree prune"
            # one timed add+remove cycle: check out, then delete, every tracked
            # file in the tree - a burst of file creation and removal that EDR
            # file hooks tax on every path.
            cmd = (
                f"git worktree add --quiet --detach {shlex.quote(wt)} HEAD && "
                f"git worktree remove {shlex.quote(wt)}"
            )

            tests.append(
                {
                    "name": "worktree",
                    "cmd": cmd,
                    "dirty": dirty,
                    "cwd": str(repo_dir),
                    "reps": args.worktree_reps,
                }
            )
            cleanups.append(pathlib.Path(wt))

        on_runs = {t["name"]: [] for t in tests}
        off_runs = {t["name"]: [] for t in tests}
        discarded = {t["name"]: 0 for t in tests}

        if tests:
            # ---- ON: every test, all reps, with the sensor armed ----
            # wait until the sensor is fully armed before trusting the ON
            # measurements: on the way up its eBPF program count climbs
            # progressively toward an unknown total, so we wait for it to plateau
            # (see verify_attached) rather than merely become nonzero
            systemctl("start", falcon + others, check=False)
            ok, n_on = verify_attached(
                args.falcon_comm, args.detach_timeout, args.settle
            )
            if ok:
                print(f"\nsensor ON ({n_on} eBPF progs loaded)", file=sys.stderr)
                for t in tests:
                    on_runs[t["name"]], _ = measure_reps(
                        t, "ON", user, rapl, wrap, args.ebpf_off_max
                    )
            else:
                print(
                    f"\nsensor '{args.falcon_comm}' has no eBPF progs loaded; "
                    "skipping ON runs",
                    file=sys.stderr,
                )

            # ---- OFF: stop the sensor once, then every test, all reps ----
            # gate on whether the sensor's eBPF programs actually detached, not
            # on systemctl is-active (a managed sensor reports active again
            # almost immediately while its hooks stay down)
            systemctl("stop", others, check=False)
            systemctl("stop", falcon, check=False)
            ok, remaining = verify_detached(args.falcon_comm, args.detach_timeout)
            if ok:
                print("\nsensor OFF (0 eBPF progs remain)", file=sys.stderr)
                time.sleep(args.settle)
                try:
                    for t in tests:
                        off_runs[t["name"]], discarded[t["name"]] = measure_reps(
                            t, "OFF", user, rapl, wrap, args.ebpf_off_max
                        )
                finally:
                    # restore the sensor once, after every OFF run
                    systemctl("start", falcon + others, check=False)
            else:
                print(
                    f"\nsensor BPF not detached ({remaining} progs remain); "
                    "skipping OFF runs",
                    file=sys.stderr,
                )
                systemctl("start", falcon + others, check=False)

        for path in cleanups:
            shutil.rmtree(path, ignore_errors=True)

        for t in tests:
            name = t["name"]
            results[name] = summarize(on_runs[name], off_runs[name], discarded[name])
    finally:
        systemctl("start", falcon + others, check=False)
        systemctl("start", paused, check=False)
        restore_governors(saved_gov)
        os.close(stats_fd)
        print("\nrestored services and governor", file=sys.stderr)

    summary = {
        "captured_at": datetime.datetime.now().astimezone().isoformat(),
        "kernel": os.uname().release,
        "repo_url": args.repo_url,
        **results,
    }
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2) + "\n")

    if "clone" in results:
        print_report("CLONE", results["clone"], args.clones_per_day)
    if "pull" in results:
        print_report("PULL", results["pull"], args.pulls_per_day)
    if "worktree" in results:
        print_report("WORKTREE", results["worktree"], args.worktrees_per_day)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
