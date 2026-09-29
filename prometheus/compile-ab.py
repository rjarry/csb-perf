#!/usr/bin/env python3

"""
A/B compile benchmark: the wall-clock cost of the EDR sensors on a real build.

Interleaves a fixed, repeatable build with the sensors ON (falcon-sensor +
osquery + splunk) vs OFF, verifying that falcon's eBPF programs actually
detached before each "off" build and that no eBPF ran during it. Each timed
build runs inside a throwaway cgroup so the whole process tree's user/system CPU
and peak RSS are captured, and is bracketed by RAPL energy and eBPF run-time
deltas.

The machine is pinned to the "performance" governor for the duration (restored
on exit) so wall-clock is not confounded by frequency scaling. Services and
governor are always restored, even on error or Ctrl-C.

Reports per-build medians and the ON-OFF delta in wall-clock, kernel CPU,
energy and eBPF run-time, then projects the daily/annual time lost.

Must run as root (service control, cgroups, eBPF stats). The build itself runs
as --user so it does not create root-owned files in the tree.
"""

import argparse
import datetime
import json
import os
import pathlib
import pwd
import shlex
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


def prog_count():
    return sum(1 for _ in bpfstats.iter_progs())


def wait_progs_stable(timeout):
    # After stopping falcon its programs take a moment to unload. Poll the total
    # program count until it stops changing (two equal reads) or we time out.
    # Actual "were the sensors really off" validity is confirmed after the build
    # by the eBPF run-time gate, which is unambiguous.
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        c = prog_count()
        if last is not None and c == last:
            return c
        last = c
        time.sleep(0.5)
    return last


def systemctl(action, services, check=True):
    for svc in services:
        subprocess.run(["systemctl", action, svc], check=check)


def is_active(svc):
    return subprocess.run(["systemctl", "is-active", "--quiet", svc]).returncode == 0


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


def run_user(cmd, user, workdir):
    # CCACHE_DISABLE so we measure real compilation, not cache hits.
    script = f"export CCACHE_DISABLE=1; cd {shlex.quote(workdir)} && {cmd}"
    full = ["runuser", "-u", user, "--", "bash", "-lc", script]
    return subprocess.run(full, capture_output=True, text=True)


def resolve_user(explicit, workdir):
    if explicit:
        return explicit
    try:
        return pwd.getpwuid(os.stat(workdir).st_uid).pw_name
    except (KeyError, OSError):
        raise SystemExit("error: cannot determine build user; pass --user")


def measure_build(build_cmd, dirty_cmd, user, workdir, rapl, wrap):
    # dirty step is not part of the measurement
    if dirty_cmd and dirty_cmd.strip():
        d = run_user(dirty_cmd, user, workdir)
        if d.returncode != 0:
            return {"rc": d.returncode, "err": (d.stderr or d.stdout)[-800:], "phase": "dirty"}

    cg = CGROUP_BASE / f"cab-{uuid.uuid4().hex[:8]}"
    try:
        cg.mkdir()
    except OSError:
        cg = None

    def preexec():
        if cg is not None:
            with open(cg / "cgroup.procs", "w") as f:
                f.write(str(os.getpid()))

    script = f"export CCACHE_DISABLE=1; cd {shlex.quote(workdir)} && {build_cmd}"
    full = ["runuser", "-u", user, "--", "bash", "-lc", script]

    e0 = read_energy_uj(rapl)
    b0 = bpf_runtime_ns()
    t0 = time.monotonic()
    p = subprocess.run(full, capture_output=True, text=True, preexec_fn=preexec)
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


def main():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  # edit-rebuild loop, make-based project (run from the project directory)
  sudo ./compile-ab.py --build-cmd 'make -j$(nproc)'

  # meson/ninja project, full clean rebuild each repetition
  sudo ./compile-ab.py --dirty-cmd 'ninja -C build clean' \\
                       --build-cmd 'ninja -C build'

  # a different agent / service set
  sudo ./compile-ab.py --falcon-services falcon-sensor \\
                       --other-services SplunkForwarder,orbit
""",
    )
    p.add_argument("--workdir", default=os.environ.get("PWD") or os.getcwd(),
                   help="project directory to build in (default: current dir)")
    p.add_argument("--user", default=os.environ.get("SUDO_USER"),
                   help="run the build as this user "
                        "(default: $SUDO_USER, else the owner of --workdir)")
    p.add_argument("--reps", type=int, default=5)
    p.add_argument("--build-cmd", default="make",
                   help="the timed build command (ccache is disabled for it)")
    p.add_argument("--dirty-cmd",
                   default="git ls-files -- '*.c' '*.h' '*.cc' '*.cpp' '*.cxx' "
                           "'*.hpp' '*.hxx' '*.rs' '*.go' | xargs -r touch",
                   help="run before each timed build to force a rebuild (not "
                        "timed). Default touches tracked C/C++/Rust/Go sources "
                        "(the edit-rebuild loop); for a full rebuild pass e.g. "
                        "'make clean' or 'ninja -C build clean'. The default "
                        "needs git; pass your own otherwise.")
    p.add_argument("--setup-cmd", default=None,
                   help="one-time warm/setup build (default: --build-cmd)")
    p.add_argument("--falcon-services", default="falcon-sensor",
                   help="eBPF sensor service(s); detachment is verified for OFF")
    p.add_argument("--other-services", default="SplunkForwarder,orbit",
                   help="other agents stopped for the OFF build (with falcon)")
    p.add_argument("--pause-services", default="osquery-trace",
                   help="local instrument service(s) to stop for the whole run")
    p.add_argument("--governor", default="performance")
    p.add_argument("--detach-timeout", type=float, default=15.0)
    p.add_argument("--ebpf-off-max", type=float, default=0.5,
                   help="max eBPF CPU-seconds tolerated during an OFF build "
                        "before it is discarded as contaminated")
    p.add_argument("--settle", type=float, default=3.0)
    p.add_argument("--builds-per-day", type=float, default=20.0)
    p.add_argument("--out", default="/var/lib/power-exporter/compile-ab.json")
    args = p.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("error: must run as root")

    workdir = args.workdir
    user = resolve_user(args.user, workdir)
    dirty = args.dirty_cmd
    setup = args.setup_cmd or args.build_cmd
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

    saved_gov = get_governors()
    on_runs, off_runs = [], []
    discarded = 0

    print(f"workdir={workdir} reps={args.reps} user={user}", file=sys.stderr)
    print(f"build-cmd: {args.build_cmd}", file=sys.stderr)

    try:
        set_governor(args.governor)
        systemctl("stop", paused, check=False)

        # ensure fully built & warm before timing anything
        print("warm/setup build...", file=sys.stderr)
        w = run_user(setup, user, workdir)
        if w.returncode != 0:
            raise SystemExit(f"setup build failed:\n{w.stderr[-2000:]}")

        for rep in range(args.reps):
            print(f"\n=== rep {rep + 1}/{args.reps} ===", file=sys.stderr)

            # ---- ON ----
            systemctl("start", falcon + others, check=False)
            time.sleep(args.settle)
            on = measure_build(args.build_cmd, dirty, user, workdir, rapl, wrap)
            if on.get("rc", 1) != 0:
                print(f"  ON build failed: {on.get('err','')}", file=sys.stderr)
            else:
                on_runs.append(on)
                print(f"  ON : wall={fmt(on['wall_s'],'s',2)} "
                      f"sys={fmt(on['sys_s'],'s',1)} ebpf={fmt(on['ebpf_s'],'s',2)} "
                      f"E={fmt(on['energy_j'],'J',0)}", file=sys.stderr)

            # ---- OFF ----
            on_count = prog_count()
            systemctl("stop", others, check=False)
            systemctl("stop", falcon, check=False)
            off_count = wait_progs_stable(args.detach_timeout)
            if is_active(falcon[0]):
                print("  falcon still active after stop; skipping OFF", file=sys.stderr)
                systemctl("start", falcon + others, check=False)
                continue
            print(f"  eBPF progs {on_count} -> {off_count} after stop", file=sys.stderr)
            time.sleep(args.settle)
            off = measure_build(args.build_cmd, dirty, user, workdir, rapl, wrap)
            falcon_back = is_active(falcon[0])
            # restore immediately
            systemctl("start", falcon + others, check=False)

            if off.get("rc", 1) != 0:
                print(f"  OFF build failed: {off.get('err','')}", file=sys.stderr)
            elif falcon_back or off["ebpf_s"] > args.ebpf_off_max:
                discarded += 1
                print(f"  OFF contaminated (falcon_back={falcon_back} "
                      f"ebpf={fmt(off['ebpf_s'],'s',2)}); discarded", file=sys.stderr)
            else:
                off_runs.append(off)
                print(f"  OFF: wall={fmt(off['wall_s'],'s',2)} "
                      f"sys={fmt(off['sys_s'],'s',1)} ebpf={fmt(off['ebpf_s'],'s',2)} "
                      f"E={fmt(off['energy_j'],'J',0)}", file=sys.stderr)
    finally:
        systemctl("start", falcon + others, check=False)
        systemctl("start", paused, check=False)
        restore_governors(saved_gov)
        os.close(stats_fd)
        print("\nrestored services and governor", file=sys.stderr)

    def agg(runs, key):
        return med([r[key] for r in runs])

    summary = {
        "captured_at": datetime.datetime.now().astimezone().isoformat(),
        "kernel": os.uname().release,
        "workdir": workdir,
        "reps_on": len(on_runs),
        "reps_off": len(off_runs),
        "discarded_off": discarded,
        "on": {k: agg(on_runs, k) for k in ("wall_s", "user_s", "sys_s", "energy_j", "ebpf_s", "peak_rss")},
        "off": {k: agg(off_runs, k) for k in ("wall_s", "user_s", "sys_s", "energy_j", "ebpf_s", "peak_rss")},
        "on_wall_all": [r["wall_s"] for r in on_runs],
        "off_wall_all": [r["wall_s"] for r in off_runs],
    }

    wo, wf = summary["on"]["wall_s"], summary["off"]["wall_s"]
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2) + "\n")

    print("\n================= RESULT =================")
    print(f"reps: ON={len(on_runs)} OFF={len(off_runs)} "
          f"(discarded OFF={discarded})")
    print(f"wall-clock   ON {fmt(wo,'s',2)}   OFF {fmt(wf,'s',2)}")
    if wo and wf:
        dw = wo - wf
        print(f"  -> EDR costs {dw:+.2f}s per build "
              f"({dw / wf * 100:+.1f}% slower)")
        bpd = args.builds_per_day
        print(f"  -> at {bpd:g} builds/day: {dw * bpd / 60:.1f} min/day, "
              f"{dw * bpd * 230 / 3600:.1f} h/year/engineer")
    print(f"kernel CPU   ON {fmt(summary['on']['sys_s'],'s',1)}   "
          f"OFF {fmt(summary['off']['sys_s'],'s',1)}", end="")
    so, sf = summary["on"]["sys_s"], summary["off"]["sys_s"]
    if so and sf:
        print(f"   (+{so - sf:.1f}s system time per build)")
    else:
        print()
    print(f"energy/build ON {fmt(summary['on']['energy_j'],'J',0)}   "
          f"OFF {fmt(summary['off']['energy_j'],'J',0)}", end="")
    eo, ef = summary["on"]["energy_j"], summary["off"]["energy_j"]
    if eo and ef:
        print(f"   (+{eo - ef:.0f} J per build)")
    else:
        print()
    print(f"eBPF CPU     ON {fmt(summary['on']['ebpf_s'],'s',2)}   "
          f"OFF {fmt(summary['off']['ebpf_s'],'s',2)} (should be ~0)")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
