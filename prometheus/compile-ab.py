#!/usr/bin/env python3

"""
A/B compile benchmark: the wall-clock cost of the EDR sensors on a real build.

Interleaves a fixed, repeatable build in three variants: with the sensors ON
(falcon-sensor + osquery + splunk), with them ON but falcon capped to a
CPUQuota (--falcon-quota, 5% by default), and with them OFF. It verifies that
falcon's eBPF programs really attached before each "on" build and really
detached before each "off" one, and discards any "off" build during which eBPF
still ran. Each timed build runs inside a throwaway cgroup so the whole process
tree's user/system CPU and peak RSS are captured, and is bracketed by RAPL
energy and eBPF run-time deltas.

The quota variant answers "can we just cap the thing?". The property is applied
to the running service, so the eBPF programs stay exactly as they were, and
only the daemon's own threads are starved. Since the hooks run in the context
of the build's processes - charged to the build's cgroup, not the sensor's -
the quota cannot reach them, and the report shows how much of the sensor's cost
survives being throttled. The service cgroup's throttled_usec confirms the cap
actually bound.

For the ON builds the sensor process's own cost is measured too: its CPU time
(total and system), its resident memory, and a CPU-time-proportional share of
the package energy counting both its own CPU and the in-kernel eBPF run-time
its hooks add to the build's syscalls. Both CPU figures are also reported as
CPU-equivalents - how many CPUs the sensor keeps continuously busy for as long
as the build lasts - which is the "it costs us N cores" number, and its RSS is
put next to the build's own peak and the installed RAM.

eBPF run-time is attributed per program: the contamination gate uses every
loaded program, but what is charged to falcon is only the programs it owns
(the ones whose fds are held by --falcon-comm), so osquery's publisher does not
end up on falcon's bill.

The build and falcon can each be confined to a subset of CPUs (--build-cpus,
--falcon-cpus): the build through the cpuset of its measurement cgroup, falcon
through a runtime AllowedCPUs property, cleared on exit. Note that confining
falcon only moves its userspace threads: its eBPF programs still run in the
context of whichever build process trips the hook, on that process's CPU. The
sensor and eBPF CPU-equivalents separate exactly those two costs.

The machine is pinned to the "performance" governor for the duration (restored
on exit) so wall-clock is not confounded by frequency scaling. Services,
governor and CPU affinity are always restored, even on error or Ctrl-C.

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
CLK_TCK = os.sysconf("SC_CLK_TCK")
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")

MEASURES = (
    "wall_s",
    "user_s",
    "sys_s",
    "energy_j",
    "ebpf_s",
    "ebpf_falcon_s",
    "peak_rss",
    "sensor_cpu_s",
    "sensor_sys_s",
    "sensor_rss",
    "sensor_energy_j",
    "cpus_sensor",
    "cpus_ebpf",
    "throttled_s",
)


def cpu_topology():
    # online logical CPUs, and how many distinct physical cores back them
    logical = 0
    cores = set()
    for core_id in CPUFREQ.glob("cpu[0-9]*/topology/core_id"):
        try:
            core = core_id.read_text().strip()
            pkg = (core_id.parent / "physical_package_id").read_text().strip()
        except OSError:
            continue
        logical += 1
        cores.add((pkg, core))
    return logical, len(cores)


def read_mem_total():
    for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) * 1024
    return None


def count_cpus(spec):
    # number of CPUs in a cpuset list like "0-7,10"
    n = 0
    for part in spec.split(","):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        n += int(hi) - int(lo) + 1 if hi else 1
    return n


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


def bpf_runtime_by_id():
    return {p["id"]: p["run_time_ns"] for p in bpfstats.iter_progs()}


def runtime_delta(b0, b1, ids=None):
    # eBPF CPU-seconds burned between two snapshots, optionally restricted to a
    # set of program ids. Matching per id (rather than summing both snapshots)
    # keeps programs that unloaded in between from subtracting their whole
    # lifetime run-time; a program that appeared in between counts in full,
    # which is what the OFF contamination gate wants.
    ns = 0
    for prog_id, t1 in b1.items():
        if ids is not None and prog_id not in ids:
            continue
        ns += t1 - b0.get(prog_id, 0)
    return ns / 1e9


def read_total_cpu_s():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:]]
    # user + nice + system + irq + softirq + steal (idle/iowait excluded;
    # guest/guest_nice are already folded into user/nice)
    busy = v[0] + v[1] + v[2] + v[5] + v[6]
    if len(v) > 7:
        busy += v[7]
    return busy / CLK_TCK


def read_comm_cpu(comm):
    # The sensor's own cost, summed over every process whose comm matches. The
    # kernel truncates comm to 15 bytes, so "falcon-sensor-bpf" reads back as
    # "falcon-sensor-b". Returns (cpu_s, sys_s, rss) or None when no such
    # process exists, i.e. the sensor is not running.
    cpu_s = sys_s = 0.0
    rss = 0
    found = False
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/stat") as f:
                stat = f.read()
            end = stat.rindex(")")
            if stat[stat.index("(") + 1 : end] != comm:
                continue
            fields = stat[end + 2 :].split()
            utime, stime, rss_pages = int(fields[11]), int(fields[12]), int(fields[21])
        except (OSError, ValueError):
            continue
        cpu_s += (utime + stime) / CLK_TCK
        sys_s += stime / CLK_TCK
        rss += rss_pages * PAGE_SIZE
        found = True
    return (cpu_s, sys_s, rss) if found else None


def falcon_prog_ids(comm):
    # Plain-Python equivalent of
    #   bpftool prog show -j | jq '.[] | select(.pids[0].comm == comm)'
    # A loaded eBPF program is "owned" by every process holding an fd to it, and
    # each such fd appears in /proc/<pid>/fdinfo/<fd> as a "prog_id:" line (this
    # is exactly how bpftool builds its pids[].comm field). We map those program
    # ids back to the owning process's comm and keep the sensor's.
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
    # while its hooks stay down; a mid-build reload is still caught afterwards by
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
    # programs progressively, so "count > 0" can fire mid-load and leave the
    # build only half-armed. Instead we wait for the count to plateau: nonzero
    # and unchanged for `settle` seconds.
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


def set_property(services, prop, value):
    # Runtime-only properties: dropped on reboot, and cleared by passing an
    # empty value. They apply to a running service without restarting it, and
    # survive the restarts the benchmark does every rep, unlike writing
    # cpuset.cpus or cpu.max into the service cgroup by hand.
    for svc in services:
        subprocess.run(
            ["systemctl", "set-property", "--runtime", svc, f"{prop}={value}"],
            check=False,
        )


def read_cpu_max(cg):
    try:
        return (cg / "cpu.max").read_text().strip()
    except OSError:
        return None


def read_throttled_s(cg):
    # seconds the cgroup spent throttled by its CPUQuota, cumulative
    try:
        for line in (cg / "cpu.stat").read_text().splitlines():
            k, _, v = line.partition(" ")
            if k == "throttled_usec":
                return int(v) / 1e6
    except (OSError, ValueError):
        pass
    return None


def enable_cpuset():
    # cpuset.cpus only exists in a cgroup if its parent delegates the
    # controller; systemd usually already does at the root.
    ctl = CGROUP_BASE / "cgroup.subtree_control"
    try:
        if "cpuset" in ctl.read_text().split():
            return True
        ctl.write_text("+cpuset")
        return True
    except OSError:
        return False


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


def measure_build(build_cmd, dirty_cmd, user, workdir, rapl, wrap, comm, build_cpus,
                  sensor_cg):
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
    if build_cpus:
        try:
            (cg / "cpuset.cpus").write_text(build_cpus)
        except (OSError, TypeError):
            return {"rc": 1, "err": f"cannot confine the build to CPUs {build_cpus}",
                    "phase": "cpuset"}

    def preexec():
        if cg is not None:
            with open(cg / "cgroup.procs", "w") as f:
                f.write(str(os.getpid()))

    script = f"export CCACHE_DISABLE=1; cd {shlex.quote(workdir)} && {build_cmd}"
    full = ["runuser", "-u", user, "--", "bash", "-lc", script]

    # Samples are nested symmetrically around the build, cheapest innermost, so
    # the slow /proc walks sit outside the measured window on both sides and
    # their cost cancels out of the deltas.
    ids0 = falcon_prog_ids(comm)
    s0 = read_comm_cpu(comm)
    b0 = bpf_runtime_by_id()
    ct0 = read_total_cpu_s()
    e0 = read_energy_uj(rapl)
    th0 = read_throttled_s(sensor_cg)
    t0 = time.monotonic()
    p = subprocess.run(full, capture_output=True, text=True, preexec_fn=preexec)
    t1 = time.monotonic()
    th1 = read_throttled_s(sensor_cg)
    e1 = read_energy_uj(rapl)
    ct1 = read_total_cpu_s()
    b1 = bpf_runtime_by_id()
    s1 = read_comm_cpu(comm)
    # union of before and after, so programs falcon reloaded mid-build still
    # count as falcon's
    falcon_ids = ids0 | falcon_prog_ids(comm)

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
    energy_j = de / 1e6
    # every loaded program (what the OFF gate checks) vs only the ones falcon
    # owns (what gets attributed to falcon in the report)
    ebpf_s = runtime_delta(b0, b1)
    ebpf_falcon_s = runtime_delta(b0, b1, falcon_ids) if falcon_ids else None
    wall_s = t1 - t0

    # The sensor process's own cost during the build, plus a CPU-time
    # proportional share of the package energy. The share counts both its own
    # CPU and the in-kernel eBPF run-time its hooks burn inside the build's
    # syscalls. All None when the sensor is not running, and dropped when it
    # restarted mid-build (the per-pid counters went backwards).
    sensor_cpu_s = sensor_sys_s = sensor_rss = sensor_energy_j = None
    if s0 is not None and s1 is not None and s1[0] >= s0[0]:
        sensor_cpu_s = s1[0] - s0[0]
        sensor_sys_s = s1[1] - s0[1]
        sensor_rss = max(s0[2], s1[2])
        total_cpu_s = ct1 - ct0
        if total_cpu_s > 0:
            sensor_energy_j = (energy_j * (sensor_cpu_s + (ebpf_falcon_s or 0))
                               / total_cpu_s)

    # CPU-equivalents: CPU-seconds burned per second of build, i.e. how many
    # CPUs falcon keeps continuously busy for as long as you wait for the
    # build. Split between the daemon's own threads (confinable with
    # --falcon-cpus) and its eBPF hooks running inside the build's syscalls
    # (not confinable: they run on the build's own CPUs).
    cpus_ebpf = ebpf_falcon_s / wall_s if ebpf_falcon_s is not None else None
    cpus_sensor = sensor_cpu_s / wall_s if sensor_cpu_s is not None else None

    # Time the sensor's threads spent throttled by its CPUQuota during the
    # build. The kernel sums this over the cgroup's per-CPU queues, so it can
    # exceed the wall-clock. 0 means the quota never bound, and the variant
    # proves nothing.
    throttled_s = th1 - th0 if th0 is not None and th1 is not None else None

    return {
        "rc": p.returncode,
        "err": (p.stderr or "")[-800:] if p.returncode else "",
        "wall_s": wall_s,
        "user_s": user_s,
        "sys_s": sys_s,
        "peak_rss": peak,
        "energy_j": energy_j,
        "ebpf_s": ebpf_s,
        "ebpf_falcon_s": ebpf_falcon_s,
        "sensor_cpu_s": sensor_cpu_s,
        "sensor_sys_s": sensor_sys_s,
        "sensor_rss": sensor_rss,
        "sensor_energy_j": sensor_energy_j,
        "cpus_sensor": cpus_sensor,
        "cpus_ebpf": cpus_ebpf,
        "throttled_s": throttled_s,
    }


def med(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def fmt(x, u="", n=1):
    return f"{x:.{n}f}{u}" if x is not None else "n/a"


def print_hogged(on, logical, physical, build_cpus, falcon_cpus):
    # How many CPUs falcon keeps busy for the whole duration of the build:
    # its own threads plus the eBPF hooks it runs inside the build's syscalls.
    daemon, ebpf = on["cpus_sensor"], on["cpus_ebpf"]
    if daemon is None and ebpf is None:
        return
    daemon, ebpf = daemon or 0, ebpf or 0
    total = daemon + ebpf

    print(f"\nCPUs hogged by falcon during the build: {total:.2f} CPUs, "
          "continuously, start to finish")
    confined = f", confined to {count_cpus(falcon_cpus)} CPUs" if falcon_cpus else ""
    print(f"  {daemon:.2f} CPUs  the sensor's own threads{confined}")
    print(f"  {ebpf:.2f} CPUs  its eBPF hooks, charged to the build's own syscalls")
    print("             (they run on whichever CPU the build is on, so")
    print("              --falcon-cpus cannot move them)")
    if logical:
        print(f"  -> {total / logical * 100:.1f}% of this machine: "
              f"{logical} CPUs / {physical} physical cores")
    if physical:
        # CPU-equivalents are hardware threads: one busy hyperthread is one
        # CPU-equivalent, not a whole core.
        per_core = logical / physical
        print(f"  -> {total / per_core:.2f} physical cores "
              f"(at {per_core:.1f} threads/core on average)")
    if build_cpus:
        n = count_cpus(build_cpus)
        print(f"  -> {total / n * 100:.1f}% of the {n} CPUs given to the build")


def mb(x):
    return x / 1e6 if x else None


def print_memory(on, off, mem_total):
    build_peak, sensor_rss = on["peak_rss"], on["sensor_rss"]
    print(f"peak RSS     ON {fmt(mb(build_peak),'MB',0)}   "
          f"OFF {fmt(mb(off['peak_rss']),'MB',0)} (whole build process tree)")
    if sensor_rss is None:
        return
    line = f"falcon RSS   {fmt(mb(sensor_rss),'MB',0)} (sampled, not a peak)"
    if build_peak:
        line += f" = {sensor_rss / build_peak * 100:.0f}% of the build's peak"
    print(line)
    if mem_total:
        print(f"             {sensor_rss / mem_total * 100:.1f}% of the "
              f"{mem_total / 1e9:.1f}GB installed on this machine"
              + (f", {build_peak / mem_total * 100:.0f}% for the build"
                 if build_peak else ""))


def print_quota(on, quota, off, args):
    # Does capping the sensor's CPU share buy the build anything? The daemon's
    # own threads live in the service cgroup and are throttled; its eBPF hooks
    # run in the context of the build's processes, charged to the build's own
    # cgroup, where the quota has no reach. This block shows which of the two
    # the quota actually moved.
    print(f"\nCPUQuota={args.falcon_quota} verdict:")
    thr = quota["throttled_s"]
    if not thr:
        print("  the quota never throttled the sensor during the build, so this")
        print("  variant proves nothing: it already fit inside its budget")
    else:
        print(f"  the sensor's threads were held off the CPU for {fmt(thr,'s',2)} "
              "during the build")
        print("  (summed over the cgroup's per-CPU queues, so it can exceed the "
              "wall-clock)")

    def row(label, key, unit, n, note=""):
        a, b = on[key], quota[key]
        line = f"  {label:<18} {fmt(a,unit,n):>8} -> {fmt(b,unit,n):>8}"
        if a and b:
            line += f"  ({(b - a) / a * 100:+.1f}%)"
        print(line + note)

    row("falcon own CPU", "sensor_cpu_s", "s", 2)
    row("falcon eBPF CPU", "ebpf_falcon_s", "s", 2)
    row("build kernel CPU", "sys_s", "s", 1)
    row("build wall-clock", "wall_s", "s", 2)

    wq, wo, wf = quota["wall_s"], on["wall_s"], off["wall_s"]
    if wq and wo and wf and wo > wf:
        kept = (wq - wf) / (wo - wf) * 100
        print(f"  -> the quota removes {100 - kept:.0f}% of the {wo - wf:.2f}s the "
              f"sensor costs this build;")
        print(f"     {kept:.0f}% of it survives, which is the part that is not the "
              "daemon but")
        print("     its hooks running inside your own compiler processes")


def print_report(results, discarded, args, logical, physical, mem_total):
    on, quota, off = results["on"], results["quota"], results["off"]
    have_quota = results["reps"]["quota"] > 0

    print("\n================= RESULT =================")
    ram = f", {mem_total / 1e9:.1f}GB RAM" if mem_total else ""
    print(f"machine: {logical} CPUs / {physical} physical cores{ram}")
    if args.build_cpus or args.falcon_cpus:
        print(f"cpus: build={args.build_cpus or 'all'}  "
              f"falcon={args.falcon_cpus or 'all'}")
    reps = results["reps"]
    print(f"reps: ON={reps['on']} QUOTA={reps['quota']} OFF={reps['off']} "
          f"(discarded OFF={discarded})")

    def line(label, key, unit, n, extra=""):
        mid = (f"   QUOTA {fmt(quota[key],unit,n)}" if have_quota else "")
        print(f"{label:<12} ON {fmt(on[key],unit,n)}{mid}   "
              f"OFF {fmt(off[key],unit,n)}{extra}")

    line("wall-clock", "wall_s", "s", 2)
    wo, wf = on["wall_s"], off["wall_s"]
    if wo and wf:
        dw = wo - wf
        print(f"  -> EDR costs {dw:+.2f}s per build "
              f"({dw / wf * 100:+.1f}% slower)")
        bpd = args.builds_per_day
        print(f"  -> at {bpd:g} builds/day: {dw * bpd / 60:.1f} min/day, "
              f"{dw * bpd * 230 / 3600:.1f} h/year/engineer")
    so, sf = on["sys_s"], off["sys_s"]
    line("kernel CPU", "sys_s", "s", 1,
         f"   (+{so - sf:.1f}s system time per build)" if so and sf else "")
    eo, ef = on["energy_j"], off["energy_j"]
    line("energy/build", "energy_j", "J", 0,
         f"   (+{eo - ef:.0f} J per build)" if eo and ef else "")
    line("eBPF CPU", "ebpf_s", "s", 2, "  (all loaded programs; OFF should be ~0)")
    if on["ebpf_falcon_s"] is not None:
        print(f"  -> {fmt(on['ebpf_falcon_s'],'s',2)} of that belongs to programs "
              f"owned by '{args.falcon_comm}', the rest to the other agents")
    sc, ss, se, sr = (on["sensor_cpu_s"], on["sensor_sys_s"],
                      on["sensor_energy_j"], on["sensor_rss"])
    if sc is not None:
        print(f"sensor process (ON): CPU {fmt(sc,'s',2)} (sys {fmt(ss,'s',2)})   "
              f"RSS {fmt(mb(sr),'MB',0)}   energy {fmt(se,'J',1)} per build")
    print_memory(on, off, mem_total)
    print_hogged(on, logical, physical, args.build_cpus, args.falcon_cpus)
    if have_quota:
        print_quota(on, quota, off, args)


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

  # controlled CPU budget: build on 8 cores, falcon confined to 2 others
  sudo ./compile-ab.py --build-cmd 'make -j8' --build-cpus 0-7 \\
                       --falcon-cpus 8-9

  # harsher cap on the sensor, or no quota variant at all
  sudo ./compile-ab.py --falcon-quota 1%
  sudo ./compile-ab.py --falcon-quota ''

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
                   help="eBPF sensor service(s); attachment and detachment are "
                        "verified before each build")
    p.add_argument("--other-services", default="SplunkForwarder,orbit",
                   help="other agents stopped for the OFF build (with falcon)")
    p.add_argument("--pause-services", default="osquery-trace",
                   help="local instrument service(s) to stop for the whole run")
    p.add_argument("--build-cpus", default="",
                   help="confine the build to these CPUs, cpuset syntax e.g. "
                        "'0-7' (default: all CPUs)")
    p.add_argument("--falcon-cpus", default="",
                   help="confine the falcon services to these CPUs via a "
                        "runtime AllowedCPUs property, cleared on exit. Only "
                        "moves its userspace threads: its eBPF programs still "
                        "run on the CPU of the build process that trips them.")
    p.add_argument("--falcon-quota", default="5%",
                   help="also run a third variant with the sensor up but "
                        "capped to this CPUQuota (runtime property, cleared on "
                        "exit), to see whether starving the daemon gives the "
                        "build its time back. Pass '' to skip that variant.")
    p.add_argument("--falcon-comm", default="falcon-sensor-b",
                   help="process name (comm, truncated to 15 bytes by the "
                        "kernel) that owns the sensor's eBPF programs; it gates "
                        "the ON/OFF builds and its CPU/RSS are reported as the "
                        "sensor's own cost")
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
    comm = args.falcon_comm
    falcon = [s for s in args.falcon_services.split(",") if s]
    others = [s for s in args.other_services.split(",") if s]
    paused = [s for s in args.pause_services.split(",") if s]

    if args.build_cpus and not enable_cpuset():
        raise SystemExit("error: cpuset controller unavailable; cannot use --build-cpus")

    logical, physical = cpu_topology()
    mem_total = read_mem_total()

    rapl = find_rapl()
    if not rapl:
        raise SystemExit("error: no RAPL domain")
    wrap = energy_wrap(rapl)

    stats_fd = bpfstats.enable_stats()
    if stats_fd is None:
        raise SystemExit("error: could not enable eBPF run-time stats")

    # the sensor's own service cgroup: where its CPUQuota bites and where the
    # throttling it causes is accounted
    sensor_cg = CGROUP_BASE / "system.slice" / f"{falcon[0]}.service" if falcon else None

    saved_gov = get_governors()
    runs = {"on": [], "quota": [], "off": []}
    discarded = 0

    print(f"workdir={workdir} reps={args.reps} user={user}", file=sys.stderr)
    print(f"build-cmd: {args.build_cmd}", file=sys.stderr)
    if args.build_cpus or args.falcon_cpus:
        print(f"cpus: build={args.build_cpus or 'all'} "
              f"falcon={args.falcon_cpus or 'all'}", file=sys.stderr)
    if args.falcon_quota:
        print(f"quota variant: CPUQuota={args.falcon_quota}", file=sys.stderr)

    def build(label):
        m = measure_build(args.build_cmd, dirty, user, workdir, rapl, wrap, comm,
                          args.build_cpus, sensor_cg)
        if m.get("rc", 1) != 0:
            print(f"  {label} build failed: {m.get('err','')}", file=sys.stderr)
            return None
        extra = ""
        if m["sensor_cpu_s"] is not None:
            extra = f" sensorCPU={fmt(m['sensor_cpu_s'],'s',2)}"
        if m["throttled_s"]:
            extra += f" throttled={fmt(m['throttled_s'],'s',2)}"
        print(f"  {label:<5}: wall={fmt(m['wall_s'],'s',2)} "
              f"sys={fmt(m['sys_s'],'s',1)} ebpf={fmt(m['ebpf_s'],'s',2)} "
              f"E={fmt(m['energy_j'],'J',0)}{extra}", file=sys.stderr)
        return m

    try:
        set_governor(args.governor)
        systemctl("stop", paused, check=False)
        if args.falcon_cpus:
            set_property(falcon, "AllowedCPUs", args.falcon_cpus)

        # ensure fully built & warm before timing anything
        print("warm/setup build...", file=sys.stderr)
        w = run_user(setup, user, workdir)
        if w.returncode != 0:
            raise SystemExit(f"setup build failed:\n{w.stderr[-2000:]}")

        for rep in range(args.reps):
            print(f"\n=== rep {rep + 1}/{args.reps} ===", file=sys.stderr)

            # ---- ON ----
            # wait for falcon's eBPF program count to plateau: it loads them
            # progressively, so "nonzero" would start the build half-armed
            systemctl("start", falcon + others, check=False)
            armed, n_on = verify_attached(comm, args.detach_timeout, args.settle)
            if not armed:
                print(f"  sensor '{comm}' loaded no eBPF progs; skipping ON",
                      file=sys.stderr)
            else:
                print(f"  sensor armed ({n_on} eBPF progs)", file=sys.stderr)
                time.sleep(args.settle)
                m = build("ON")
                if m is not None:
                    runs["on"].append(m)

            # ---- QUOTA: same thing, with the daemon starved ----
            # The property applies to the running service, no restart, so the
            # eBPF programs stay exactly as they were for the ON build.
            if armed and args.falcon_quota:
                set_property(falcon, "CPUQuota", args.falcon_quota)
                applied = read_cpu_max(sensor_cg) if sensor_cg else None
                print(f"  CPUQuota={args.falcon_quota} applied (cpu.max: {applied})",
                      file=sys.stderr)
                time.sleep(args.settle)
                m = build("QUOTA")
                if m is not None:
                    runs["quota"].append(m)
                    if not m["throttled_s"]:
                        print("  note: the quota never throttled the sensor",
                              file=sys.stderr)
                set_property(falcon, "CPUQuota", "")

            # ---- OFF ----
            # gate on falcon's eBPF programs being really gone, not on
            # systemctl is-active (a managed sensor reports active again almost
            # immediately while its hooks stay down)
            systemctl("stop", others, check=False)
            systemctl("stop", falcon, check=False)
            gone, remaining = verify_detached(comm, args.detach_timeout)
            if not gone:
                print(f"  sensor eBPF not detached ({remaining} progs remain); "
                      "skipping OFF", file=sys.stderr)
                systemctl("start", falcon + others, check=False)
                continue
            print(f"  sensor detached ({n_on} -> 0 eBPF progs)", file=sys.stderr)
            time.sleep(args.settle)
            off = build("OFF")
            # restore immediately
            systemctl("start", falcon + others, check=False)

            if off is not None:
                if off["ebpf_s"] > args.ebpf_off_max:
                    discarded += 1
                    print(f"  OFF contaminated (ebpf={fmt(off['ebpf_s'],'s',2)} "
                          f"> {args.ebpf_off_max:g}s); discarded", file=sys.stderr)
                else:
                    runs["off"].append(off)
    finally:
        set_property(falcon, "CPUQuota", "")
        if args.falcon_cpus:
            set_property(falcon, "AllowedCPUs", "")
        systemctl("start", falcon + others, check=False)
        systemctl("start", paused, check=False)
        restore_governors(saved_gov)
        os.close(stats_fd)
        print("\nrestored services, governor, CPU affinity and quota",
              file=sys.stderr)

    results = {v: {k: med([r[k] for r in rs]) for k in MEASURES}
               for v, rs in runs.items()}
    results["reps"] = {v: len(rs) for v, rs in runs.items()}

    summary = {
        "captured_at": datetime.datetime.now().astimezone().isoformat(),
        "kernel": os.uname().release,
        "workdir": workdir,
        "cpus_logical": logical,
        "cpus_physical": physical,
        "mem_total": mem_total,
        "build_cpus": args.build_cpus or None,
        "falcon_cpus": args.falcon_cpus or None,
        "falcon_quota": args.falcon_quota or None,
        "discarded_off": discarded,
        **results,
        "wall_all": {v: [r["wall_s"] for r in rs] for v, rs in runs.items()},
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2) + "\n")

    print_report(results, discarded, args, logical, physical, mem_total)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
