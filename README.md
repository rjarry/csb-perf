# CSB Performance Tooling

Telemetry to quantify the overhead of endpoint security agents (CrowdStrike
falcon-sensor-bpf, osquery/orbit) on a Linux workstation: CPU, memory, power,
and the time they cost syscall-heavy workloads such as compiles.

## Why this exists

An eBPF-based sensor attaches programs to syscalls, tracepoints and LSM hooks.
Those programs run **in the context of whatever process triggered the event**,
so their cost is charged to that process's *system* (kernel) time and is
smeared across every syscall-heavy process (`cc1`, `ld`, `make`, `git`, ...).
It is therefore invisible if you only look at the sensor's own processes.

Two things make it visible again:

- **eBPF run-time accounting.** With run-time stats enabled, every loaded
  program exposes `run_time_ns` and `run_cnt`. Summed, that is the in-kernel
  CPU time the sensor actually burns.

- **A/B benchmarks of real workloads.** The same build, or the same idle
  window, with the sensors ON vs momentarily OFF, yields the wall-clock and
  power cost as developers actually feel it.

The exporter itself is passive: it only reads `/proc`, `/sys` and cgroup files
when scraped, and never runs anything in the background, so it does not perturb
what it measures. The A/B tools are run by hand, when you want a measurement.

## Components

| Path | Purpose |
| --- | --- |
| `prometheus/power-exporter.py` | Prometheus exporter: per-process CPU/mem/IO, RAPL energy, cgroup stats for the sensors. Pure `/proc` and `/sys` reads at scrape time, no background activity. |
| `prometheus/bpfstats.py` | Reads per-program eBPF run-time via `bpf(2)` directly (no `bpftool` dependency); enables run-time stats and holds the fd so they auto-disable on exit. Used by the A/B tools. |
| `prometheus/compile-ab.py` | A/B benchmark of a *real* build, sensors ON vs capped to a CPUQuota vs OFF (falcon eBPF attach+detach verified). Reports per-build wall-clock, kernel-CPU, energy, eBPF and sensor-process deltas, and how many CPUs/cores falcon hogs; optional CPU confinement of the build and of falcon. Project-agnostic. |
| `prometheus/idle-ab.py` | Idle A/B: fan RPM, package temperature, interrupt + eBPF rates and power with the sensors ON vs momentarily OFF. Shows the sensors keep an idle machine (and its fan) busy. |
| `prometheus/file-trace.bt` | bpftrace script logging a process's file access (open/read/write/stat/readdir). Used to see *what* osquery touches. |
| `prometheus/prometheus.yml` | Prometheus scrape config (self + exporter on :9599). |
| `grafana/dashboards/power.json` | Grafana dashboard. |
| `grafana/provisioning/` | Grafana datasource + dashboard provisioning. |
| `systemd/power-exporter.service` | Runs the exporter (as root, to read every process's `io`/`status`). |
| `systemd/osquery-trace.service` | Runs `file-trace.bt` against the live osqueryd pid, logging to `/var/log/osquery-trace.log`. |
| `logrotate.d/osquery-trace` | Rotates the osquery trace log. |

## Metrics

- `node_rapl_energy_joules` — package energy (RAPL), for power apportioning.
- `node_process_cpu_seconds_total{comm}` — per-command CPU (user+system).
- `node_process_cpu_system_seconds_total{comm}` — per-command **system** time
  (this is where smeared eBPF cost lands).
- `node_process_memory_rss_bytes{comm}`, `node_process_io_bytes_total{comm,direction}`.
- `node_process_ctxt_switches_total{comm,kind}` — voluntary/nonvoluntary.
- `node_cgroup_cpu_seconds_total{cgroup,mode}`, `node_cgroup_memory_bytes`,
  `node_cgroup_pids` — clean attribution of the sensor daemons.

## Requirements

- root (the exporter reads every process's `io`/`status`; the A/B tools need
  CAP_BPF/CAP_SYS_ADMIN for eBPF run-time stats).
- `python3`.
- Prometheus and Grafana for storage and display.
- `bpftrace` for the optional osquery file-trace.

## Install

```sh
sudo make install       # install deps and config, enable services
```

`make install` installs the scrape config to `/etc/prometheus/prometheus.yml`
and enables Prometheus (scraping the exporter on `localhost:9599`) and Grafana,
which auto-loads the datasource and dashboard from `/etc/grafana/provisioning/`.

## A/B compile benchmark

`compile-ab.py` measures what the sensors cost a *real* build, end to end, in
wall-clock time — the number developers actually feel. It interleaves the same
build in three variants: sensors **ON**, sensors on but falcon capped to a
**CPUQuota** (`--falcon-quota`, 5% by default), and sensors **OFF**. Each build
is gated on falcon's eBPF programs really being attached (or really gone), and
any "off" build during which eBPF still ran is discarded. It pins the CPU
governor, runs each build in a throwaway cgroup to capture the whole process
tree's CPU and peak RSS, and brackets it with RAPL energy and eBPF run-time
deltas. Services, governor, CPU affinity and quota are always restored on exit.

The quota variant answers "can we just cap the thing?". The property is applied
to the *running* service, so the eBPF programs stay exactly as they were and
only the daemon's own threads are starved. The hooks run in the context of the
build's own processes, charged to the build's cgroup rather than the sensor's,
so the quota cannot reach them — the verdict block shows how much of the cost
survives being throttled. The service cgroup's `throttled_usec` confirms the cap
actually bound; if it never did, the report says so instead of pretending the
variant means something.

For the ON builds it also reports the sensor process's own cost
(`--falcon-comm`, default `falcon-sensor-b`): its CPU time, how much of that is
system time, its RSS, and a CPU-proportional share of package energy. Both that
and the eBPF run-time are then expressed as **CPUs hogged** — CPU-seconds burned
per second of build, i.e. how many CPUs falcon keeps busy for as long as you sit
waiting, in logical CPUs, physical cores, and percent of the machine. The two
are deliberately kept apart: the daemon's own threads are a rounding error, the
in-kernel eBPF time charged to *your* build's syscalls is where the cost is. Its
RSS is likewise put next to the build's own peak RSS and the installed RAM.

eBPF run-time is attributed per program id. The contamination gate looks at
every loaded program, but only the ones falcon owns (fds held by
`--falcon-comm`) are charged to falcon, so osquery's BPF publisher does not end
up on its bill.

It is project-agnostic. Run it as root **from your project directory** (or pass
`--workdir`); the build itself runs as `--user` (default `$SUDO_USER`) so it does
not create root-owned files, and `ccache` is disabled for the timed build so you
measure real compilation.

```sh
# edit-rebuild loop of a make-based project (the frequent dev inner loop)
cd ~/src/myproject
sudo /etc/prometheus/compile-ab.py --build-cmd 'make -j$(nproc)'

# meson/ninja project, full clean rebuild each repetition
sudo /etc/prometheus/compile-ab.py \
    --dirty-cmd 'ninja -C build clean' --build-cmd 'ninja -C build'

# more repetitions, and your real cadence for the time-lost projection
sudo /etc/prometheus/compile-ab.py --reps 7 --builds-per-day 40

# controlled CPU budget: build on 8 cores, falcon confined to 2 others
sudo /etc/prometheus/compile-ab.py \
    --build-cmd 'make -j8' --build-cpus 0-7 --falcon-cpus 8-9

# harsher cap on the sensor, or drop the quota variant entirely
sudo /etc/prometheus/compile-ab.py --falcon-quota 1%
sudo /etc/prometheus/compile-ab.py --falcon-quota ''

# a different agent / service set (defaults target the CSB stack)
sudo /etc/prometheus/compile-ab.py \
    --falcon-services falcon-sensor --other-services SplunkForwarder,orbit
```

`--build-cpus` is applied as the cpuset of the build's own measurement cgroup,
`--falcon-cpus` as a runtime `AllowedCPUs=` property on the falcon services,
cleared on exit. Both default to unrestricted. Confining falcon only moves its
*userspace* threads: its eBPF programs still run in the context of whichever
build process trips the hook, on that process's CPU — which is precisely why
the sensor's own CPU and the eBPF CPU are reported separately.

By default each repetition recompiles the tracked C/C++/Rust/Go sources
(`--dirty-cmd` touches them); override `--dirty-cmd` for a full rebuild or a
different language. Results are written to `--out`
(`/var/lib/power-exporter/compile-ab.json`) and printed as a summary (shape of
the output; numbers are illustrative):

```
machine: 14 CPUs / 12 physical cores, 33.1GB RAM
reps: ON=5 QUOTA=5 OFF=5 (discarded OFF=0)
wall-clock   ON 17.96s   QUOTA 17.80s   OFF 14.53s
  -> EDR costs +3.43s per build (+23.6% slower)
  -> at 20 builds/day: 1.1 min/day, 4.4 h/year/engineer
eBPF CPU     ON 5.31s   QUOTA 5.31s   OFF 0.01s  (all loaded programs; OFF should be ~0)
  -> 4.80s of that belongs to programs owned by 'falcon-sensor-b', the rest to the other agents
sensor process (ON): CPU 0.64s (sys 0.19s)   RSS 628MB   energy 63.7J per build
peak RSS     ON 2102MB   OFF 2098MB (whole build process tree)
falcon RSS   628MB (sampled, not a peak) = 30% of the build's peak
             1.9% of the 33.1GB installed on this machine, 6% for the build

CPUs hogged by falcon during the build: 0.30 CPUs, continuously, start to finish
  0.04 CPUs  the sensor's own threads
  0.27 CPUs  its eBPF hooks, charged to the build's own syscalls
             (they run on whichever CPU the build is on, so
              --falcon-cpus cannot move them)
  -> 2.2% of this machine: 14 CPUs / 12 physical cores
  -> 0.26 physical cores (at 1.2 threads/core on average)

CPUQuota=5% verdict:
  the sensor's threads were held off the CPU for 12.40s during the build
  (summed over the cgroup's per-CPU queues, so it can exceed the wall-clock)
  falcon own CPU        0.64s ->    0.11s  (-82.8%)
  falcon eBPF CPU       4.80s ->    4.77s  (-0.6%)
  build kernel CPU      20.4s ->    20.1s  (-1.5%)
  build wall-clock     17.96s ->   17.80s  (-0.9%)
  -> the quota removes 5% of the 3.43s the sensor costs this build;
     95% of it survives, which is the part that is not the daemon but
     its hooks running inside your own compiler processes
```

(Run it uninstalled with `sudo ./prometheus/compile-ab.py --workdir <project>`;
it imports `bpfstats` from the same directory.)

## Idle A/B (fan / power)

`idle-ab.py` answers a different question: why does the fan run when the machine
is doing nothing? Close everything but the terminal running it, then:

```sh
sudo /etc/prometheus/idle-ab.py
```

It records fan RPM, package temperature, interrupt rate, eBPF activity and power
with the sensors ON, stops them (verifying eBPF actually went quiet), measures
again over a longer window so the fan has time to react, and restores on exit.
Expect the eBPF event rate to collapse (tens of thousands/s to tens/s) and, a few
seconds later, the fan to spin down — then ramp back when the services restart.
Results are written to `/var/lib/power-exporter/idle-ab.json`.

## Benchmark caveats

- **Nothing runs on its own.** The exporter never spawns processes; the A/B
  tools only run real workloads (your build, or nothing at all when idle), so
  there is no synthetic activity for a behavioural sensor to alert on and
  nothing to allowlist.

- **Pinning.** When confining a benchmark to specific CPUs
  (`--build-cpus`, `--falcon-cpus`), use housekeeping cores, never an
  isolated/DPDK core.
