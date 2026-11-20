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

## Components

| Path | Purpose |
| --- | --- |
| `prometheus/power-exporter.py` | Prometheus exporter: per-process CPU/mem/IO, RAPL energy, eBPF program run-time, cgroup stats for the sensors. |
| `prometheus/bpfstats.py` | Reads per-program eBPF run-time via `bpf(2)` directly (no `bpftool` dependency); enables run-time stats and holds the fd so they auto-disable on exit. |
| `prometheus/compile-ab.py` | A/B benchmark of a *real* build with the sensors ON vs momentarily OFF (falcon eBPF-detach verified). Reports the per-build wall-clock, kernel-CPU, energy and eBPF deltas. Project-agnostic. |
| `prometheus/idle-ab.py` | Idle A/B: fan RPM, package temperature, interrupt + eBPF rates and power with the sensors ON vs momentarily OFF. Shows the sensors keep an idle machine (and its fan) busy. |
| `prometheus/file-trace.bt` | bpftrace script logging a process's file access (open/read/write/stat/readdir). Used to see *what* osquery touches. |
| `prometheus/prometheus.yml` | Prometheus scrape config (self + exporter on :9599). |
| `grafana/dashboards/power.json` | Grafana dashboard. |
| `grafana/provisioning/` | Grafana datasource + dashboard provisioning. |
| `systemd/power-exporter.service` | Runs the exporter (as root; needs CAP_BPF for run-time stats). |
| `systemd/osquery-trace.service` | Runs `file-trace.bt` against the live osqueryd pid, logging to `/var/log/osquery-trace.log`. |
| `logrotate.d/osquery-trace` | Rotates the osquery trace log. |

## Metrics

- `node_rapl_energy_joules` — package energy (RAPL), for power apportioning.
- `node_process_cpu_seconds_total{comm}` — per-command CPU (user+system).
- `node_process_cpu_system_seconds_total{comm}` — per-command **system** time
  (this is where smeared eBPF cost lands).
- `node_process_memory_rss_bytes{comm}`, `node_process_io_bytes_total{comm,direction}`.
- `node_process_ctxt_switches_total{comm,kind}` — voluntary/nonvoluntary.
- `node_bpf_prog_run_seconds_total{name,type}` / `node_bpf_prog_run_count_total`
  — the direct, otherwise-hidden sensor overhead.
- `node_bpf_stats_enabled` — 1 if run-time accounting is on.
- `node_cgroup_cpu_seconds_total{cgroup,mode}`, `node_cgroup_memory_bytes`,
  `node_cgroup_pids` — clean attribution of the sensor daemons.

## Requirements

- root (the exporter needs CAP_BPF/CAP_SYS_ADMIN for run-time stats and to read
  every process's `io`/`status`).
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
build with the sensors ON vs momentarily OFF (verifying falcon's eBPF programs
actually detached, and discarding any "off" build during which eBPF still ran),
pins the CPU governor, runs each build in a throwaway cgroup to capture the whole
process tree's CPU and peak RSS, and brackets it with RAPL energy and eBPF
run-time deltas. Services and governor are always restored on exit.

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

# a different agent / service set (defaults target the CSB stack)
sudo /etc/prometheus/compile-ab.py \
    --falcon-services falcon-sensor --other-services SplunkForwarder,orbit
```

By default each repetition recompiles the tracked C/C++/Rust/Go sources
(`--dirty-cmd` touches them); override `--dirty-cmd` for a full rebuild or a
different language. Results are written to `--out`
(`/var/lib/power-exporter/compile-ab.json`) and printed as a summary:

```
wall-clock   ON 17.96s   OFF 14.53s
  -> EDR costs +3.44s per build (+23.7% slower)
  -> at 20 builds/day: 1.1 min/day, 4.4 h/year/engineer
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

- **Pinning.** Pin the benchmark (`taskset -c <cpu>`) to a housekeeping core,
  never an isolated/DPDK core.
