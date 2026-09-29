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

- **A/B syscall benchmark.** A fixed micro-benchmark of hooked (`openat`,
  `execve`) vs essentially-unhooked (`getpid`) syscalls, compared against
  a baseline captured with the sensor momentarily disabled, yields the per-call
  latency tax and hence the "time lost" on syscall-heavy work.

## Components

| Path | Purpose |
| --- | --- |
| `prometheus/power-exporter.py` | Prometheus exporter: per-process CPU/mem/IO, RAPL energy, eBPF program run-time, cgroup stats for the sensors, syscall-benchmark + baseline metrics. |
| `prometheus/bpfstats.py` | Reads per-program eBPF run-time via `bpf(2)` directly (no `bpftool` dependency); enables run-time stats and holds the fd so they auto-disable on exit. |
| `syscall-bench.c` | `syscall-bench`: measures per-call latency of `getpid`/`openat`/`execve`. Distinct binary name for EDR allowlisting; optional CPU pinning. |
| `prometheus/capture-baseline.py` | Captures the no-EDR baseline (A/B/A, with BPF-detach verification). |
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
- `node_syscall_bench_seconds{op}` / `node_syscall_bench_cpu_seconds{op}` — live
  per-call latency.
- `node_syscall_baseline_seconds{op,condition}`,
  `node_syscall_baseline_overhead_seconds{op}`,
  `node_syscall_baseline_stale` — from the captured baseline.

## Requirements

- root (the exporter needs CAP_BPF/CAP_SYS_ADMIN for run-time stats and to read
  every process's `io`/`status`).
- `python3`, a C compiler.
- Prometheus and Grafana for storage and display.
- `bpftrace` for the optional osquery file-trace.

## Install

```sh
make                    # compile syscall-bench
sudo make install       # install deps, binary and config, enable services
```

`make install` installs the scrape config to `/etc/prometheus/prometheus.yml`
and enables Prometheus (scraping the exporter on `localhost:9599`) and Grafana,
which auto-loads the datasource and dashboard from `/etc/grafana/provisioning/`.

## Establishing the baseline

The baseline is the only way to state absolute "% slower without the sensor".
It requires a window where the sensor is genuinely off. On a managed machine
the sensor is restarted out of your control after a few hours, so this is
a single, scripted window rather than a continuous A/B:

```sh
sudo taskset -c 2 ./prometheus/capture-baseline.py
```

Per bracket the script measures all-on, stops osquery, stops falcon **and
verifies its eBPF programs actually detached** (stopping the service does not
always detach the programs), measures, then restores. Because the external
restart can fire mid-window, detachment is re-checked around every off-sample
and any contaminated sample is discarded. The stepwise teardown attributes cost
to osquery vs falcon separately.

The output (`/var/lib/power-exporter/syscall-baseline.json` by default) is
tagged with the kernel and sensor versions; `node_syscall_baseline_stale` flags
when the running kernel no longer matches, i.e. when to recapture.

## Benchmark caveats

- **Observer effect.** The benchmark adds syscall load to a syscall-overhead
  measurement. Keep iteration counts small and the interval long (defaults do);
  per-call `min` latency stays valid and the average footprint is negligible.

- **EDR alerting.** A tight `execve` loop can look like a fork-bomb to the
  sensor. Allowlist the `syscall-bench` binary, or run only
  `--bench-ops getpid,openat`.

- **Pinning.** Pin the benchmark (`taskset -c <cpu>`) to a housekeeping core,
  never an isolated/DPDK core.
