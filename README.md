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
| `prometheus/compile-ab.py` | A/B benchmark of a *real* build with the sensors ON vs momentarily OFF (falcon eBPF-detach verified). Reports the per-build wall-clock, kernel-CPU, energy and eBPF deltas. Project-agnostic. |
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

## Benchmark caveats

- **Observer effect.** The benchmark adds syscall load to a syscall-overhead
  measurement. Keep iteration counts small and the interval long (defaults do);
  per-call `min` latency stays valid and the average footprint is negligible.

- **EDR alerting, and how to allowlist without skewing the result.** The
  `execve` benchmark is a tight `fork()` + `execve("/usr/bin/true")` loop
  (~2,200 process spawns per run, which the exporter repeats five times every
  15 minutes). To a behavioural sensor that looks like a fork-bomb or mass
  process creation, which can page your SOC, get the benchmark throttled or
  killed by the prevention policy, and corrupt the sample if the sensor steps
  in mid-run. `syscall-bench` uses a distinct binary name on purpose, so a
  rule is easy to target.

  To silence it, have whoever administers the Falcon tenant add an *exclusion*
  for the binary, by path (`/usr/local/bin/syscall-bench`) or SHA-256 hash; on
  a managed CSB you usually cannot do this yourself. Ask specifically for a
  **detection/prevention exclusion** (Falcon's IOA / ML exclusions) that
  suppresses the *alert* while the eBPF programs keep running. Do **not**
  accept a *sensor visibility exclusion*: it reduces monitoring of the binary
  and makes the "sensor on" measurement artificially cheap, under-reporting
  the overhead you are trying to quantify. The goal is to stop the sensor
  crying wolf about this process, not to stop it watching it.

  If you cannot get an exclusion added, drop the op instead:
  `--bench-ops getpid,openat`. Those never spawn a process, so nothing looks
  like a fork-bomb and there is nothing to allowlist; you lose the
  process-spawn latency but keep file-open latency, where most of the compile
  tax lives. This caveat applies to the microbenchmark only: `compile-ab.py`
  runs real builds and needs no allowlisting.

- **Pinning.** Pin the benchmark (`taskset -c <cpu>`) to a housekeeping core,
  never an isolated/DPDK core.
