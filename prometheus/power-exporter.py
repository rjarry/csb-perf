#!/usr/bin/env python3

import argparse
import http.server
import os
import pathlib

RAPL_BASE = pathlib.Path("/sys/class/powercap")
CLK_TCK = os.sysconf("SC_CLK_TCK")
CGROUP_BASE = pathlib.Path("/sys/fs/cgroup")


def find_rapl_domain():
    best = None
    best_name = None
    for path in RAPL_BASE.glob("intel-rapl:*"):
        name = (path / "name").read_text().strip()
        if name == "psys":
            return path, name
        if best is None:
            best = path
            best_name = name
    return best, best_name


def read_comm(stat_path, comm):
    # comm in /proc/<pid>/stat is truncated to 15 characters. When it looks
    # truncated, recover the full name from the basename of argv[0].
    if len(comm) < 15:
        return comm
    try:
        cmdline = (stat_path.parent / "cmdline").read_bytes()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return comm
    arg0 = cmdline.split(b"\0", 1)[0]
    if not arg0:
        return comm
    name = os.path.basename(os.fsdecode(arg0))
    if name.startswith(comm):
        return name
    return comm


def escape(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def read_ctxt_switches(status_path):
    vol = nonvol = 0
    try:
        for line in status_path.read_text().splitlines():
            if line.startswith("voluntary_ctxt_switches:"):
                vol = int(line.split()[1])
            elif line.startswith("nonvoluntary_ctxt_switches:"):
                nonvol = int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
        pass
    return vol, nonvol


def format_processes(lines):
    page_size = os.sysconf("SC_PAGE_SIZE")
    by_comm = {}

    for stat_path in pathlib.Path("/proc").glob("*/stat"):
        try:
            int(stat_path.parent.name)
        except ValueError:
            continue
        try:
            stat = stat_path.read_text()
            i = stat.index("(")
            j = stat.rindex(")")
            comm = read_comm(stat_path, stat[i + 1 : j])
            fields = stat[j + 2 :].split()
            utime = int(fields[11])
            stime = int(fields[12])
            rss_pages = int(fields[21])

            acc = by_comm.get(comm)
            if acc is None:
                # cpu, sys_cpu, rss, rchar, wchar, vcsw, nvcsw
                acc = [0.0, 0.0, 0, 0, 0, 0, 0]
                by_comm[comm] = acc
            acc[0] += (utime + stime) / CLK_TCK
            acc[1] += stime / CLK_TCK
            acc[2] += rss_pages * page_size

            try:
                io_data = (stat_path.parent / "io").read_text()
                for line in io_data.splitlines():
                    k, _, v = line.partition(":")
                    if k == "rchar":
                        acc[3] += int(v)
                    elif k == "wchar":
                        acc[4] += int(v)
            except (PermissionError, FileNotFoundError):
                pass

            vol, nonvol = read_ctxt_switches(stat_path.parent / "status")
            acc[5] += vol
            acc[6] += nonvol

        except (FileNotFoundError, ProcessLookupError, ValueError, IndexError):
            continue

    lines.append(
        "# HELP node_process_cpu_seconds_total "
        "CPU time consumed by process group (user + system)."
    )
    lines.append("# TYPE node_process_cpu_seconds_total gauge")
    lines.append(
        "# HELP node_process_cpu_system_seconds_total "
        "System (kernel) CPU time consumed by process group. This absorbs the "
        "in-kernel cost of eBPF hooks triggered by the process's syscalls."
    )
    lines.append("# TYPE node_process_cpu_system_seconds_total gauge")
    lines.append("# HELP node_process_memory_rss_bytes Resident set size in bytes.")
    lines.append("# TYPE node_process_memory_rss_bytes gauge")
    lines.append(
        "# HELP node_process_io_bytes_total Bytes read/written by process group."
    )
    lines.append("# TYPE node_process_io_bytes_total gauge")
    lines.append(
        "# HELP node_process_ctxt_switches_total Context switches by process group."
    )
    lines.append("# TYPE node_process_ctxt_switches_total gauge")

    for comm in sorted(by_comm):
        cpu, sys_cpu, rss, rchar, wchar, vcsw, nvcsw = by_comm[comm]
        label = f'comm="{escape(comm)}"'
        lines.append(f"node_process_cpu_seconds_total{{{label}}} {cpu}")
        lines.append(f"node_process_cpu_system_seconds_total{{{label}}} {sys_cpu}")
        lines.append(f"node_process_memory_rss_bytes{{{label}}} {rss}")
        lines.append(f'node_process_io_bytes_total{{{label},direction="read"}} {rchar}')
        lines.append(
            f'node_process_io_bytes_total{{{label},direction="write"}} {wchar}'
        )
        lines.append(
            f'node_process_ctxt_switches_total{{{label},kind="voluntary"}} {vcsw}'
        )
        lines.append(
            f'node_process_ctxt_switches_total{{{label},kind="nonvoluntary"}} {nvcsw}'
        )
    lines.append("")


def format_cgroups(lines, cgroups):
    emitted = False
    for name, path in cgroups.items():
        if not path.exists():
            continue
        if not emitted:
            lines.append(
                "# HELP node_cgroup_cpu_seconds_total CPU time consumed by cgroup."
            )
            lines.append("# TYPE node_cgroup_cpu_seconds_total counter")
            lines.append(
                "# HELP node_cgroup_memory_bytes Current memory usage of cgroup."
            )
            lines.append("# TYPE node_cgroup_memory_bytes gauge")
            lines.append("# HELP node_cgroup_pids Current number of tasks in cgroup.")
            lines.append("# TYPE node_cgroup_pids gauge")
            emitted = True
        label = f'cgroup="{escape(name)}"'
        try:
            for line in (path / "cpu.stat").read_text().splitlines():
                k, _, v = line.partition(" ")
                if k == "user_usec":
                    lines.append(
                        f'node_cgroup_cpu_seconds_total{{{label},mode="user"}} '
                        f"{int(v) / 1e6}"
                    )
                elif k == "system_usec":
                    lines.append(
                        f'node_cgroup_cpu_seconds_total{{{label},mode="system"}} '
                        f"{int(v) / 1e6}"
                    )
        except (FileNotFoundError, ValueError):
            pass
        try:
            mem = int((path / "memory.current").read_text())
            lines.append(f"node_cgroup_memory_bytes{{{label}}} {mem}")
        except (FileNotFoundError, ValueError):
            pass
        try:
            pids = int((path / "pids.current").read_text())
            lines.append(f"node_cgroup_pids{{{label}}} {pids}")
        except (FileNotFoundError, ValueError):
            pass
    if emitted:
        lines.append("")


def format_metrics(rapl_path, cgroups):
    lines = []

    energy_uj = int((rapl_path / "energy_uj").read_text())
    lines.append(
        "# HELP node_rapl_energy_joules "
        "Total energy consumed reported by RAPL (counter)."
    )
    lines.append("# TYPE node_rapl_energy_joules counter")
    lines.append(f"node_rapl_energy_joules {energy_uj / 1_000_000}")
    lines.append("")

    format_processes(lines)
    format_cgroups(lines, cgroups)

    return "\n".join(lines) + "\n"


class MetricsHandler(http.server.BaseHTTPRequestHandler):
    rapl_path = None
    cgroups = {}

    def do_GET(self):
        body = format_metrics(self.rapl_path, self.cgroups).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def main():
    p = argparse.ArgumentParser(
        description="Per-process power consumption Prometheus exporter"
    )
    p.add_argument(
        "-p", "--port", type=int, default=9599, help="listen port (default: 9599)"
    )
    p.add_argument(
        "--cgroup-services",
        default="falcon-sensor,osqueryd,orbit",
        help="system.slice services to report cgroup stats for",
    )
    args = p.parse_args()

    rapl_path, rapl_name = find_rapl_domain()
    if not rapl_path:
        raise SystemExit("error: no RAPL domain found")
    print(f"using RAPL domain: {rapl_name} ({rapl_path})")

    cgroups = {
        svc: CGROUP_BASE / "system.slice" / f"{svc}.service"
        for svc in args.cgroup_services.split(",")
        if svc
    }
    MetricsHandler.rapl_path = rapl_path
    MetricsHandler.cgroups = cgroups

    server = http.server.HTTPServer(("", args.port), MetricsHandler)
    print(f"listening on :{args.port}/metrics", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
