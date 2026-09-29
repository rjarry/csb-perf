#!/usr/bin/env python3

"""
Capture a syscall-latency baseline with the EDR sensors momentarily disabled.

On a managed machine falcon-sensor is restarted out of our control after a few
hours, so a continuous A/B is impossible. Instead this does a single, fully
scripted window: measure -> stop -> verify BPF actually detached -> measure ->
restore, repeated for a few brackets, keeping the minimum per condition.

Because the restart can fire mid-window, falcon detachment is verified around
every "off" sample and any contaminated sample is discarded.

Output is a version-tagged JSON file that power-exporter.py reads to compute the
per-syscall overhead attributable to the sensors. Must run as root.
"""

import argparse
import datetime
import json
import math
import os
import pathlib
import subprocess
import sys
import time

import bpfstats


def bench_once(binary, op, cpu):
    cmd = [binary, op]
    if cpu is not None:
        cmd += ["-c", str(cpu)]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return json.loads(out)["wall_ns"]


def measure(binary, ops, cpu, repeats):
    # min-of-N: the least-interfered run is the best latency estimate.
    return {op: min(bench_once(binary, op, cpu) for _ in range(repeats)) for op in ops}


def merge_min(acc, sample):
    for op, ns in sample.items():
        acc[op] = min(acc[op], ns)


def systemctl(action, services):
    for svc in services:
        subprocess.run(["systemctl", action, svc], check=True)


def is_active(services):
    for s in services:
        p = subprocess.run(["systemctl", "is-active", "--quiet", s], check=False)
        if p.returncode == 0:
            return True
    return False


def snapshot_prog_ids():
    return {p["id"] for p in bpfstats.iter_progs()}


def verify_detached(before_ids, threshold, timeout):
    # Poll until (almost) none of the pre-stop programs remain. Programs take a
    # moment to unload; a mid-window restart makes the fraction jump back up.
    deadline = time.monotonic() + timeout
    frac = 1.0
    while True:
        remaining = before_ids & snapshot_prog_ids()
        frac = len(remaining) / max(len(before_ids), 1)
        if frac <= threshold:
            return True, frac
        if time.monotonic() >= deadline:
            return False, frac
        time.sleep(0.5)


def tool_version(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)
        return (p.stdout + p.stderr).strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bench", default="/usr/local/bin/syscall-bench")
    p.add_argument("--out", default="/var/lib/power-exporter/syscall-baseline.json")
    p.add_argument("--ops", default="getpid,openat,execve")
    p.add_argument("--cpu", type=int, default=None, help="pin bench to this CPU")
    p.add_argument("--cycles", type=int, default=3)
    p.add_argument("--repeats", type=int, default=5, help="bench runs per sample")
    p.add_argument("--falcon-services", default="falcon-sensor")
    p.add_argument("--osquery-services", default="orbit")
    p.add_argument(
        "--detach-threshold",
        type=float,
        default=0.2,
        help="fraction of falcon BPF progs allowed to remain after stop",
    )
    p.add_argument("--detach-timeout", type=float, default=10.0)
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="measure all_on only, never touch services",
    )
    args = p.parse_args()

    ops = [o for o in args.ops.split(",") if o]
    falcon = [s for s in args.falcon_services.split(",") if s]
    osquery = [s for s in args.osquery_services.split(",") if s]

    if not args.dry_run and os.geteuid() != 0:
        raise SystemExit("error: must run as root (or use --dry-run)")

    conditions = ["all_on", "no_osquery", "no_edr"]
    results = {c: {op: math.inf for op in ops} for c in conditions}

    if args.dry_run:
        for _ in range(args.cycles):
            merge_min(
                results["all_on"], measure(args.bench, ops, args.cpu, args.repeats)
            )
    else:
        for cycle in range(args.cycles):
            print(f"cycle {cycle + 1}/{args.cycles}", file=sys.stderr)

            merge_min(
                results["all_on"], measure(args.bench, ops, args.cpu, args.repeats)
            )

            systemctl("stop", osquery)
            merge_min(
                results["no_osquery"], measure(args.bench, ops, args.cpu, args.repeats)
            )

            before = snapshot_prog_ids()
            systemctl("stop", falcon)
            ok, frac = verify_detached(
                before, args.detach_threshold, args.detach_timeout
            )
            if not ok:
                print(
                    f"warning: falcon BPF not detached ({frac:.0%} progs remain); "
                    "skipping no_edr this cycle",
                    file=sys.stderr,
                )
            else:
                sample = measure(args.bench, ops, args.cpu, args.repeats)
                still, _ = verify_detached(before, args.detach_threshold, 0)
                if still:
                    merge_min(results["no_edr"], sample)
                else:
                    print(
                        "warning: falcon reappeared mid-measurement; "
                        "discarding no_edr sample",
                        file=sys.stderr,
                    )

            systemctl("start", falcon)
            systemctl("start", osquery)
            time.sleep(2)
            merge_min(
                results["all_on"], measure(args.bench, ops, args.cpu, args.repeats)
            )

    for c in conditions:
        for op in ops:
            if math.isinf(results[c][op]):
                results[c][op] = None

    overhead = {}
    for op in ops:
        base = results["no_edr"][op]
        top = results["all_on"][op]
        overhead[op] = (top - base) if (base is not None and top is not None) else None

    baseline = {
        "captured_at": datetime.datetime.now().astimezone().isoformat(),
        "kernel": os.uname().release,
        "falcon_version": tool_version(["falconctl", "-g", "--version"]),
        "osquery_version": tool_version(["osqueryd", "--version"]),
        "cpu": args.cpu,
        "ops": ops,
        "conditions_ns": results,
        "overhead_ns": overhead,
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(baseline, indent=2) + "\n")
    print(json.dumps(baseline, indent=2))
    print(f"\nwrote {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
