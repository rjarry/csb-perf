#!/usr/bin/env python3

"""
Idle A/B: show that the EDR sensors are what keeps an otherwise-idle machine
(and its fan) busy.

With the machine quiet (close everything but the terminal running this), it
measures fan RPM, package temperature, eBPF program activity, interrupt rate and
power with the sensors ON, then stops them (verifying falcon's eBPF programs
detached and that eBPF activity actually collapsed), measures again, and
restores. Services are always restored on exit.

The point is not CPU load (an idle machine is a few percent busy) but the
constant stream of in-kernel hook firings the sensor generates, and the
sustained power/heat that keeps the fan engaged. Stop the sensor and the fan
winds down; start it and it ramps back, under identical idle load.

The CPU governor is deliberately left untouched: this measures real idle
behaviour, not a pinned benchmark. Must run as root.
"""

import argparse
import datetime
import json
import os
import pathlib
import shutil
import subprocess
import time

import bpfstats

RAPL_BASE = pathlib.Path("/sys/class/powercap")
HAVE_TURBOSTAT = shutil.which("turbostat") is not None


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
    try:
        return int((rapl / "energy_uj").read_text())
    except (OSError, ValueError, TypeError):
        return None


HWMON_BASE = pathlib.Path("/sys/class/hwmon")


def read_fan():
    best = 0
    for fan in HWMON_BASE.glob("hwmon*/fan*_input"):
        try:
            best = max(best, int(fan.read_text()))
        except (OSError, ValueError):
            pass
    return best


THERMAL_BASE = pathlib.Path("/sys/class/thermal")


def find_pkgtemp():
    for label in HWMON_BASE.glob("hwmon*/temp*_label"):
        try:
            if "Package" in label.read_text():
                name = label.name.replace("_label", "_input")
                return label.parent / name
        except OSError:
            pass
    for zone in THERMAL_BASE.glob("thermal_zone*"):
        try:
            if (zone / "type").read_text().strip() == "x86_pkg_temp":
                return zone / "temp"
        except OSError:
            pass
    return None


PKGTEMP = find_pkgtemp()


def read_temp():
    if not PKGTEMP:
        return None
    try:
        return round(int(PKGTEMP.read_text()) / 1000.0, 1)
    except (OSError, ValueError):
        return None


def bpf_counts():
    cnt = progs = 0
    for p in bpfstats.iter_progs():
        cnt += p["run_cnt"]
        progs += 1
    return cnt, progs


def parse_turbostat(blobs):
    for blob in blobs:
        lines = [l for l in blob.splitlines() if l.strip()]
        for i, l in enumerate(lines):
            if l.startswith("Avg_MHz") and i + 1 < len(lines):
                return dict(zip(l.split(), lines[i + 1].split()))
    return {}


def systemctl(action, services):
    for svc in services:
        subprocess.run(["systemctl", action, svc], check=False)


def is_active(svc):
    p = subprocess.run(["systemctl", "is-active", "--quiet", svc], check=False)
    return p.returncode == 0


def measure(label, dur, rapl):
    c0, _ = bpf_counts()
    e0 = read_energy_uj(rapl)
    t0 = time.monotonic()

    proc = None
    if HAVE_TURBOSTAT:
        proc = subprocess.Popen(
            ["turbostat", "--quiet", "--Summary", "sleep", str(dur)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    timeline = []
    while True:
        timeline.append((round(time.monotonic() - t0), read_fan(), read_temp()))
        if proc is not None:
            if proc.poll() is not None:
                break
        elif time.monotonic() - t0 >= dur:
            break
        time.sleep(1)

    dt = time.monotonic() - t0
    c1, progs = bpf_counts()
    e1 = read_energy_uj(rapl)
    ts = parse_turbostat(proc.communicate()) if proc is not None else {}

    pkg_idle = sum(
        float(ts.get(k, "0") or 0)
        for k in ("Pkg%pc2", "Pkg%pc3", "Pkg%pc6", "Pkg%pc8", "Pk%pc10")
    )
    fans = [f for _, f, _ in timeline]
    temps = [t for _, _, t in timeline if t is not None]
    watts = None
    if e0 is not None and e1 is not None:
        watts = round((e1 - e0) / 1e6 / dt, 2)

    row = {
        "ebpf_per_s": round((c1 - c0) / dt),
        "progs": progs,
        "fan_start": fans[0] if fans else None,
        "fan_end": fans[-1] if fans else None,
        "fan_min": min(fans) if fans else None,
        "fan_max": max(fans) if fans else None,
        "temp_avg": round(sum(temps) / len(temps), 1) if temps else None,
        "rapl_watts": watts,
        "busy_pct": ts.get("Busy%"),
        "irq_per_s": round(float(ts.get("IRQ", "0") or 0) / dt) if ts else None,
        "any_c0_pct": ts.get("Any%C0"),
        "pkg_deep_idle_pct": round(pkg_idle, 2) if ts else None,
        "pkg_watt": ts.get("PkgWatt"),
        "sys_watt": ts.get("SysWatt"),
        "pkg_tmp": ts.get("PkgTmp"),
    }
    print(
        f"  {label}: fan {row['fan_start']}->{row['fan_min']} RPM  "
        f"eBPF {row['ebpf_per_s']}/s  "
        f"power {row['sys_watt'] or row['rapl_watts']}W",
        flush=True,
    )
    return row, timeline


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    p.add_argument(
        "--on-seconds",
        type=int,
        default=30,
        help="test duration with sensors ON",
    )
    p.add_argument(
        "--off-seconds",
        type=int,
        default=30,
        help="test duraction with sensors OFF",
    )
    p.add_argument(
        "--settle",
        type=float,
        default=60.0,
        help="grace period between ON and OFF tests",
    )
    p.add_argument(
        "--falcon-services",
        default="falcon-sensor",
        help="eBPF sensor service(s); detachment is verified",
    )
    p.add_argument(
        "--other-services",
        default="orbit,SplunkForwarder",
        help="other agents stopped with falcon",
    )
    p.add_argument(
        "--ebpf-off-max",
        type=float,
        default=2000.0,
        help="""
        max eBPF events/s tolerated once stopped before the OFF phase is
        flagged as contaminated
        """,
    )
    p.add_argument("--out", default="/var/lib/power-exporter/idle-ab.json")
    args = p.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("error: must run as root")

    falcon = [s for s in args.falcon_services.split(",") if s]
    others = [s for s in args.other_services.split(",") if s]
    rapl = find_rapl()

    if bpfstats.enable_stats() is None:
        raise SystemExit("error: could not enable eBPF run-time stats")

    print(
        f"turbostat: {'yes' if HAVE_TURBOSTAT else 'no (power from RAPL only)'}  "
        f"fan now: {read_fan()} RPM  temp: {read_temp()} C",
    )

    on = off = None
    on_tl = off_tl = None
    contaminated = False
    try:
        print(f">>> sensors ON ({args.on_seconds} seconds)")
        on, on_tl = measure("ON ", args.on_seconds, rapl)
        print("\nON fan/temp timeline (s : RPM : degC):")
        for s, f, t in on_tl:
            if s % 3 == 0:
                print(f"  {s:3d}s  {f:5d} RPM  {t} C")

        print(f">>> stopping sensors ({args.settle} seconds)")
        systemctl("stop", others + falcon)
        time.sleep(args.settle)
        a, _ = bpf_counts()
        time.sleep(2)
        b, progs = bpf_counts()
        rate = (b - a) / 2
        falcon_up = any(is_active(s) for s in falcon)
        print(
            f"after stop: progs={progs} eBPF={rate:.0f}/s falcon_active={falcon_up}",
        )
        if falcon_up or rate > args.ebpf_off_max:
            contaminated = True
            print("warning: sensors did not fully stop; OFF phase is suspect")

        print(f">>> sensors OFF ({args.off_seconds})")
        off, off_tl = measure("OFF", args.off_seconds, rapl)
        print("\nOFF fan/temp timeline (s : RPM : degC):")
        for s, f, t in off_tl:
            if s % 3 == 0:
                print(f"  {s:3d}s  {f:5d} RPM  {t} C")
    finally:
        systemctl("start", falcon + others)
        print(">>> sensors restored")

    keys = [
        "ebpf_per_s",
        "irq_per_s",
        "busy_pct",
        "any_c0_pct",
        "pkg_deep_idle_pct",
        "rapl_watts",
        "sys_watt",
        "pkg_watt",
        "pkg_tmp",
        "temp_avg",
        "fan_start",
        "fan_min",
    ]
    print("\n==== IDLE A/B (close everything but this terminal) ====")
    for k in keys:
        print(f"  {k:18} ON={on.get(k):>8}   OFF={off.get(k):>8}")
    if contaminated:
        print("\nNOTE: OFF phase flagged contaminated (sensors restarted?). Re-run.")

    summary = {
        "captured_at": datetime.datetime.now().astimezone().isoformat(),
        "kernel": os.uname().release,
        "contaminated": contaminated,
        "on": on,
        "on_timeline": on_tl,
        "off": off,
        "off_timeline": off_tl,
    }
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
