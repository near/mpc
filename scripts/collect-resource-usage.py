#!/usr/bin/env python3
"""Sample system CPU, memory, and load to a CSV at a fixed interval (Linux only).

Used to back-fill telemetry for E2E test runs where CPU / memory contention is
suspected to cause flakiness — see near/mpc#2883. The CSV is meant to be
uploaded as a CI artifact and inspected when a test fails.

Usage:
    python3 scripts/collect-resource-usage.py --output telemetry.csv &
    pid=$!
    # ... run tests ...
    kill -TERM "$pid"
    wait "$pid" 2>/dev/null || true
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time

REQUIRED_PROC_FILES = ("/proc/stat", "/proc/meminfo", "/proc/loadavg")

CSV_HEADER = (
    "ts_unix,"
    "cpu_user_pct,cpu_sys_pct,cpu_iowait_pct,cpu_idle_pct,"
    "mem_total_kb,mem_available_kb,"
    "load_1m,load_5m,load_15m,procs_running"
)


def read_cpu_jiffies():
    """Cumulative CPU counters from the first line of /proc/stat (jiffies)."""
    with open("/proc/stat", "r") as f:
        parts = f.readline().split()
    user, nice, system, idle, iowait, irq, softirq, steal = (int(x) for x in parts[1:9])
    return {
        "user": user + nice,
        "system": system + irq + softirq + steal,
        "iowait": iowait,
        "idle": idle,
    }


def read_meminfo_kb():
    """MemTotal and MemAvailable from /proc/meminfo (KB)."""
    res = {}
    with open("/proc/meminfo", "r") as f:
        for line in f:
            parts = line.split()
            key = parts[0].rstrip(":")
            if key in ("MemTotal", "MemAvailable"):
                res[key] = int(parts[1])
                if len(res) == 2:
                    break
    return res


def read_loadavg():
    """(load_1m, load_5m, load_15m, procs_running) from /proc/loadavg."""
    with open("/proc/loadavg", "r") as f:
        parts = f.read().split()
    return (
        float(parts[0]),
        float(parts[1]),
        float(parts[2]),
        int(parts[3].split("/")[0]),
    )


def cpu_pct(prev, cur):
    """Convert two /proc/stat snapshots to user/system/iowait/idle percentages."""
    d_user = cur["user"] - prev["user"]
    d_sys = cur["system"] - prev["system"]
    d_iow = cur["iowait"] - prev["iowait"]
    d_idle = cur["idle"] - prev["idle"]
    d_total = d_user + d_sys + d_iow + d_idle
    if d_total <= 0:
        return (0.0, 0.0, 0.0, 0.0)
    return (
        round(d_user / d_total * 100, 2),
        round(d_sys / d_total * 100, 2),
        round(d_iow / d_total * 100, 2),
        round(d_idle / d_total * 100, 2),
    )


def main():
    parser = argparse.ArgumentParser(
        description="Sample CPU, memory, and load average to a CSV (Linux only).",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Seconds between samples (default: 2.0).",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="CSV output path. Parent directory is created if missing.",
    )
    args = parser.parse_args()

    missing = [p for p in REQUIRED_PROC_FILES if not os.path.exists(p)]
    if missing:
        sys.stderr.write(
            "collect-resource-usage: required proc files not present "
            f"({', '.join(missing)}); this script needs Linux. "
            "Exiting without sampling.\n"
        )
        sys.exit(1)

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Exit cleanly on SIGTERM/SIGINT so the partial CSV survives as an artifact.
    def _term(_signum, _frame):
        sys.exit(0)

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)

    # Line-buffered so a `tail -f` works while the collector is running and
    # nothing is lost when the process is terminated.
    out = open(args.output, "w", buffering=1)
    out.write(CSV_HEADER + "\n")

    prev = read_cpu_jiffies()
    while True:
        time.sleep(args.interval)
        cur = read_cpu_jiffies()
        pu, ps, pi, pd = cpu_pct(prev, cur)
        prev = cur

        mem = read_meminfo_kb()
        l1, l5, l15, procs_running = read_loadavg()
        ts = int(time.time())

        out.write(
            f"{ts},{pu},{ps},{pi},{pd},"
            f"{mem.get('MemTotal', 0)},{mem.get('MemAvailable', 0)},"
            f"{l1},{l5},{l15},{procs_running}\n"
        )


if __name__ == "__main__":
    main()
