#!/usr/bin/env python3
"""Print a human-readable summary of a resource-usage CSV.

The CSV is the one produced by `scripts/collect-resource-usage.py`. The summary
is intended to surface in the GitHub Actions log so a reviewer can see whether
the runner was under contention without downloading the artifact.
"""

from __future__ import annotations

import argparse
import csv
import sys


def _percentile(sorted_values, pct):
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    # Nearest-rank percentile is fine for ~hundreds of samples.
    idx = max(
        0, min(len(sorted_values) - 1, round(pct / 100 * (len(sorted_values) - 1)))
    )
    return sorted_values[idx]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--input",
        required=True,
        help="CSV produced by collect-resource-usage.py.",
    )
    args = parser.parse_args()

    with open(args.input, newline="") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print(f"summarize-resource-usage: no samples in {args.input}", file=sys.stderr)
        return

    cpu_busy = sorted(100.0 - float(r["cpu_idle_pct"]) for r in rows)
    cpu_iowait = sorted(float(r["cpu_iowait_pct"]) for r in rows)
    load_1m = sorted(float(r["load_1m"]) for r in rows)
    procs_running = sorted(int(r["procs_running"]) for r in rows)
    mem_total_kb = [int(r["mem_total_kb"]) for r in rows]
    mem_avail_kb = [int(r["mem_available_kb"]) for r in rows]
    mem_used_pct = sorted(
        (t - a) / t * 100 for t, a in zip(mem_total_kb, mem_avail_kb) if t > 0
    )

    duration_s = int(rows[-1]["ts_unix"]) - int(rows[0]["ts_unix"])
    mem_total_gib = mem_total_kb[0] / 1024.0 / 1024.0 if mem_total_kb else 0.0

    def line(label, values, fmt="{:.1f}"):
        avg = sum(values) / len(values)
        print(
            f"  {label:<18} "
            f"avg={fmt.format(avg)}  "
            f"p50={fmt.format(_percentile(values, 50))}  "
            f"p95={fmt.format(_percentile(values, 95))}  "
            f"max={fmt.format(max(values))}"
        )

    print(f"=== resource-usage summary ({args.input}) ===")
    print(f"  samples            {len(rows)}")
    print(f"  duration           {duration_s} s")
    print(f"  mem total          {mem_total_gib:.1f} GiB")
    line("cpu busy %", cpu_busy)
    line("cpu iowait %", cpu_iowait)
    line("load 1m", load_1m, fmt="{:.2f}")
    line("procs running", procs_running, fmt="{:.1f}")
    line("mem used %", mem_used_pct)


if __name__ == "__main__":
    main()
