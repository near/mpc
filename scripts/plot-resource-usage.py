#!/usr/bin/env python3
"""Plot a resource-usage CSV produced by collect-resource-usage.py to a PNG.

Requires matplotlib. The nix devshell already provides it; outside nix install
with `python3 -m pip install --user matplotlib`.

Usage:
    python3 scripts/plot-resource-usage.py \\
        --input target/telemetry/e2e-resource-usage.csv
    open target/telemetry/e2e-resource-usage.png  # macOS
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path


USAGE_EXAMPLE = """\
Examples:
  # Plot a CSV produced locally or downloaded from the e2e CI artifact.
  python3 scripts/plot-resource-usage.py \\
      --input target/telemetry/e2e-resource-usage.csv

  # Custom output path.
  python3 scripts/plot-resource-usage.py \\
      --input usage.csv --output usage.png
"""


def main():
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=USAGE_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input",
        required=True,
        help="CSV produced by collect-resource-usage.py.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="PNG output path (default: input path with .png suffix).",
    )
    args = parser.parse_args()

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        sys.stderr.write(
            "plot-resource-usage: matplotlib not installed. Install with:\n"
            "    python3 -m pip install --user matplotlib\n"
        )
        sys.exit(1)

    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else input_path.with_suffix(".png")

    with input_path.open(newline="") as f:
        rows = list(csv.DictReader(f))

    if len(rows) < 2:
        sys.stderr.write(
            "plot-resource-usage: need at least 2 samples, got "
            f"{len(rows)} in {input_path}\n"
        )
        sys.exit(1)

    t0 = int(rows[0]["ts_unix"])
    t_min = [(int(r["ts_unix"]) - t0) / 60.0 for r in rows]
    cpu_busy = [100.0 - float(r["cpu_idle_pct"]) for r in rows]
    cpu_iowait = [float(r["cpu_iowait_pct"]) for r in rows]
    mem_used_pct = [
        (int(r["mem_total_kb"]) - int(r["mem_available_kb"]))
        / int(r["mem_total_kb"])
        * 100
        for r in rows
    ]
    load_1m = [float(r["load_1m"]) for r in rows]
    procs_running = [int(r["procs_running"]) for r in rows]

    fig, axes = plt.subplots(3, 1, figsize=(11, 8), sharex=True)

    ax = axes[0]
    ax.plot(t_min, cpu_busy, label="busy", color="tab:blue")
    ax.plot(t_min, cpu_iowait, label="iowait", color="tab:orange")
    ax.set_ylabel("CPU %")
    ax.set_ylim(0, 100)
    ax.grid(True, alpha=0.3)
    ax.legend(loc="upper right")

    ax = axes[1]
    ax.plot(t_min, mem_used_pct, color="tab:green")
    ax.set_ylabel("memory used %")
    ax.set_ylim(0, 100)
    ax.grid(True, alpha=0.3)

    ax = axes[2]
    ax.plot(t_min, load_1m, label="load 1m", color="tab:red")
    ax.set_ylabel("load 1m")
    ax.set_xlabel("minutes since first sample")
    ax.grid(True, alpha=0.3)
    ax2 = ax.twinx()
    ax2.plot(
        t_min,
        procs_running,
        label="procs running",
        color="tab:purple",
        linestyle="--",
        alpha=0.7,
    )
    ax2.set_ylabel("procs running")
    ax.legend(loc="upper left")
    ax2.legend(loc="upper right")

    fig.suptitle(f"Resource usage — {input_path.name}")
    fig.tight_layout()
    fig.savefig(output_path, dpi=120)
    print(f"wrote {output_path}")


if __name__ == "__main__":
    main()
