#!/usr/bin/env python3
"""Generate gruvbox-themed benchmark graphs from bench/results/ data.

Produces:
  1. syscall_scaling.png  - Syscall count vs process count (O(N) vs ~O(1))
  2. collection_time.png  - Collection time vs process count with p95 band
  3. syscall_breakdown.png - Per-syscall breakdown at N=5000

Usage: python3 bench/plot.py [--results-dir bench/results]
"""

import argparse
import json
import os
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# ── Gruvbox dark palette (from palette.rs) ───────────────────────

BG       = "#282828"
BG1      = "#3c3836"
BG2      = "#504945"
FG       = "#ebdbb2"
FG4      = "#a89984"
BR_GREEN = "#b8bb26"
BR_RED   = "#fb4934"
BR_YELLOW = "#fabd2f"
BR_BLUE  = "#83a598"
BR_AQUA  = "#8ec07c"
BR_ORANGE = "#fe8019"

SCALES = [100, 500, 1000, 2000, 5000, 10000]


def setup_style():
    """Configure matplotlib for gruvbox dark theme."""
    plt.rcParams.update({
        "figure.facecolor": BG,
        "axes.facecolor": BG,
        "axes.edgecolor": BG2,
        "axes.labelcolor": FG,
        "axes.grid": True,
        "grid.color": BG1,
        "grid.alpha": 0.8,
        "text.color": FG,
        "xtick.color": FG4,
        "ytick.color": FG4,
        "legend.facecolor": BG1,
        "legend.edgecolor": BG2,
        "legend.labelcolor": FG,
        "font.family": "monospace",
        "font.size": 11,
        "savefig.facecolor": BG,
        "savefig.dpi": 150,
        "savefig.bbox": "tight",
    })


def parse_strace(path):
    """Parse strace -c output, returning (total_calls, {syscall: count})."""
    if not os.path.exists(path):
        return 0, {}

    with open(path) as f:
        lines = f.readlines()

    syscalls = {}
    total = 0

    for line in lines:
        # strace -c format: % time  seconds  usecs/call  calls  errors  syscall
        # or:                % time  seconds  usecs/call  calls  syscall
        m = re.match(
            r"\s*[\d.]+\s+[\d.]+\s+\d+\s+(\d+)\s+\d*\s*(\w+)\s*$", line
        )
        if m:
            calls = int(m.group(1))
            name = m.group(2)
            if name == "total":
                continue
            syscalls[name] = calls
            total += calls

    return total, syscalls


def load_bpftop_timing(results_dir, n):
    """Load bpftop timing JSON for scale point N."""
    path = os.path.join(results_dir, f"bpftop_timing_{n}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def load_hyperfine(results_dir, tool, n):
    """Load hyperfine JSON for a tool at scale point N.

    Returns dict with mean/stddev/min/max in seconds, or None.
    """
    path = os.path.join(results_dir, f"{tool}_hyperfine_{n}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        data = json.load(f)
    if "results" not in data or not data["results"]:
        return None
    return data["results"][0]


def plot_syscall_scaling(results_dir, output_dir):
    """Graph 1: Total syscall count vs process count."""
    bpftop_calls = []
    htop_calls = []
    scales_found = []

    for n in SCALES:
        bt, _ = parse_strace(os.path.join(results_dir, f"bpftop_strace_{n}.txt"))
        ht, _ = parse_strace(os.path.join(results_dir, f"htop_strace_{n}.txt"))
        if bt > 0 or ht > 0:
            scales_found.append(n)
            bpftop_calls.append(bt)
            htop_calls.append(ht)

    if not scales_found:
        print("WARNING: No strace data found, skipping syscall_scaling.png")
        return

    fig, ax = plt.subplots(figsize=(10, 6))

    ax.plot(scales_found, htop_calls, color=BR_RED, marker="o",
            linewidth=2, markersize=8, label="htop", zorder=3)
    ax.plot(scales_found, bpftop_calls, color=BR_GREEN, marker="s",
            linewidth=2, markersize=8, label="bpftop", zorder=3)

    ax.set_xlabel("Process Count")
    ax.set_ylabel("Syscalls per Benchmark Run")
    ax.set_title("Syscall Scaling: bpftop vs htop", fontsize=14, fontweight="bold")
    ax.legend(fontsize=12)

    # Format y-axis with K suffix for thousands
    ax.yaxis.set_major_formatter(
        matplotlib.ticker.FuncFormatter(lambda x, _: f"{x/1000:.0f}K" if x >= 1000 else f"{x:.0f}")
    )

    out = os.path.join(output_dir, "syscall_scaling.png")
    fig.savefig(out)
    plt.close(fig)
    print(f"  Saved {out}")


def plot_collection_time(results_dir, output_dir):
    """Graph 2: Collection time vs process count (hyperfine data)."""
    bpf_means = []
    bpf_stddevs = []
    htop_means = []
    htop_stddevs = []
    scales_found = []

    for n in SCALES:
        bpf = load_hyperfine(results_dir, "bpftop", n)
        ht = load_hyperfine(results_dir, "htop", n)
        if bpf is None and ht is None:
            # Fall back to internal bench timing for bpftop
            data = load_bpftop_timing(results_dir, n)
            if data is None:
                continue
            scales_found.append(n)
            s = data["stats"]
            bpf_means.append(s["mean_us"] / 1000.0)  # us -> ms
            bpf_stddevs.append(s["stddev_us"] / 1000.0)
            htop_means.append(None)
            htop_stddevs.append(None)
        else:
            scales_found.append(n)
            if bpf:
                bpf_means.append(bpf["mean"] * 1000)  # s -> ms
                bpf_stddevs.append(bpf["stddev"] * 1000)
            else:
                bpf_means.append(None)
                bpf_stddevs.append(None)
            if ht:
                htop_means.append(ht["mean"] * 1000)
                htop_stddevs.append(ht["stddev"] * 1000)
            else:
                htop_means.append(None)
                htop_stddevs.append(None)

    if not scales_found:
        print("WARNING: No timing data found, skipping collection_time.png")
        return

    fig, ax = plt.subplots(figsize=(10, 6))

    # Plot bpftop
    bpf_x = [s for s, m in zip(scales_found, bpf_means) if m is not None]
    bpf_y = np.array([m for m in bpf_means if m is not None])
    bpf_err = np.array([s for s in bpf_stddevs if s is not None])
    if len(bpf_x) > 0:
        ax.fill_between(bpf_x, bpf_y - bpf_err, bpf_y + bpf_err,
                         alpha=0.2, color=BR_GREEN)
        ax.plot(bpf_x, bpf_y, color=BR_GREEN, marker="s",
                linewidth=2, markersize=8, label="bpftop", zorder=3)

    # Plot htop
    ht_x = [s for s, m in zip(scales_found, htop_means) if m is not None]
    ht_y = np.array([m for m in htop_means if m is not None])
    ht_err = np.array([s for s in htop_stddevs if s is not None])
    if len(ht_x) > 0:
        ax.fill_between(ht_x, ht_y - ht_err, ht_y + ht_err,
                         alpha=0.2, color=BR_RED)
        ax.plot(ht_x, ht_y, color=BR_RED, marker="o",
                linewidth=2, markersize=8, label="htop", zorder=3)

    ax.set_xlabel("Process Count")
    ax.set_ylabel("Time per Refresh (ms)")
    ax.set_title("Refresh Time: bpftop vs htop (hyperfine)",
                 fontsize=14, fontweight="bold")
    ax.legend(fontsize=12)

    out = os.path.join(output_dir, "collection_time.png")
    fig.savefig(out)
    plt.close(fig)
    print(f"  Saved {out}")


def plot_syscall_breakdown(results_dir, output_dir, target_n=5000):
    """Graph 3: Horizontal bar chart of per-syscall counts at N=target_n."""
    _, bpf_syscalls = parse_strace(
        os.path.join(results_dir, f"bpftop_strace_{target_n}.txt")
    )
    _, htop_syscalls = parse_strace(
        os.path.join(results_dir, f"htop_strace_{target_n}.txt")
    )

    if not bpf_syscalls and not htop_syscalls:
        # Try the largest available scale
        for n in reversed(SCALES):
            _, bpf_syscalls = parse_strace(
                os.path.join(results_dir, f"bpftop_strace_{n}.txt")
            )
            _, htop_syscalls = parse_strace(
                os.path.join(results_dir, f"htop_strace_{n}.txt")
            )
            if bpf_syscalls or htop_syscalls:
                target_n = n
                break
        else:
            print("WARNING: No strace data found, skipping syscall_breakdown.png")
            return

    # Get top syscalls from htop (most interesting)
    all_names = set(bpf_syscalls.keys()) | set(htop_syscalls.keys())
    # Sort by htop count descending, take top 15
    sorted_names = sorted(all_names, key=lambda s: htop_syscalls.get(s, 0), reverse=True)[:15]
    sorted_names.reverse()  # bottom-to-top for horizontal bars

    bpf_vals = [bpf_syscalls.get(n, 0) for n in sorted_names]
    htop_vals = [htop_syscalls.get(n, 0) for n in sorted_names]

    fig, ax = plt.subplots(figsize=(12, 7))
    y = np.arange(len(sorted_names))
    height = 0.35

    ax.barh(y + height / 2, htop_vals, height, color=BR_RED, label="htop", zorder=3)
    ax.barh(y - height / 2, bpf_vals, height, color=BR_GREEN, label="bpftop", zorder=3)

    ax.set_yticks(y)
    ax.set_yticklabels(sorted_names)
    ax.set_xlabel("Syscall Count")
    ax.set_title(f"Syscall Breakdown at N={target_n}", fontsize=14, fontweight="bold")
    ax.legend(fontsize=12, loc="lower right")

    # Log scale if the difference is huge
    max_val = max(max(htop_vals, default=1), max(bpf_vals, default=1))
    min_val = min(
        min((v for v in htop_vals if v > 0), default=1),
        min((v for v in bpf_vals if v > 0), default=1),
    )
    if max_val > min_val * 100:
        ax.set_xscale("log")

    out = os.path.join(output_dir, "syscall_breakdown.png")
    fig.savefig(out)
    plt.close(fig)
    print(f"  Saved {out}")




def main():
    parser = argparse.ArgumentParser(description="Generate benchmark graphs")
    parser.add_argument(
        "--results-dir",
        default=os.path.join(os.path.dirname(__file__), "results"),
        help="Directory containing benchmark results",
    )
    args = parser.parse_args()

    results_dir = args.results_dir
    output_dir = results_dir  # PNGs go alongside the data

    if not os.path.isdir(results_dir):
        print(f"ERROR: Results directory not found: {results_dir}")
        print("  Run 'sudo bash bench/run.sh' first.")
        return 1

    setup_style()

    print("Generating benchmark graphs...")
    plot_syscall_scaling(results_dir, output_dir)
    plot_collection_time(results_dir, output_dir)
    plot_syscall_breakdown(results_dir, output_dir)
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
