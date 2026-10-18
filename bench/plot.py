#!/usr/bin/env python3
"""Generate gruvbox-themed benchmark graphs from bench/results/ data.

All numbers are per refresh: (cost of 1+K refreshes - cost of 1) / K, as
recorded by bench/run.sh, so startup and htop's inter-refresh sleep cancel.

Produces:
  1. syscall_scaling.png   - Syscalls per refresh vs process count
  2. collection_time.png   - CPU time per refresh vs process count
  3. syscall_breakdown.png - Per-syscall breakdown per refresh at the largest N

Usage: python3 bench/plot.py [--results-dir bench/results]
"""

import argparse
import json
import os
import re
import statistics
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


def load_meta(results_dir, n):
    path = os.path.join(results_dir, f"meta_{n}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def scales_found(results_dir):
    """Scale points with complete metadata, sorted."""
    found = []
    for name in os.listdir(results_dir):
        m = re.fullmatch(r"meta_(\d+)\.json", name)
        if m and "extra_refreshes" in (load_meta(results_dir, int(m.group(1))) or {}):
            found.append(int(m.group(1)))
    return sorted(found)


def per_refresh_syscalls(results_dir, tool, n, k):
    """{syscall: calls per refresh} from the base/run strace pair."""
    _, base = parse_strace(os.path.join(results_dir, f"{tool}_strace_{n}_base.txt"))
    _, run = parse_strace(os.path.join(results_dir, f"{tool}_strace_{n}_run.txt"))
    if not run:
        return {}
    return {
        name: (run.get(name, 0) - base.get(name, 0)) / k
        for name in set(base) | set(run)
        if run.get(name, 0) > base.get(name, 0)
    }


def per_refresh_cpu_ms(results_dir, tool, n, k):
    """Median user+sys CPU ms per refresh, or None."""
    path = os.path.join(results_dir, f"{tool}_cpu_{n}.txt")
    if not os.path.exists(path):
        return None
    samples = {"base": [], "run": []}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 3 and parts[0] in samples:
                samples[parts[0]].append(float(parts[1]) + float(parts[2]))
    if not samples["base"] or not samples["run"]:
        return None
    delta = statistics.median(samples["run"]) - statistics.median(samples["base"])
    return max(delta, 0.0) / k * 1000.0


def plot_lines(ax, xs, series):
    for label, color, marker, ys in series:
        pts = [(x, y) for x, y in zip(xs, ys) if y is not None]
        if pts:
            ax.plot(*zip(*pts), color=color, marker=marker, linewidth=2,
                    markersize=8, label=label, zorder=3)


def plot_syscall_scaling(results_dir, output_dir, scales):
    """Graph 1: syscalls per refresh vs process count."""
    procs, bpf, htop = [], [], []
    for n in scales:
        meta = load_meta(results_dir, n)
        k = meta["extra_refreshes"]
        b = per_refresh_syscalls(results_dir, "bpftop", n, k)
        h = per_refresh_syscalls(results_dir, "htop", n, k)
        procs.append(meta["actual_procs"])
        bpf.append(sum(b.values()) if b else None)
        htop.append(sum(h.values()) if h else None)

    fig, ax = plt.subplots(figsize=(10, 6))
    plot_lines(ax, procs, [("htop", BR_RED, "o", htop), ("bpftop", BR_GREEN, "s", bpf)])
    ax.set_yscale("log")
    ax.set_xlabel("Process Count")
    ax.set_ylabel("Syscalls per Refresh (log)")
    ax.set_title("Syscalls per Refresh: bpftop vs htop", fontsize=14, fontweight="bold")
    ax.legend(fontsize=12)

    out = os.path.join(output_dir, "syscall_scaling.png")
    fig.savefig(out)
    plt.close(fig)
    print(f"  Saved {out}")


def plot_cpu_time(results_dir, output_dir, scales):
    """Graph 2: CPU time (user+sys) per refresh vs process count."""
    procs, bpf, htop = [], [], []
    for n in scales:
        meta = load_meta(results_dir, n)
        k = meta["extra_refreshes"]
        procs.append(meta["actual_procs"])
        bpf.append(per_refresh_cpu_ms(results_dir, "bpftop", n, k))
        htop.append(per_refresh_cpu_ms(results_dir, "htop", n, k))

    fig, ax = plt.subplots(figsize=(10, 6))
    plot_lines(ax, procs, [("htop", BR_RED, "o", htop), ("bpftop", BR_GREEN, "s", bpf)])
    ax.set_xlabel("Process Count")
    ax.set_ylabel("CPU Time per Refresh (ms, user+sys)")
    ax.set_title("CPU Cost per Refresh: bpftop vs htop", fontsize=14, fontweight="bold")
    ax.legend(fontsize=12)

    out = os.path.join(output_dir, "collection_time.png")
    fig.savefig(out)
    plt.close(fig)
    print(f"  Saved {out}")


def plot_syscall_breakdown(results_dir, output_dir, scales):
    """Graph 3: per-syscall calls per refresh at the largest scale."""
    n = scales[-1]
    k = load_meta(results_dir, n)["extra_refreshes"]
    bpf = per_refresh_syscalls(results_dir, "bpftop", n, k)
    htop = per_refresh_syscalls(results_dir, "htop", n, k)

    names = sorted(set(bpf) | set(htop), key=lambda s: max(htop.get(s, 0), bpf.get(s, 0)), reverse=True)[:15]
    names.reverse()  # bottom-to-top for horizontal bars

    fig, ax = plt.subplots(figsize=(12, 7))
    y = np.arange(len(names))
    height = 0.35
    ax.barh(y + height / 2, [htop.get(s, 0) for s in names], height, color=BR_RED, label="htop", zorder=3)
    ax.barh(y - height / 2, [bpf.get(s, 0) for s in names], height, color=BR_GREEN, label="bpftop", zorder=3)
    ax.set_yticks(y)
    ax.set_yticklabels(names)
    ax.set_xscale("log")
    ax.set_xlabel("Calls per Refresh (log)")
    procs = load_meta(results_dir, n)["actual_procs"]
    ax.set_title(f"Syscall Breakdown per Refresh ({procs} processes)", fontsize=14, fontweight="bold")
    ax.legend(fontsize=12, loc="lower right")

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

    scales = scales_found(results_dir)
    if not scales:
        print(f"ERROR: no bench/run.sh results (meta_N.json) in {results_dir}")
        return 1

    setup_style()

    print(f"Generating benchmark graphs for N={scales}...")
    plot_syscall_scaling(results_dir, output_dir, scales)
    plot_cpu_time(results_dir, output_dir, scales)
    plot_syscall_breakdown(results_dir, output_dir, scales)
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
