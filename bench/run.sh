#!/usr/bin/env bash
# Benchmark bpftop vs htop: syscalls and CPU time per refresh, at varying
# process counts.
#
# Both tools are measured the same way: one run with 1 refresh and one
# with 1+K refreshes. The difference divided by K is the per-refresh cost,
# which cancels out startup (BPF load and BTF parsing for bpftop, init for
# htop) and htop's sleep between refreshes.
#
# Usage: sudo bash bench/run.sh
# Knobs (env): SCALES="100 1000" K=20 REPS=5 BENCH_BIN=... RESULTS_DIR=...

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
BENCH_BIN="${BENCH_BIN:-$SCRIPT_DIR/../target/release/bench}"
CPUTIME="python3 $SCRIPT_DIR/cputime.py"
read -ra SCALES <<< "${SCALES:-100 500 1000 2000 5000 10000}"
K="${K:-20}"        # extra refreshes in the "run" measurement
REPS="${REPS:-5}"   # CPU time repetitions (plot.py takes the median)
DUMMY_PIDS=()

mkdir -p "$RESULTS_DIR"

# ── Helpers ──────────────────────────────────────────────────────

log() { echo ">>> $*" >&2; }

# Glob counts: an `ls | wc` pipeline fails under pipefail when a PID from
# the glob exits before ls stats it.
count_procs() { local p=(/proc/[0-9]*); echo "${#p[@]}"; }
count_tasks() { local t=(/proc/[0-9]*/task/*); echo "${#t[@]}"; }

# Spawn N dummy sleep processes, store PIDs in DUMMY_PIDS array
spawn_dummies() {
    local n=$1
    DUMMY_PIDS=()
    log "Spawning $n dummy processes..."
    for ((i = 0; i < n; i++)); do
        sleep infinity &
        DUMMY_PIDS+=($!)
    done
    sleep 1
}

kill_dummies() {
    if [ ${#DUMMY_PIDS[@]} -gt 0 ]; then
        log "Killing ${#DUMMY_PIDS[@]} dummy processes..."
        kill "${DUMMY_PIDS[@]}" 2>/dev/null || true
        wait 2>/dev/null || true
        DUMMY_PIDS=()
        sleep 1
    fi
}

trap kill_dummies EXIT

# Command line doing N refreshes.
bpftop_cmd() { echo "$BENCH_BIN --iterations $1 --warmup 0"; }
htop_cmd() { echo "htop -d 1 -n $1"; }

# Run a command; htop needs a terminal, so it gets a pseudo-terminal.
run_as() {
    local tool=$1; shift
    if [ "$tool" = htop ]; then
        script -qfec "$*" /dev/null > /dev/null
    else
        "$@" > /dev/null 2>&1
    fi
}

# ── Preflight checks ────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (BPF requires CAP_BPF)" >&2
    exit 1
fi

if [ ! -x "$BENCH_BIN" ]; then
    echo "ERROR: bench binary not found at $BENCH_BIN" >&2
    echo "  Build it first: cargo build --release --bin bench" >&2
    exit 1
fi

for cmd in strace htop script python3; do
    command -v "$cmd" >/dev/null || { echo "ERROR: $cmd not found" >&2; exit 1; }
done

# ── Main benchmark loop ─────────────────────────────────────────

for N in "${SCALES[@]}"; do
    log "============================================"
    log "Scale point: N=$N"
    log "============================================"

    spawn_dummies "$N"
    ACTUAL_PROCS=$(count_procs)
    ACTUAL_TASKS=$(count_tasks)
    log "$ACTUAL_PROCS processes, $ACTUAL_TASKS tasks"

    for tool in bpftop htop; do
        cpu_file="$RESULTS_DIR/${tool}_cpu_${N}.txt"
        rm -f "$cpu_file"
        for label in base run; do
            refreshes=1
            [ "$label" = run ] && refreshes=$((K + 1))
            cmd=$("${tool}_cmd" "$refreshes")

            log "$tool: $refreshes refresh(es), strace"
            run_as "$tool" strace -f -c -S calls -o "$RESULTS_DIR/${tool}_strace_${N}_${label}.txt" $cmd

            log "$tool: $refreshes refresh(es), CPU time x$REPS"
            for ((r = 0; r < REPS; r++)); do
                run_as "$tool" $CPUTIME "$cpu_file" "$label" $cmd
            done
        done
    done

    # In-process collect() latency percentiles (bpftop only)
    log "bpftop: in-process timing"
    "$BENCH_BIN" --iterations 50 --warmup 5 --json \
        > "$RESULTS_DIR/bpftop_timing_${N}.json" 2>/dev/null

    cat > "$RESULTS_DIR/meta_${N}.json" <<METAEOF
{
    "scale": $N,
    "actual_procs": $ACTUAL_PROCS,
    "actual_tasks": $ACTUAL_TASKS,
    "extra_refreshes": $K,
    "cpu_reps": $REPS,
    "kernel": "$(uname -r)",
    "timestamp": "$(date -Iseconds)"
}
METAEOF

    kill_dummies
    log "Scale $N complete."
done

log ""
log "All benchmarks complete. Results in $RESULTS_DIR/"
log ""
log "Files per scale point (TOOL = bpftop | htop):"
log "  TOOL_strace_N_{base,run}.txt - strace -c of 1 and 1+K refreshes"
log "  TOOL_cpu_N.txt               - CPU time (label user sys) per repetition"
log "  bpftop_timing_N.json         - bpftop in-process collect() timing"
log "  meta_N.json                  - run metadata"
log ""
log "Run 'python3 bench/plot.py' to generate graphs."
