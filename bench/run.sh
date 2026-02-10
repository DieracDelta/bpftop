#!/usr/bin/env bash
# Benchmark orchestration: bpftop vs htop at varying process counts.
#
# Uses hyperfine for statistically rigorous timing, strace for syscall counts.
# Spawns dummy processes at each scale point, benchmarks both tools.
#
# Usage: sudo bash bench/run.sh

set -euo pipefail

DUMMY_PIDS=()

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
BENCH_BIN="${SCRIPT_DIR}/../target/release/bench"
HYPERFINE_RUNS=20
HYPERFINE_WARMUP=3
HTOP_REFRESHES=5
SCALES=(100 500 1000 2000 5000 10000)

mkdir -p "$RESULTS_DIR"

# ── Helpers ──────────────────────────────────────────────────────

log() { echo ">>> $*" >&2; }

count_procs() {
    ls -1d /proc/[0-9]* 2>/dev/null | wc -l
}

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
    log "$(count_procs) total processes visible in /proc"
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

command -v strace >/dev/null || { echo "ERROR: strace not found" >&2; exit 1; }
command -v htop >/dev/null || { echo "ERROR: htop not found" >&2; exit 1; }
command -v hyperfine >/dev/null || { echo "ERROR: hyperfine not found" >&2; exit 1; }

# ── Baseline ─────────────────────────────────────────────────────

log "Recording baseline process count: $(count_procs)"

# ── Main benchmark loop ─────────────────────────────────────────

for N in "${SCALES[@]}"; do
    log "============================================"
    log "Scale point: N=$N"
    log "============================================"

    spawn_dummies "$N"
    ACTUAL_PROCS=$(count_procs)
    log "Actual process count: $ACTUAL_PROCS"

    # ── bpftop: hyperfine timing ─────────────────────────────
    # bench binary does 1 BPF iteration per invocation with --iterations 1 --warmup 0
    # hyperfine handles the repetition and statistics.
    log "Running bpftop via hyperfine..."
    hyperfine \
        --runs "$HYPERFINE_RUNS" \
        --warmup "$HYPERFINE_WARMUP" \
        --export-json "$RESULTS_DIR/bpftop_hyperfine_${N}.json" \
        --command-name "bpftop (N=$N)" \
        "$BENCH_BIN --iterations 1 --warmup 0" \
        2>&1 | tee "$RESULTS_DIR/bpftop_hyperfine_${N}.log" >&2

    # Also run the bench binary's own detailed timing (has percentiles)
    log "Running bpftop bench (internal timing)..."
    "$BENCH_BIN" --iterations 50 --warmup 5 --json \
        > "$RESULTS_DIR/bpftop_timing_${N}.json" 2>/dev/null

    # ── htop: hyperfine timing ───────────────────────────────
    # htop needs a tty; use script(1) to provide one.
    log "Running htop via hyperfine..."
    hyperfine \
        --runs "$HYPERFINE_RUNS" \
        --warmup "$HYPERFINE_WARMUP" \
        --export-json "$RESULTS_DIR/htop_hyperfine_${N}.json" \
        --command-name "htop (N=$N)" \
        "script -qfc 'htop -d 1 -n $HTOP_REFRESHES' /dev/null > /dev/null" \
        2>&1 | tee "$RESULTS_DIR/htop_hyperfine_${N}.log" >&2

    # ── bpftop: syscall count (strace pass) ──────────────────
    log "Running bpftop bench (strace pass)..."
    strace -c -S calls -o "$RESULTS_DIR/bpftop_strace_${N}.txt" \
        "$BENCH_BIN" --iterations 5 --warmup 1 2>/dev/null

    # ── htop: syscall count (strace pass) ────────────────────
    # -f follows forks so we trace htop, not just the script wrapper
    log "Running htop (strace pass)..."
    strace -f -c -S calls -o "$RESULTS_DIR/htop_strace_${N}.txt" \
        script -qfc "htop -d 1 -n $HTOP_REFRESHES" /dev/null \
        > /dev/null 2>&1 || true

    # ── Head-to-head hyperfine comparison ────────────────────
    log "Running head-to-head comparison..."
    hyperfine \
        --runs "$HYPERFINE_RUNS" \
        --warmup "$HYPERFINE_WARMUP" \
        --export-json "$RESULTS_DIR/comparison_${N}.json" \
        --command-name "bpftop" "$BENCH_BIN --iterations 1 --warmup 0" \
        --command-name "htop" "script -qfc 'htop -d 1 -n $HTOP_REFRESHES' /dev/null > /dev/null" \
        2>&1 | tee "$RESULTS_DIR/comparison_${N}.log" >&2

    # Record metadata
    cat > "$RESULTS_DIR/meta_${N}.json" <<METAEOF
{
    "scale": $N,
    "actual_procs": $ACTUAL_PROCS,
    "hyperfine_runs": $HYPERFINE_RUNS,
    "htop_refreshes": $HTOP_REFRESHES,
    "timestamp": "$(date -Iseconds)"
}
METAEOF

    kill_dummies
    log "Scale $N complete."
done

log ""
log "All benchmarks complete. Results in $RESULTS_DIR/"
log ""
log "Files per scale point:"
log "  bpftop_hyperfine_N.json - hyperfine results for bpftop"
log "  htop_hyperfine_N.json   - hyperfine results for htop"
log "  comparison_N.json       - head-to-head hyperfine comparison"
log "  bpftop_timing_N.json    - bpftop internal timing (percentiles)"
log "  bpftop_strace_N.txt     - bpftop syscall summary"
log "  htop_strace_N.txt       - htop syscall summary"
log "  meta_N.json             - run metadata"
log ""
log "Run 'python3 bench/plot.py' to generate graphs."
