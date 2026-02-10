//! Headless benchmark binary for bpftop's BPF collection pipeline.
//!
//! Follows the diagnose.rs pattern: self-contained, loads BPF directly.
//! Runs the BPF task iterator + /proc system stats in a loop and outputs
//! timing data as JSON.
//!
//! Run: sudo ./target/release/bench --iterations 50 --json

use std::io::Read;
use std::time::Instant;

use anyhow::{Context, Result};
use aya::programs::iter::{Iter, IterLink};
use aya::programs::TracePoint;
use aya::{Btf, Ebpf};
use bpftop_common::TaskInfo;
use clap::Parser;
use serde::Serialize;

static BPF_OBJ: &[u8] =
    aya::include_bytes_aligned!("../../../bpftop-ebpf/target/bpfel-unknown-none/release/bpftop-ebpf");

#[derive(Parser)]
#[command(name = "bench", about = "Benchmark bpftop BPF collection pipeline")]
struct Cli {
    /// Number of timed iterations
    #[arg(short, long, default_value_t = 50)]
    iterations: usize,

    /// Number of warmup iterations (not timed)
    #[arg(short, long, default_value_t = 5)]
    warmup: usize,

    /// Output results as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct BenchResult {
    iterations: usize,
    warmup: usize,
    process_count: usize,
    timings_us: Vec<f64>,
    stats: Stats,
    system: SystemMeta,
}

#[derive(Serialize)]
struct Stats {
    min_us: f64,
    max_us: f64,
    mean_us: f64,
    median_us: f64,
    p95_us: f64,
    p99_us: f64,
    stddev_us: f64,
}

#[derive(Serialize)]
struct SystemMeta {
    kernel: String,
    arch: String,
    cpus: usize,
    hostname: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load eBPF programs
    eprintln!("Loading eBPF programs...");
    let mut bpf = Ebpf::load(BPF_OBJ).context("loading eBPF object")?;
    let btf = Btf::from_sys_fs().context("reading kernel BTF")?;

    // Load task iterator
    let iter_prog: &mut Iter = bpf
        .program_mut("dump_task")
        .context("dump_task not found")?
        .try_into()
        .context("not an Iter")?;
    iter_prog.load("task", &btf).context("loading dump_task")?;

    // Load tracepoints (needed for realistic pipeline)
    load_tracepoint(&mut bpf, "capture_cmdline", "sched", "sched_process_exec")?;
    load_tracepoint(&mut bpf, "cleanup_cmdline", "sched", "sched_process_exit")?;

    eprintln!("BPF loaded. Running {} warmup iterations...", cli.warmup);

    // Warmup
    let mut last_count = 0;
    for _ in 0..cli.warmup {
        let tasks = collect_once(&mut bpf)?;
        last_count = tasks.len();
    }
    eprintln!("Warmup done. {} tasks seen. Running {} timed iterations...", last_count, cli.iterations);

    // Timed iterations
    let mut timings_us = Vec::with_capacity(cli.iterations);
    let mut process_count = 0;

    for i in 0..cli.iterations {
        let start = Instant::now();
        let tasks = collect_once(&mut bpf)?;
        let elapsed = start.elapsed();

        process_count = tasks.len();
        timings_us.push(elapsed.as_secs_f64() * 1_000_000.0);

        if !cli.json && (i + 1) % 10 == 0 {
            eprintln!("  [{}/{}] {:.0} µs, {} tasks",
                i + 1, cli.iterations, timings_us.last().unwrap(), process_count);
        }
    }

    let stats = compute_stats(&timings_us);
    let system = get_system_meta();

    let result = BenchResult {
        iterations: cli.iterations,
        warmup: cli.warmup,
        process_count,
        timings_us,
        stats,
        system,
    };

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        eprintln!("\n=== bpftop Benchmark Results ===");
        eprintln!("Iterations: {}", result.iterations);
        eprintln!("Process count: {}", result.process_count);
        eprintln!("Min:    {:.1} µs", result.stats.min_us);
        eprintln!("Max:    {:.1} µs", result.stats.max_us);
        eprintln!("Mean:   {:.1} µs", result.stats.mean_us);
        eprintln!("Median: {:.1} µs", result.stats.median_us);
        eprintln!("P95:    {:.1} µs", result.stats.p95_us);
        eprintln!("P99:    {:.1} µs", result.stats.p99_us);
        eprintln!("Stddev: {:.1} µs", result.stats.stddev_us);
    }

    Ok(())
}

/// Run one full collection cycle: BPF iterator walk + parse tasks.
/// This is the core operation being benchmarked.
fn collect_once(bpf: &mut Ebpf) -> Result<Vec<TaskInfo>> {
    // Run the BPF task iterator
    let prog: &mut Iter = bpf
        .program_mut("dump_task")
        .context("dump_task not found")?
        .try_into()
        .context("not an Iter")?;

    let link_id = prog.attach().context("attach")?;
    let link: IterLink = prog.take_link(link_id).context("take_link")?;
    let mut file = link.into_file().context("into_file")?;

    let mut buf = Vec::with_capacity(64 * 1024);
    file.read_to_end(&mut buf).context("read iterator")?;

    let task_size = std::mem::size_of::<TaskInfo>();
    let tasks: Vec<TaskInfo> = buf
        .chunks_exact(task_size)
        .map(|chunk| unsafe { std::ptr::read_unaligned(chunk.as_ptr() as *const TaskInfo) })
        .collect();

    // Also read /proc system stats (this is what bpftop does each cycle)
    let _ = std::fs::read_to_string("/proc/stat");
    let _ = std::fs::read_to_string("/proc/meminfo");
    let _ = std::fs::read_to_string("/proc/loadavg");
    let _ = std::fs::read_to_string("/proc/uptime");

    Ok(tasks)
}

fn load_tracepoint(bpf: &mut Ebpf, name: &str, category: &str, tp: &str) -> Result<()> {
    let prog: &mut TracePoint = bpf
        .program_mut(name)
        .context(format!("{name} not found"))?
        .try_into()
        .context(format!("{name} not a TracePoint"))?;
    prog.load().context(format!("loading {name}"))?;
    prog.attach(category, tp).context(format!("attaching {name}"))?;
    Ok(())
}

fn compute_stats(timings: &[f64]) -> Stats {
    let mut sorted = timings.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let n = sorted.len() as f64;
    let sum: f64 = sorted.iter().sum();
    let mean = sum / n;

    let variance: f64 = sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let stddev = variance.sqrt();

    let median = percentile(&sorted, 50.0);
    let p95 = percentile(&sorted, 95.0);
    let p99 = percentile(&sorted, 99.0);

    Stats {
        min_us: sorted[0],
        max_us: *sorted.last().unwrap(),
        mean_us: mean,
        median_us: median,
        p95_us: p95,
        p99_us: p99,
        stddev_us: stddev,
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let idx = (p / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn get_system_meta() -> SystemMeta {
    let kernel = std::fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .split_whitespace()
        .nth(2)
        .unwrap_or("unknown")
        .to_string();

    let arch = std::env::consts::ARCH.to_string();

    let cpus = std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count();

    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();

    SystemMeta {
        kernel,
        arch,
        cpus,
        hostname,
    }
}
