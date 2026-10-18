//! Headless benchmark for bpftop's collection pipeline.
//!
//! Drives the real `Collector::collect()` (BPF iterator, per-process
//! enrichment, /proc system stats, net stats) in a loop, so syscall
//! counts and timings match what the TUI's background thread does.
//!
//! Run: sudo ./target/release/bench --iterations 50 --json
//! Syscalls per cycle: compare `strace -fc` of `--iterations 1` vs `--iterations N`.

#[allow(dead_code)]
#[path = "../data/mod.rs"]
mod data;
#[allow(dead_code)]
#[path = "../ebpf/mod.rs"]
mod ebpf;

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;

use data::collector::{CollectTimings, Collector};
use ebpf::loader::EbpfLoader;

#[derive(Parser)]
#[command(name = "bench", about = "Benchmark bpftop's collection pipeline")]
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

    /// Only load and attach the BPF programs, then idle this many seconds
    /// (for measuring probe overhead on other workloads)
    #[arg(long)]
    hold: Option<u64>,

    /// Wait this long after loading before collecting, so BPF programs
    /// observe some activity first
    #[arg(long, default_value_t = 0)]
    settle_ms: u64,

    /// Sleep between timed iterations (gives CPU% a real interval)
    #[arg(long, default_value_t = 0)]
    interval_ms: u64,

    /// Print the last cycle's processes as TSV instead of timing results:
    /// pid, user, frozen, net_tx, net_rx, net_if, cpu_percent, cmdline
    #[arg(long)]
    dump: bool,
}

#[derive(Serialize)]
struct BenchResult {
    iterations: usize,
    warmup: usize,
    process_count: usize,
    task_count: u32,
    net_probe_mode: String,
    timings_us: Vec<f64>,
    stats: Stats,
    /// Median wall time per collect() phase.
    phases_median_us: Phases,
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

#[derive(Serialize, Default)]
struct Phases {
    system_stats: f64,
    cgroup_tick: f64,
    bpf_iter: f64,
    per_process: f64,
    gpu: f64,
    net: f64,
    tree: f64,
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

    eprintln!("Loading eBPF programs...");
    let loader = EbpfLoader::load().context("loading eBPF")?;
    let net_probe_mode = format!("{:?}", loader.net_probe_mode.unwrap());
    if let Some(secs) = cli.hold {
        eprintln!("BPF loaded (network probes: {net_probe_mode}); holding for {secs}s");
        std::thread::sleep(Duration::from_secs(secs));
        return Ok(());
    }
    let mut collector = Collector::new(loader);
    std::thread::sleep(Duration::from_millis(cli.settle_ms));

    eprintln!("BPF loaded. Running {} warmup iterations...", cli.warmup);
    for _ in 0..cli.warmup {
        collector.collect()?;
    }

    let mut timings_us = Vec::with_capacity(cli.iterations);
    let mut phases = Vec::with_capacity(cli.iterations);
    let mut process_count = 0;
    let mut task_count = 0;
    let mut last_procs = Vec::new();

    for i in 0..cli.iterations {
        if cli.interval_ms > 0 {
            std::thread::sleep(Duration::from_millis(cli.interval_ms));
        }
        let start = Instant::now();
        let (sys, procs) = collector.collect()?;
        let elapsed = start.elapsed();

        process_count = procs.len();
        task_count = sys.total_tasks + sys.user_threads + sys.kernel_threads;
        timings_us.push(us(elapsed));
        phases.push(collector.last_timings);
        last_procs = procs;

        if !cli.json && (i + 1) % 10 == 0 {
            eprintln!(
                "  [{}/{}] {:.0} µs, {} processes",
                i + 1,
                cli.iterations,
                timings_us.last().unwrap(),
                process_count
            );
        }
    }

    if cli.dump {
        let clean = |s: &str| s.replace(|c: char| c.is_control(), " ");
        for p in &last_procs {
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{:.1}\t{}",
                p.pid,
                p.user,
                p.frozen as u8,
                p.net_tx_bytes,
                p.net_rx_bytes,
                p.net_ifname,
                p.cpu_percent,
                clean(&p.cmdline)
            );
        }
        return Ok(());
    }

    let result = BenchResult {
        iterations: cli.iterations,
        warmup: cli.warmup,
        process_count,
        task_count,
        net_probe_mode,
        stats: compute_stats(&timings_us),
        phases_median_us: median_phases(&phases),
        timings_us,
        system: get_system_meta(),
    };

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if !result.timings_us.is_empty() {
        let p = &result.phases_median_us;
        eprintln!("\n=== bpftop Benchmark Results ===");
        eprintln!("Iterations:    {}", result.iterations);
        eprintln!("Processes:     {}", result.process_count);
        eprintln!("Tasks:         {}", result.task_count);
        eprintln!("Net probes:    {}", result.net_probe_mode);
        eprintln!("Min:    {:.1} µs", result.stats.min_us);
        eprintln!("Median: {:.1} µs", result.stats.median_us);
        eprintln!("P95:    {:.1} µs", result.stats.p95_us);
        eprintln!("Max:    {:.1} µs", result.stats.max_us);
        eprintln!("Phases (median µs): system={:.0} cgroup_tick={:.0} bpf_iter={:.0} per_process={:.0} gpu={:.0} net={:.0} tree={:.0}",
            p.system_stats, p.cgroup_tick, p.bpf_iter, p.per_process, p.gpu, p.net, p.tree);
    }

    Ok(())
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000_000.0
}

fn median_phases(phases: &[CollectTimings]) -> Phases {
    if phases.is_empty() {
        return Phases::default();
    }
    let med = |f: fn(&CollectTimings) -> Duration| {
        let mut v: Vec<f64> = phases.iter().map(|t| us(f(t))).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    };
    Phases {
        system_stats: med(|t| t.system_stats),
        cgroup_tick: med(|t| t.cgroup_tick),
        bpf_iter: med(|t| t.bpf_iter),
        per_process: med(|t| t.per_process),
        gpu: med(|t| t.gpu),
        net: med(|t| t.net),
        tree: med(|t| t.tree),
    }
}

fn compute_stats(timings: &[f64]) -> Stats {
    if timings.is_empty() {
        return Stats { min_us: 0.0, max_us: 0.0, mean_us: 0.0, median_us: 0.0, p95_us: 0.0, p99_us: 0.0, stddev_us: 0.0 };
    }
    let mut sorted = timings.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let n = sorted.len() as f64;
    let sum: f64 = sorted.iter().sum();
    let mean = sum / n;

    let variance: f64 = sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let stddev = variance.sqrt();

    Stats {
        min_us: sorted[0],
        max_us: *sorted.last().unwrap(),
        mean_us: mean,
        median_us: percentile(&sorted, 50.0),
        p95_us: percentile(&sorted, 95.0),
        p99_us: percentile(&sorted, 99.0),
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

    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

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
