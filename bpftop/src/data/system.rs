use std::fs;
use anyhow::{Context, Result};

use super::gpu::GpuDeviceInfo;

/// System-wide information: CPU, memory, swap, load, uptime.
#[derive(Debug, Clone, Default)]
pub struct SystemInfo {
    #[allow(dead_code)]
    pub cpu_total: CpuStats,
    pub cpus: Vec<CpuStats>,
    pub memory: MemoryInfo,
    pub swap: SwapInfo,
    pub load_avg: [f64; 3],
    pub uptime_secs: f64,
    pub total_tasks: u32,
    pub user_threads: u32,
    pub kernel_threads: u32,
    pub running_tasks: u32,
    #[allow(dead_code)]
    pub sleeping_tasks: u32,
    pub gpus: Vec<GpuDeviceInfo>,
}

/// Per-CPU tick counters from /proc/stat.
#[derive(Debug, Clone, Default)]
pub struct CpuStats {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
    // Computed percentages (from delta)
    pub user_pct: f64,
    pub system_pct: f64,
    pub nice_pct: f64,
    pub iowait_pct: f64,
    pub idle_pct: f64,
    pub total_pct: f64,
}

impl CpuStats {
    pub fn total_ticks(&self) -> u64 {
        self.user + self.nice + self.system + self.idle + self.iowait + self.irq + self.softirq + self.steal
    }

    pub fn busy_ticks(&self) -> u64 {
        self.total_ticks() - self.idle - self.iowait
    }

    /// Calculate percentage deltas from a previous sample.
    pub fn calc_percentages(&mut self, prev: &CpuStats) {
        let total_delta = self.total_ticks().saturating_sub(prev.total_ticks());
        if total_delta == 0 {
            return;
        }
        let d = total_delta as f64;
        self.user_pct = (self.user.saturating_sub(prev.user)) as f64 / d * 100.0;
        self.nice_pct = (self.nice.saturating_sub(prev.nice)) as f64 / d * 100.0;
        self.system_pct = (self.system.saturating_sub(prev.system)) as f64 / d * 100.0;
        self.iowait_pct = (self.iowait.saturating_sub(prev.iowait)) as f64 / d * 100.0;
        self.idle_pct = (self.idle.saturating_sub(prev.idle)) as f64 / d * 100.0;
        self.total_pct = (self.busy_ticks().saturating_sub(prev.busy_ticks())) as f64 / d * 100.0;
    }
}

#[derive(Debug, Clone, Default)]
pub struct MemoryInfo {
    pub total: u64,
    pub free: u64,
    pub available: u64,
    pub buffers: u64,
    pub cached: u64,
    pub s_reclaimable: u64,
    pub used: u64,
    /// Live physical RAM backing zram (3rd field of mm_stat).
    pub zram_mem_used: u64,
}

impl MemoryInfo {
    #[allow(dead_code)]
    pub fn used_pct(&self) -> f64 {
        if self.total == 0 { 0.0 } else { self.used as f64 / self.total as f64 * 100.0 }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SwapInfo {
    pub total: u64,
    pub free: u64,
    pub used: u64,
    /// zram compression ratio (orig_data / compr_data); None if no zram or no data stored.
    pub zram_compression_ratio: Option<f64>,
}

impl SwapInfo {
    #[allow(dead_code)]
    pub fn used_pct(&self) -> f64 {
        if self.total == 0 { 0.0 } else { self.used as f64 / self.total as f64 * 100.0 }
    }
}

/// Read CPU stats from /proc/stat.
pub fn read_cpu_stats() -> Result<(CpuStats, Vec<CpuStats>)> {
    let content = fs::read_to_string("/proc/stat").context("reading /proc/stat")?;
    let mut total = CpuStats::default();
    let mut cpus = Vec::new();

    for line in content.lines() {
        if line.starts_with("cpu ") {
            total = parse_cpu_line(line);
        } else if line.starts_with("cpu") {
            cpus.push(parse_cpu_line(line));
        }
    }

    Ok((total, cpus))
}

fn parse_cpu_line(line: &str) -> CpuStats {
    let parts: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|s| s.parse().ok())
        .collect();

    CpuStats {
        user: parts.first().copied().unwrap_or(0),
        nice: parts.get(1).copied().unwrap_or(0),
        system: parts.get(2).copied().unwrap_or(0),
        idle: parts.get(3).copied().unwrap_or(0),
        iowait: parts.get(4).copied().unwrap_or(0),
        irq: parts.get(5).copied().unwrap_or(0),
        softirq: parts.get(6).copied().unwrap_or(0),
        steal: parts.get(7).copied().unwrap_or(0),
        ..Default::default()
    }
}

/// Read memory info from /proc/meminfo.
pub fn read_memory_info() -> Result<(MemoryInfo, SwapInfo)> {
    let content = fs::read_to_string("/proc/meminfo").context("reading /proc/meminfo")?;

    let mut mem = MemoryInfo::default();
    let mut swap = SwapInfo::default();

    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let key = match parts.next() {
            Some(k) => k.trim_end_matches(':'),
            None => continue,
        };
        let val: u64 = match parts.next().and_then(|v| v.parse::<u64>().ok()) {
            Some(v) => v * 1024, // Convert from kB to bytes
            None => continue,
        };

        match key {
            "MemTotal" => mem.total = val,
            "MemFree" => mem.free = val,
            "MemAvailable" => mem.available = val,
            "Buffers" => mem.buffers = val,
            "Cached" => mem.cached = val,
            "SReclaimable" => mem.s_reclaimable = val,
            "SwapTotal" => swap.total = val,
            "SwapFree" => swap.free = val,
            _ => {}
        }
    }

    mem.used = mem.total.saturating_sub(mem.free + mem.buffers + mem.cached + mem.s_reclaimable);
    let (zram_mem_used, zram_ratio) = read_zram_stats();
    mem.zram_mem_used = zram_mem_used;
    swap.used = swap.total.saturating_sub(swap.free);
    swap.zram_compression_ratio = zram_ratio;

    Ok((mem, swap))
}

/// Read zram stats from /sys/block/zram*/mm_stat.
/// Returns (total_mem_used, compression_ratio).
/// mm_stat fields: orig_data_size compr_data_size mem_used_total ...
fn read_zram_stats() -> (u64, Option<f64>) {
    let Ok(entries) = fs::read_dir("/sys/block") else { return (0, None) };
    let mut total_mem_used = 0u64;
    let mut total_orig = 0u64;
    let mut total_compr = 0u64;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("zram") { continue; }
        if let Ok(content) = fs::read_to_string(entry.path().join("mm_stat")) {
            let fields: Vec<u64> = content
                .split_whitespace()
                .take(3)
                .filter_map(|s| s.parse().ok())
                .collect();
            if fields.len() >= 3 {
                total_orig += fields[0];
                total_compr += fields[1];
                total_mem_used += fields[2];
            }
        }
    }
    let ratio = if total_compr > 0 {
        Some(total_orig as f64 / total_compr as f64)
    } else {
        None
    };
    (total_mem_used, ratio)
}

/// Read load averages from /proc/loadavg.
pub fn read_load_avg() -> Result<[f64; 3]> {
    let content = fs::read_to_string("/proc/loadavg").context("reading /proc/loadavg")?;
    let parts: Vec<&str> = content.split_whitespace().collect();
    let load1 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let load5 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let load15 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    Ok([load1, load5, load15])
}

/// Read system uptime from /proc/uptime.
pub fn read_uptime() -> Result<f64> {
    let content = fs::read_to_string("/proc/uptime").context("reading /proc/uptime")?;
    let uptime: f64 = content
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    Ok(uptime)
}

/// Format uptime as Xd HH:MM:SS.
pub fn format_uptime(secs: f64) -> String {
    let total = secs as u64;
    let days = total / 86400;
    let hours = (total % 86400) / 3600;
    let mins = (total % 3600) / 60;
    let s = total % 60;
    if days > 0 {
        format!("{days}d {hours:02}:{mins:02}:{s:02}")
    } else {
        format!("{hours:02}:{mins:02}:{s:02}")
    }
}
