use std::fs::{self, File};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::cpuset::{CpuSet, Partition};
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
    /// CPUs reserved by cpuset partitions or isolcpus.
    pub reserved_cpus: CpuSet,
    /// The partitions reserving them.
    pub partitions: Vec<Partition>,
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

/// A stat file kept open across refreshes and re-read with pread from
/// offset 0: one syscall per refresh instead of open/statx/read/read/close.
pub(crate) struct StatFile {
    file: File,
    buf: Vec<u8>,
}

impl StatFile {
    pub(crate) fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            file: File::open(path)?,
            buf: vec![0; 4096],
        })
    }

    /// These are all single-show seq_files, which return their whole
    /// content in one read when the buffer is large enough, so a short
    /// read means EOF.
    pub(crate) fn read(&mut self) -> io::Result<&str> {
        let mut len = 0;
        loop {
            if len == self.buf.len() {
                self.buf.resize(self.buf.len() * 2, 0);
            }
            let want = self.buf.len() - len;
            match self.file.read_at(&mut self.buf[len..], len as u64) {
                Ok(n) => {
                    len += n;
                    if n < want {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        std::str::from_utf8(&self.buf[..len])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// How often to rescan /sys/block for zram devices.
const ZRAM_RESCAN: Duration = Duration::from_secs(60);

/// Reads system-wide stats from /proc and zram sysfs, holding the files open.
pub struct SystemReader {
    stat: StatFile,
    meminfo: StatFile,
    loadavg: StatFile,
    uptime: StatFile,
    zram: Vec<StatFile>,
    zram_scanned: Option<Instant>,
}

impl SystemReader {
    pub fn new() -> Result<Self> {
        let open = |p: &str| StatFile::open(p).with_context(|| format!("opening {p}"));
        Ok(Self {
            stat: open("/proc/stat")?,
            meminfo: open("/proc/meminfo")?,
            loadavg: open("/proc/loadavg")?,
            uptime: open("/proc/uptime")?,
            zram: Vec::new(),
            zram_scanned: None,
        })
    }

    pub fn read_cpu_stats(&mut self) -> Result<(CpuStats, Vec<CpuStats>)> {
        Ok(parse_cpu_stats(self.stat.read().context("reading /proc/stat")?))
    }

    pub fn read_memory_info(&mut self) -> Result<(MemoryInfo, SwapInfo)> {
        let (mut mem, mut swap) =
            parse_memory_info(self.meminfo.read().context("reading /proc/meminfo")?);
        let (zram_mem_used, zram_ratio) = self.read_zram_stats();
        mem.zram_mem_used = zram_mem_used;
        swap.zram_compression_ratio = zram_ratio;
        Ok((mem, swap))
    }

    pub fn read_load_avg(&mut self) -> Result<[f64; 3]> {
        Ok(parse_load_avg(self.loadavg.read().context("reading /proc/loadavg")?))
    }

    pub fn read_uptime(&mut self) -> Result<f64> {
        Ok(parse_uptime(self.uptime.read().context("reading /proc/uptime")?))
    }

    /// Sum zram stats from /sys/block/zram*/mm_stat.
    /// Returns (total_mem_used, compression_ratio).
    /// mm_stat fields: orig_data_size compr_data_size mem_used_total ...
    fn read_zram_stats(&mut self) -> (u64, Option<f64>) {
        if self.zram_scanned.is_none_or(|t| t.elapsed() >= ZRAM_RESCAN) {
            self.zram = scan_zram_devices();
            self.zram_scanned = Some(Instant::now());
        }
        let mut total_mem_used = 0u64;
        let mut total_orig = 0u64;
        let mut total_compr = 0u64;
        let mut failed = false;
        for dev in &mut self.zram {
            let Ok(content) = dev.read() else {
                failed = true;
                continue;
            };
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
        if failed {
            // A device went away; rescan next cycle.
            self.zram_scanned = None;
        }
        let ratio = if total_compr > 0 {
            Some(total_orig as f64 / total_compr as f64)
        } else {
            None
        };
        (total_mem_used, ratio)
    }
}

fn scan_zram_devices() -> Vec<StatFile> {
    let Ok(entries) = fs::read_dir("/sys/block") else { return Vec::new() };
    entries
        .flatten()
        .filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with("zram")))
        .filter_map(|e| StatFile::open(e.path().join("mm_stat")).ok())
        .collect()
}

fn parse_cpu_stats(content: &str) -> (CpuStats, Vec<CpuStats>) {
    let mut total = CpuStats::default();
    let mut cpus = Vec::new();

    for line in content.lines() {
        if line.starts_with("cpu ") {
            total = parse_cpu_line(line);
        } else if line.starts_with("cpu") {
            cpus.push(parse_cpu_line(line));
        }
    }

    (total, cpus)
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

fn parse_memory_info(content: &str) -> (MemoryInfo, SwapInfo) {
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
    swap.used = swap.total.saturating_sub(swap.free);

    (mem, swap)
}

fn parse_load_avg(content: &str) -> [f64; 3] {
    let parts: Vec<&str> = content.split_whitespace().collect();
    let load1 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let load5 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let load15 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    [load1, load5, load15]
}

fn parse_uptime(content: &str) -> f64 {
    content
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0)
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
