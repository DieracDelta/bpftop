use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Result;

use super::container::CgroupResolver;
#[cfg(feature = "gpu")]
use super::gpu::GpuCollector;
use super::process::{display_text, ProcessInfo, ProcessState, Text};
use super::system::*;
use crate::ebpf::loader::{self, EbpfLoader};

/// Wall time spent in each phase of the most recent `collect()`.
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub struct CollectTimings {
    pub system_stats: Duration,
    pub cgroup_tick: Duration,
    pub bpf_iter: Duration,
    pub per_process: Duration,
    pub gpu: Duration,
    pub net: Duration,
    pub tree: Duration,
}

/// How long resolved usernames are trusted before being looked up again.
const USERNAME_TTL: Duration = Duration::from_secs(60);

/// Orchestrates data collection from eBPF programs.
///
/// System-wide stats still come from /proc/stat, /proc/meminfo, etc.
/// All per-process data comes from the BPF task iterator, which also joins
/// in NET_STATS and the CMDLINE_MAP generation. No per-PID /proc reads
/// occur after startup, and in the steady state no per-PID syscalls at all:
/// a cmdline is fetched from CMDLINE_MAP only when its generation changes,
/// and usernames are cached per uid.
pub struct Collector {
    ebpf: EbpfLoader,
    system: Option<SystemReader>,
    cgroup_resolver: CgroupResolver,
    /// pid → (CMDLINE_MAP generation, cmdline)
    cmdline_cache: HashMap<u32, (u64, Text)>,
    /// uid → username (or the uid as a string if it has no passwd entry)
    username_cache: HashMap<u32, Text>,
    /// net_ifname values shared by most processes.
    no_ifname: Text,
    any_ifname: Text,
    username_cache_time: Instant,
    prev_cpu_total: CpuStats,
    prev_cpus: Vec<CpuStats>,
    prev_proc_times: HashMap<u32, u64>,
    prev_net_bytes: HashMap<u32, u64>,
    prev_net_time: Instant,
    ifindex_cache: HashMap<u32, Text>,
    page_size: u64,
    #[cfg(feature = "gpu")]
    gpu_collector: Option<GpuCollector>,
    #[allow(dead_code)]
    pub last_timings: CollectTimings,
}

impl Collector {
    pub fn new(mut ebpf: EbpfLoader) -> Self {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };

        // One-shot /proc/*/cmdline scan to seed the BPF map for
        // processes already running before tracepoints were attached.
        if ebpf.is_loaded() {
            loader::seed_cmdlines_from_proc(&mut ebpf);
        }

        let mut system = SystemReader::new()
            .inspect_err(|e| log::error!("system stats unavailable: {e:#}"))
            .ok();

        // Seed CPU stats so the first real collect() gets a meaningful
        // delta instead of computing against zero (which would show
        // all CPUs at ~100%).
        let (prev_cpu_total, prev_cpus) = system
            .as_mut()
            .and_then(|s| s.read_cpu_stats().ok())
            .unwrap_or_default();

        Self {
            ebpf,
            system,
            cgroup_resolver: CgroupResolver::new(),
            cmdline_cache: HashMap::new(),
            username_cache: HashMap::new(),
            username_cache_time: Instant::now(),
            no_ifname: Text::from(""),
            any_ifname: Text::from("*"),
            prev_cpu_total,
            prev_cpus,
            prev_proc_times: HashMap::new(),
            prev_net_bytes: HashMap::new(),
            prev_net_time: Instant::now(),
            ifindex_cache: HashMap::new(),
            page_size,
            #[cfg(feature = "gpu")]
            gpu_collector: GpuCollector::try_new(),
            last_timings: CollectTimings::default(),
        }
    }

    /// Create a no-op collector that will never be called.
    /// Used as a placeholder after extracting the real collector for the background thread.
    pub fn noop() -> Self {
        Self {
            ebpf: EbpfLoader::noop(),
            system: None,
            cgroup_resolver: CgroupResolver::empty(),
            cmdline_cache: HashMap::new(),
            username_cache: HashMap::new(),
            username_cache_time: Instant::now(),
            no_ifname: Text::from(""),
            any_ifname: Text::from("*"),
            prev_cpu_total: CpuStats::default(),
            prev_cpus: Vec::new(),
            prev_proc_times: HashMap::new(),
            prev_net_bytes: HashMap::new(),
            prev_net_time: Instant::now(),
            ifindex_cache: HashMap::new(),
            page_size: 4096,
            #[cfg(feature = "gpu")]
            gpu_collector: None,
            last_timings: CollectTimings::default(),
        }
    }

    /// Collect all system and process data for one refresh cycle.
    pub fn collect(&mut self) -> Result<(SystemInfo, Vec<ProcessInfo>)> {
        let mut timings = CollectTimings::default();
        let mut mark = Instant::now();
        let mut lap = |slot: &mut Duration| {
            let now = Instant::now();
            *slot = now - mark;
            mark = now;
        };

        // System-wide stats from /proc (unchanged — these are the kernel's
        // official API for aggregate stats)
        let system = self
            .system
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("system stats unavailable"))?;
        let (mut cpu_total, mut cpus) = system.read_cpu_stats()?;
        let (memory, swap) = system.read_memory_info()?;
        let load_avg = system.read_load_avg()?;
        let uptime = system.read_uptime()?;

        // Calculate CPU percentages from deltas
        cpu_total.calc_percentages(&self.prev_cpu_total);
        for (i, cpu) in cpus.iter_mut().enumerate() {
            if let Some(prev) = self.prev_cpus.get(i) {
                cpu.calc_percentages(prev);
            }
        }

        lap(&mut timings.system_stats);

        // Process data from BPF task iterator (replaces all /proc/{pid} reads)
        // If BPF isn't loaded or read fails, return empty process list
        // but still return valid system stats.
        let records = match self.ebpf.read_tasks() {
            Ok(records) => records,
            Err(e) => {
                log::debug!("BPF read_tasks failed: {e}");
                Default::default()
            }
        };
        let bpf_tasks = &records.tasks;
        // Network counters were sampled during the iterator walk.
        let net_now = Instant::now();
        let net_wall_delta_secs = net_now
            .duration_since(self.prev_net_time)
            .as_secs_f64()
            .max(0.1);
        lap(&mut timings.bpf_iter);

        // Re-walk cgroupfs only if some task is in a cgroup we haven't seen.
        self.cgroup_resolver
            .ensure_known(bpf_tasks.iter().map(|t| t.cgroup_id));
        lap(&mut timings.cgroup_tick);

        if self.username_cache_time.elapsed() >= USERNAME_TTL {
            self.username_cache.clear();
            self.username_cache_time = Instant::now();
        }
        let mut cmdline_cache = HashMap::with_capacity(self.cmdline_cache.len());
        let mut new_net_bytes = HashMap::new();

        // Classify tasks: processes, user threads, kernel threads. The
        // iterator emits only thread-group leaders, with their thread count.
        let mut task_count = 0u32;
        let mut user_threads = 0u32;
        let mut kernel_threads = 0u32;
        for task in bpf_tasks {
            let is_kthread = task.kthread != 0;
            if is_kthread {
                kernel_threads += task.nr_threads.max(1);
            } else {
                task_count += 1;
                user_threads += task.nr_threads.saturating_sub(1);
            }
        }

        let mut processes = Vec::with_capacity(bpf_tasks.len());
        let mut running = 0u32;
        let mut sleeping = 0u32;

        // Total CPU ticks delta for percentage calculation
        let total_sys_delta = cpu_total
            .total_ticks()
            .saturating_sub(self.prev_cpu_total.total_ticks());

        for task in bpf_tasks {
            let state = ProcessState::from_kernel_state(task.state);
            match state {
                ProcessState::Running => running += 1,
                ProcessState::Sleeping | ProcessState::Idle => sleeping += 1,
                _ => {}
            }

            // CPU time: BPF gives nanoseconds; convert to ticks equivalent for delta.
            // Whole thread group: leader + exited threads + live threads.
            let total_cpu_ns = task.utime_ns
                + task.stime_ns
                + records.thread_cpu_ns.get(&task.pid).copied().unwrap_or(0);
            let prev_cpu_ns = self
                .prev_proc_times
                .get(&task.pid)
                .copied()
                .unwrap_or(total_cpu_ns);
            let cpu_delta_ns = total_cpu_ns.saturating_sub(prev_cpu_ns);

            // Convert ns delta to fraction of total CPU time
            // total_sys_delta is in jiffies (clock ticks), so convert
            // cpu_delta_ns to jiffies: ns / (1e9 / CLK_TCK) = ns * CLK_TCK / 1e9
            // But it's simpler to keep everything relative:
            // cpu% = (delta_ns / delta_wall_ns) * 100
            // We approximate wall time delta from system ticks:
            // wall_ns ≈ total_sys_delta * (1e9 / CLK_TCK) / num_cpus
            let num_cpus = cpus.len().max(1) as f64;
            let cpu_percent = if total_sys_delta > 0 {
                // total_sys_delta is aggregate ticks across all cores.
                // Per-core wall time in ns = total_sys_delta / num_cpus * (1e9 / CLK_TCK)
                // cpu% (Irix mode, 0-100% per core) = delta_ns / wall_ns * 100
                let wall_delta_ns =
                    total_sys_delta as f64 * 1_000_000_000.0 / 100.0 / num_cpus;
                (cpu_delta_ns as f64 / wall_delta_ns) * 100.0
            } else {
                0.0
            };

            let res_bytes = task.rss_pages * self.page_size;
            let shr_bytes = task.shmem_pages * self.page_size;
            let mem_percent = if memory.total > 0 {
                res_bytes as f64 / memory.total as f64 * 100.0
            } else {
                0.0
            };

            let cpu_time_secs = total_cpu_ns as f64 / 1_000_000_000.0;

            let nice = task.static_prio - 120;
            let priority = task.prio - 100;

            let user = self
                .username_cache
                .entry(task.ruid)
                .or_insert_with(|| Text::from(resolve_username(task.ruid)))
                .clone();

            let is_kernel_thread = task.kthread != 0;

            // cmdline: prefer BPF CMDLINE_MAP, fall back to comm. Only hit
            // the map when the entry's generation differs from the cached one.
            let comm = Text::from(comm_to_string(&task.comm));
            let cached = self
                .cmdline_cache
                .remove(&task.pid)
                .filter(|(gen, _)| *gen == task.cmdline_gen);
            let fetched = match cached {
                Some(entry) => Some(entry),
                None if task.cmdline_gen != 0 => self
                    .ebpf
                    .get_cmdline(task.pid)
                    .map(|(gen, s)| (gen, Text::from(s))),
                None => None,
            };
            let cmdline = match fetched {
                Some((gen, cmdline)) => {
                    cmdline_cache.insert(task.pid, (gen, cmdline.clone()));
                    cmdline
                }
                None => Text::from(format!("[{}]", comm)),
            };

            // Container: resolve from cgroup_id
            let cgroup_path = self.cgroup_resolver.resolve_path(task.cgroup_id);
            let container = self.cgroup_resolver.resolve(task.cgroup_id);

            // Network: cumulative bytes from NET_STATS, joined in by the iterator
            let (mut net_rate, mut net_ifname) = (0.0, self.no_ifname.clone());
            let net_total = task.net_tx_bytes + task.net_rx_bytes;
            if net_total > 0 || task.net_ifindex > 0 {
                let prev_total = self.prev_net_bytes.get(&task.pid).copied().unwrap_or(net_total);
                net_rate = net_total.saturating_sub(prev_total) as f64 / net_wall_delta_secs;
                new_net_bytes.insert(task.pid, net_total);

                net_ifname = if task.net_ifindex > 0 {
                    let ifindex = task.net_ifindex;
                    self.ifindex_cache
                        .entry(ifindex)
                        .or_insert_with(|| {
                            nix::net::if_::if_indextoname(ifindex)
                                .map(|s| Text::from(s.to_string_lossy()))
                                .unwrap_or_else(|_| Text::from(format!("if{ifindex}")))
                        })
                        .clone()
                } else {
                    self.any_ifname.clone()
                };
            }

            processes.push(ProcessInfo {
                pid: task.pid,
                ppid: task.ppid,
                uid: task.ruid,
                user,
                state,
                priority,
                nice,
                virt_bytes: task.vsize_pages * self.page_size,
                res_bytes,
                shr_bytes,
                cpu_percent,
                mem_percent,
                gpu_percent: 0.0,
                gpu_mem_bytes: 0,
                net_rx_bytes: task.net_rx_bytes,
                net_tx_bytes: task.net_tx_bytes,
                net_rate,
                net_ifname,
                cpu_time_secs,
                start_time_ns: task.start_time_ns,
                comm,
                cmdline,
                container,
                service: None,
                cgroup_path,
                children: Vec::new(),
                prev_cpu_ns: total_cpu_ns,
                is_kernel_thread,
                is_thread: false,
                tid: task.pid,
                tagged: false,
                frozen: task.frozen != 0,
                tree_prefix: String::new(),
            });
        }

        self.cmdline_cache = cmdline_cache;
        lap(&mut timings.per_process);

        // GPU data
        let mut gpus = Vec::new();
        #[cfg(feature = "gpu")]
        if let Some(ref mut gc) = self.gpu_collector {
            let (gpu_devices, proc_gpu) = gc.collect();
            gpus = gpu_devices;
            for proc in &mut processes {
                if let Some(usage) = proc_gpu.get(&proc.pid) {
                    proc.gpu_percent = usage.gpu_percent;
                    proc.gpu_mem_bytes = usage.gpu_mem_bytes;
                }
            }
        }

        lap(&mut timings.gpu);

        lap(&mut timings.net);

        // Build parent-child relationships for tree view
        let pid_set: HashMap<u32, usize> = processes
            .iter()
            .enumerate()
            .map(|(i, p)| (p.pid, i))
            .collect();

        let child_map: Vec<(u32, u32)> = processes
            .iter()
            .filter(|p| p.ppid != 0 && p.ppid != p.pid)
            .map(|p| (p.ppid, p.pid))
            .collect();

        for (ppid, child_pid) in child_map {
            if let Some(&idx) = pid_set.get(&ppid) {
                processes[idx].children.push(child_pid);
            }
        }

        // Save current state for next delta calculation
        self.prev_cpu_total = cpu_total.clone();
        self.prev_cpus = cpus.clone();
        self.prev_proc_times = processes
            .iter()
            .map(|p| (p.pid, p.prev_cpu_ns))
            .collect();
        self.prev_net_bytes = new_net_bytes;
        self.prev_net_time = net_now;
        lap(&mut timings.tree);
        self.last_timings = timings;

        let sys_info = SystemInfo {
            cpu_total,
            cpus,
            memory,
            swap,
            load_avg,
            uptime_secs: uptime,
            total_tasks: task_count,
            user_threads,
            kernel_threads,
            running_tasks: running,
            sleeping_tasks: sleeping,
            gpus,
        };

        Ok((sys_info, processes))
    }

}

/// Convert a null-terminated comm byte array to a String.
fn comm_to_string(comm: &[u8; 16]) -> String {
    let nul = comm.iter().position(|&b| b == 0).unwrap_or(16);
    display_text(&comm[..nul])
}

fn resolve_username(uid: u32) -> String {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string())
}
