use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;

use super::container::CgroupResolver;
use super::cpuset::{CpuSet, ReservedCpus};
#[cfg(feature = "gpu")]
use super::gpu::GpuCollector;
use super::process::{display_text, ProcessInfo, ProcessState, Text};
use super::system::*;
use crate::ebpf::loader::{self, EbpfLoader};
use bpftop_common::{CpuPlacement, IoCounters};

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
    reserved: ReservedCpus,
    /// The online CPUs, read when the reserved CPUs change.
    online: CpuSet,
    /// placement mask → AFFINITY text (few distinct masks exist).
    affinity_cache: HashMap<[u64; 4], Text>,
    /// pid → (start time, comm, cmdline) read from /proc for processes
    /// that exec'd where the exec hook is skipped (no CMDLINE_MAP entry).
    proc_cmdlines: HashMap<u32, (u64, Text, Text)>,
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
    /// pid (tid for thread rows) → I/O counters at the previous refresh
    prev_io: HashMap<u32, IoCounters>,
    prev_net_time: Instant,
    ifindex_cache: HashMap<u32, Text>,
    page_size: u64,
    #[cfg(feature = "gpu")]
    gpu_collector: Option<GpuCollector>,
    #[allow(dead_code)]
    pub last_timings: CollectTimings,
    /// Set by the UI while threads are shown; thread rows are only built then.
    show_threads: Arc<AtomicBool>,
}

impl Collector {
    pub fn new(mut ebpf: EbpfLoader) -> Self {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };

        // One-shot /proc/*/cmdline scan to seed the BPF map for
        // processes already running before tracepoints were attached.
        // The full strings prime the cmdline cache, so the first refresh
        // needs no CMDLINE_MAP lookups for these processes.
        let mut cmdline_cache = HashMap::new();
        if ebpf.is_loaded() {
            for (pid, cmdline) in loader::seed_cmdlines_from_proc(&mut ebpf) {
                cmdline_cache.insert(pid, (loader::SEEDED_GEN, Text::from(cmdline)));
            }
        }

        // Turn the hooks off on reserved CPUs before anything runs there.
        let mut reserved = ReservedCpus::new();
        let mut online = CpuSet::default();
        sync_reserved(&mut reserved, &mut online, &mut ebpf);

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
            reserved,
            online,
            affinity_cache: HashMap::new(),
            proc_cmdlines: HashMap::new(),
            cmdline_cache,
            username_cache: HashMap::new(),
            username_cache_time: Instant::now(),
            no_ifname: Text::from(""),
            any_ifname: Text::from("*"),
            prev_cpu_total,
            prev_cpus,
            prev_proc_times: HashMap::new(),
            prev_net_bytes: HashMap::new(),
            prev_io: HashMap::new(),
            prev_net_time: Instant::now(),
            ifindex_cache: HashMap::new(),
            page_size,
            #[cfg(feature = "gpu")]
            gpu_collector: GpuCollector::try_new(),
            last_timings: CollectTimings::default(),
            show_threads: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a no-op collector that will never be called.
    /// Used as a placeholder after extracting the real collector for the background thread.
    pub fn noop() -> Self {
        Self {
            ebpf: EbpfLoader::noop(),
            system: None,
            cgroup_resolver: CgroupResolver::empty(),
            reserved: ReservedCpus::new(),
            online: CpuSet::default(),
            affinity_cache: HashMap::new(),
            proc_cmdlines: HashMap::new(),
            cmdline_cache: HashMap::new(),
            username_cache: HashMap::new(),
            username_cache_time: Instant::now(),
            no_ifname: Text::from(""),
            any_ifname: Text::from("*"),
            prev_cpu_total: CpuStats::default(),
            prev_cpus: Vec::new(),
            prev_proc_times: HashMap::new(),
            prev_net_bytes: HashMap::new(),
            prev_io: HashMap::new(),
            prev_net_time: Instant::now(),
            ifindex_cache: HashMap::new(),
            page_size: 4096,
            #[cfg(feature = "gpu")]
            gpu_collector: None,
            last_timings: CollectTimings::default(),
            show_threads: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Shared switch for building per-thread rows (off by default).
    pub fn show_threads_flag(&self) -> Arc<AtomicBool> {
        self.show_threads.clone()
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
        if sync_reserved(&mut self.reserved, &mut self.online, &mut self.ebpf) {
            // "all" depends on the online CPUs.
            self.affinity_cache.clear();
        }
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
        // Network and I/O counters were sampled during the iterator walk.
        let net_now = Instant::now();
        let wall_delta_secs = net_now
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
        let mut proc_cmdlines = HashMap::new();
        let mut new_net_bytes = HashMap::new();
        let mut new_io = HashMap::with_capacity(self.prev_io.len());

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
        // cpu% (Irix mode, 0-100% per core) = delta_ns / per-core wall ns * 100.
        // total_sys_delta is aggregate USER_HZ (100) ticks across all cores, so
        // per-core wall time in ns = total_sys_delta / num_cpus * (1e9 / 100).
        let num_cpus = cpus.len().max(1) as f64;
        let wall_delta_ns = total_sys_delta as f64 * 1_000_000_000.0 / 100.0 / num_cpus;
        let cpu_percent_of = |delta_ns: u64| {
            if wall_delta_ns > 0.0 {
                delta_ns as f64 / wall_delta_ns * 100.0
            } else {
                0.0
            }
        };

        for task in bpf_tasks {
            let state = ProcessState::from_kernel_state(task.state);
            match state {
                ProcessState::Running => running += 1,
                ProcessState::Sleeping | ProcessState::Idle => sleeping += 1,
                _ => {}
            }

            // CPU time: BPF gives nanoseconds; convert to ticks equivalent for delta.
            // Whole thread group: leader + exited threads + live threads.
            let total_cpu_ns = task.cpu_ns
                + records.thread_cpu_ns.get(&task.pid).copied().unwrap_or(0);
            let prev_cpu_ns = self
                .prev_proc_times
                .get(&task.pid)
                .copied()
                .unwrap_or(total_cpu_ns);
            let cpu_percent = cpu_percent_of(total_cpu_ns.saturating_sub(prev_cpu_ns));

            let res_bytes = task.rss_pages * self.page_size;
            let shr_bytes = task.shared_pages * self.page_size;
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

            let comm = Text::from(comm_to_string(&task.comm));
            let last_cpu = task.placement.last_cpu();
            // The exec hook skips reserved CPUs, so CMDLINE_MAP misses (or
            // has a stale entry for) processes that exec'd there. For those,
            // read /proc instead: once, and again when the comm changes (as
            // an exec usually changes it) or the PID is reused.
            let on_reserved_cpu = !is_kernel_thread
                && last_cpu.is_some_and(|cpu| self.reserved.cpus().contains(cpu as usize));
            let cmdline = if on_reserved_cpu {
                let cached = self
                    .proc_cmdlines
                    .remove(&task.pid)
                    .filter(|(start, c, _)| *start == task.start_time_ns && *c == comm);
                let entry = cached.or_else(|| {
                    let cmdline = loader::read_proc_cmdline(task.pid)?;
                    Some((task.start_time_ns, comm.clone(), Text::from(cmdline)))
                });
                match entry {
                    Some(entry) => {
                        let cmdline = entry.2.clone();
                        proc_cmdlines.insert(task.pid, entry);
                        cmdline
                    }
                    None => Text::from(format!("[{}]", comm)),
                }
            } else {
                // Prefer BPF CMDLINE_MAP, fall back to comm. Only hit the
                // map when the entry's generation differs from the cached one.
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
                match fetched {
                    Some((gen, cmdline)) => {
                        cmdline_cache.insert(task.pid, (gen, cmdline.clone()));
                        cmdline
                    }
                    None => Text::from(format!("[{}]", comm)),
                }
            };
            let affinity = self.affinity_text(&task.placement);

            // Container: resolve from cgroup_id
            let cgroup_path = self.cgroup_resolver.resolve_path(task.cgroup_id);
            let container = self.cgroup_resolver.resolve(task.cgroup_id);

            // Network: cumulative bytes from NET_STATS, joined in by the iterator
            // Disk I/O: leader + exited threads (task.io) + live threads
            let mut io = task.io;
            if let Some(threads) = records.thread_io.get(&task.pid) {
                io += *threads;
            }
            let io_rates = IoRates::between(self.prev_io.get(&task.pid), &io, wall_delta_secs);
            new_io.insert(task.pid, io);

            let (mut net_rate, mut net_ifname) = (0.0, self.no_ifname.clone());
            let net_total = task.net_tx_bytes + task.net_rx_bytes;
            if net_total > 0 || task.net_ifindex > 0 {
                let prev_total = self.prev_net_bytes.get(&task.pid).copied().unwrap_or(net_total);
                net_rate = net_total.saturating_sub(prev_total) as f64 / wall_delta_secs;
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
                io_read_rate: io_rates.read,
                io_write_rate: io_rates.write,
                iops: io_rates.ops,
                cpu_time_secs,
                last_cpu,
                affinity,
                nr_cpus_allowed: task.placement.nr_cpus_allowed,
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
        self.proc_cmdlines = proc_cmdlines;

        // Thread rows, while the UI shows threads. A thread shares its
        // process's user, memory, cgroup and cmdline (like htop); only
        // identity, state, name and CPU are its own. pid = tid keeps rows
        // unique; ppid = the process nests threads under it in tree view.
        if self.show_threads.load(Ordering::Relaxed) {
            let leader_idx: HashMap<u32, usize> =
                processes.iter().enumerate().map(|(i, p)| (p.pid, i)).collect();
            let mut thread_rows = Vec::with_capacity(records.threads.len());
            for t in &records.threads {
                let Some(&i) = leader_idx.get(&t.pid) else { continue };
                let prev = self.prev_proc_times.get(&t.tid).copied().unwrap_or(t.cpu_ns);
                let mut row = processes[i].clone();
                row.pid = t.tid;
                row.ppid = t.pid;
                row.tid = t.tid;
                row.is_thread = true;
                row.state = ProcessState::from_kernel_state(t.state);
                row.comm = Text::from(comm_to_string(&t.comm));
                row.cpu_percent = cpu_percent_of(t.cpu_ns.saturating_sub(prev));
                row.cpu_time_secs = t.cpu_ns as f64 / 1_000_000_000.0;
                row.last_cpu = t.placement.last_cpu();
                row.affinity = self.affinity_text(&t.placement);
                row.nr_cpus_allowed = t.placement.nr_cpus_allowed;
                row.prev_cpu_ns = t.cpu_ns;
                row.net_rx_bytes = 0;
                row.net_tx_bytes = 0;
                row.net_rate = 0.0;
                row.net_ifname = self.no_ifname.clone();
                let io_rates = IoRates::between(self.prev_io.get(&t.tid), &t.io, wall_delta_secs);
                row.io_read_rate = io_rates.read;
                row.io_write_rate = io_rates.write;
                row.iops = io_rates.ops;
                new_io.insert(t.tid, t.io);
                thread_rows.push(row);
            }
            processes.extend(thread_rows);
        }
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
            .filter(|p| p.ppid != 0 && p.ppid != p.pid && !p.is_thread)
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
        self.prev_io = new_io;
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
            reserved_cpus: self.reserved.cpus().clone(),
            partitions: self.reserved.partitions().to_vec(),
        };

        Ok((sys_info, processes))
    }

}

impl Collector {
    /// The AFFINITY text for a placement: "all" when it allows every
    /// online CPU, else its CPU list. Only online CPUs are listed: the
    /// kernel leaves the mask's bits past the possible CPUs unspecified.
    fn affinity_text(&mut self, placement: &CpuPlacement) -> Text {
        let online = &self.online;
        self.affinity_cache
            .entry(placement.cpus_allowed)
            .or_insert_with(|| {
                let mut allowed = CpuSet::from_words(&placement.cpus_allowed);
                if !online.is_empty() {
                    allowed = allowed.intersection(online);
                }
                if !online.is_empty() && allowed == *online {
                    Text::from("all")
                } else {
                    Text::from(allowed.to_string())
                }
            })
            .clone()
    }
}

/// Re-read the reserved CPUs; when they changed, tell the BPF hooks and
/// re-read the online CPUs. Returns whether they changed.
fn sync_reserved(reserved: &mut ReservedCpus, online: &mut CpuSet, ebpf: &mut EbpfLoader) -> bool {
    if !reserved.refresh() && !online.is_empty() {
        return false;
    }
    *online = std::fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|s| CpuSet::parse(&s))
        .unwrap_or_default();
    if ebpf.is_loaded() {
        if let Err(e) = ebpf.set_skip_cpus(reserved.cpus()) {
            log::warn!("could not update the CPUs the BPF hooks skip: {e:#}");
        }
    }
    true
}

/// Per-second I/O rates between two samples of one task's counters.
struct IoRates {
    read: f64,
    write: f64,
    ops: f64,
}

impl IoRates {
    /// First sample for a task (no `prev`) reports zero rates.
    fn between(prev: Option<&IoCounters>, cur: &IoCounters, secs: f64) -> Self {
        let Some(prev) = prev else {
            return Self { read: 0.0, write: 0.0, ops: 0.0 };
        };
        let rate = |now: u64, before: u64| now.saturating_sub(before) as f64 / secs;
        Self {
            read: rate(cur.read_bytes, prev.read_bytes),
            write: rate(cur.write_bytes, prev.write_bytes),
            ops: rate(cur.syscr + cur.syscw, prev.syscr + prev.syscw),
        }
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
