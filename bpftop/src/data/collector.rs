use std::collections::HashMap;

use anyhow::Result;

use super::container::CgroupResolver;
#[cfg(feature = "gpu")]
use super::gpu::GpuCollector;
use super::process::{ProcessInfo, ProcessState};
use super::system::*;
use crate::ebpf::loader::{self, EbpfLoader};

/// Orchestrates data collection from eBPF programs.
///
/// System-wide stats still come from /proc/stat, /proc/meminfo, etc.
/// All per-process data comes from the BPF task iterator and CMDLINE_MAP.
/// No per-PID /proc reads occur after startup.
pub struct Collector {
    ebpf: EbpfLoader,
    cgroup_resolver: CgroupResolver,
    prev_cpu_total: CpuStats,
    prev_cpus: Vec<CpuStats>,
    prev_proc_times: HashMap<u32, u64>,
    page_size: u64,
    #[cfg(feature = "gpu")]
    gpu_collector: Option<GpuCollector>,
}

impl Collector {
    pub fn new(mut ebpf: EbpfLoader) -> Self {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };

        // One-shot /proc/*/cmdline scan to seed the BPF map for
        // processes already running before tracepoints were attached.
        loader::seed_cmdlines_from_proc(&mut ebpf);

        // Seed CPU stats so the first real collect() gets a meaningful
        // delta instead of computing against zero (which would show
        // all CPUs at ~100%).
        let (prev_cpu_total, prev_cpus) = read_cpu_stats().unwrap_or_default();

        Self {
            ebpf,
            cgroup_resolver: CgroupResolver::new(),
            prev_cpu_total,
            prev_cpus,
            prev_proc_times: HashMap::new(),
            page_size,
            #[cfg(feature = "gpu")]
            gpu_collector: GpuCollector::try_new(),
        }
    }

    /// Create a no-op collector that will never be called.
    /// Used as a placeholder after extracting the real collector for the background thread.
    pub fn noop() -> Self {
        Self {
            ebpf: EbpfLoader::noop(),
            cgroup_resolver: CgroupResolver::new(),
            prev_cpu_total: CpuStats::default(),
            prev_cpus: Vec::new(),
            prev_proc_times: HashMap::new(),
            page_size: 4096,
            #[cfg(feature = "gpu")]
            gpu_collector: None,
        }
    }

    /// Collect all system and process data for one refresh cycle.
    pub fn collect(&mut self) -> Result<(SystemInfo, Vec<ProcessInfo>)> {
        // System-wide stats from /proc (unchanged — these are the kernel's
        // official API for aggregate stats)
        let (mut cpu_total, mut cpus) = read_cpu_stats()?;
        let (memory, swap) = read_memory_info()?;
        let load_avg = read_load_avg()?;
        let uptime = read_uptime()?;

        // Calculate CPU percentages from deltas
        cpu_total.calc_percentages(&self.prev_cpu_total);
        for (i, cpu) in cpus.iter_mut().enumerate() {
            if let Some(prev) = self.prev_cpus.get(i) {
                cpu.calc_percentages(prev);
            }
        }

        // Refresh cgroup inode map periodically (once per cycle, not per-process)
        self.cgroup_resolver.tick();

        // Process data from BPF task iterator (replaces all /proc/{pid} reads)
        // If BPF isn't loaded or read fails, return empty process list
        // but still return valid system stats.
        let bpf_tasks = match self.ebpf.read_tasks() {
            Ok(tasks) => tasks,
            Err(e) => {
                log::debug!("BPF read_tasks failed: {e}");
                Vec::new()
            }
        };

        // Classify tasks: processes, user threads, kernel threads
        let mut task_count = 0u32;
        let mut user_threads = 0u32;
        let mut kernel_threads = 0u32;
        for task in &bpf_tasks {
            let is_kthread = task.ppid == 2 || task.pid == 2;
            if is_kthread {
                kernel_threads += 1;
            } else if task.tid != task.pid {
                user_threads += 1;
            } else {
                task_count += 1;
            }
        }

        let mut processes = Vec::with_capacity(bpf_tasks.len());
        let mut running = 0u32;
        let mut sleeping = 0u32;

        // Total CPU ticks delta for percentage calculation
        let total_sys_delta = cpu_total
            .total_ticks()
            .saturating_sub(self.prev_cpu_total.total_ticks());

        for task in &bpf_tasks {
            // Skip kernel threads with tid != tgid (they're threads, not processes)
            // But keep the thread group leader
            if task.tid != task.pid {
                continue;
            }

            let state = ProcessState::from_kernel_state(task.state);
            match state {
                ProcessState::Running => running += 1,
                ProcessState::Sleeping | ProcessState::Idle => sleeping += 1,
                _ => {}
            }

            // CPU time: BPF gives nanoseconds; convert to ticks equivalent for delta
            let total_cpu_ns = task.utime_ns + task.stime_ns;
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

            let user = resolve_username(task.ruid);

            let is_kernel_thread = task.ppid == 2 || task.pid == 2;

            // cmdline: prefer BPF CMDLINE_MAP, fall back to comm
            let comm = comm_to_string(&task.comm);
            let cmdline = self
                .ebpf
                .get_cmdline(task.pid)
                .unwrap_or_else(|| format!("[{}]", comm));

            // Container: resolve from cgroup_id
            let cgroup_path = self.cgroup_resolver.resolve_path(task.cgroup_id);
            let container = self.cgroup_resolver.resolve(task.cgroup_id);

            processes.push(ProcessInfo {
                pid: task.pid,
                ppid: task.ppid,
                uid: task.ruid,
                user,
                state,
                priority,
                nice,
                virt_bytes: task.vsize_bytes,
                res_bytes,
                shr_bytes,
                cpu_percent,
                mem_percent,
                gpu_percent: 0.0,
                gpu_mem_bytes: 0,
                cpu_time_secs,
                start_time_ns: task.start_time_ns,
                comm,
                cmdline,
                container: container.map(|c| c.name),
                service: None,
                cgroup_path,
                children: Vec::new(),
                prev_cpu_ns: total_cpu_ns,
                is_kernel_thread,
                is_thread: false,
                tid: task.pid,
                tagged: false,
                tree_prefix: String::new(),
            });
        }

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
    String::from_utf8_lossy(&comm[..nul]).to_string()
}

fn resolve_username(uid: u32) -> String {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string())
}
