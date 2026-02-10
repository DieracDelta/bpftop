use std::collections::HashMap;

use anyhow::Result;

use super::container::ContainerResolver;
use super::process::{ProcessInfo, ProcessState};
use super::system::*;
use crate::ebpf::loader::{self, EbpfLoader};

/// Orchestrates data collection from eBPF and /proc.
pub struct Collector {
    ebpf: EbpfLoader,
    container_resolver: ContainerResolver,
    prev_cpu_total: CpuStats,
    prev_cpus: Vec<CpuStats>,
    prev_proc_times: HashMap<u32, u64>,
    page_size: u64,
    clock_ticks: u64,
}

impl Collector {
    pub fn new() -> Self {
        // Try loading eBPF, fall back to /proc-only mode
        let ebpf = match EbpfLoader::load() {
            Ok(loader) => {
                log::info!("eBPF programs loaded successfully");
                loader
            }
            Err(e) => {
                log::warn!("eBPF not available, falling back to /proc: {e}");
                EbpfLoader::noop()
            }
        };

        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
        let clock_ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) as u64 };

        Self {
            ebpf,
            container_resolver: ContainerResolver::new(),
            prev_cpu_total: CpuStats::default(),
            prev_cpus: Vec::new(),
            prev_proc_times: HashMap::new(),
            page_size,
            clock_ticks,
        }
    }

    /// Collect all system and process data for one refresh cycle.
    pub fn collect(&mut self) -> Result<(SystemInfo, Vec<ProcessInfo>)> {
        // Collect system-wide stats
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

        // Collect process data from /proc (primary) + eBPF (supplemental)
        let proc_tasks = loader::read_proc_tasks()?;

        let mut processes = Vec::with_capacity(proc_tasks.len());
        let mut running = 0u32;
        let mut sleeping = 0u32;
        let total = proc_tasks.len() as u32;

        for (pid, task) in &proc_tasks {
            let state = ProcessState::from_proc_stat(task.state);
            match state {
                ProcessState::Running => running += 1,
                ProcessState::Sleeping | ProcessState::Idle => sleeping += 1,
                _ => {}
            }

            let total_cpu_ns = task.utime_ticks + task.stime_ticks;
            let prev_cpu_ns = self.prev_proc_times.get(pid).copied().unwrap_or(total_cpu_ns);
            let cpu_delta = total_cpu_ns.saturating_sub(prev_cpu_ns);

            // CPU% = (delta ticks / total system delta ticks) * 100 * num_cpus
            let total_sys_delta = cpu_total.total_ticks().saturating_sub(self.prev_cpu_total.total_ticks());
            let cpu_percent = if total_sys_delta > 0 {
                (cpu_delta as f64 / total_sys_delta as f64) * 100.0 * cpus.len().max(1) as f64
            } else {
                0.0
            };

            let res_bytes = task.rss_pages * self.page_size;
            let shr_pages = loader::read_shared_pages(*pid);
            let shr_bytes = shr_pages * self.page_size;
            let mem_percent = if memory.total > 0 {
                res_bytes as f64 / memory.total as f64 * 100.0
            } else {
                0.0
            };

            let cpu_time_secs = (task.utime_ticks + task.stime_ticks) as f64 / self.clock_ticks as f64;

            let user = resolve_username(task.uid);

            let is_kernel_thread = task.ppid == 2 || *pid == 2;
            let container = self.container_resolver.resolve(*pid);

            processes.push(ProcessInfo {
                pid: *pid,
                ppid: task.ppid,
                uid: task.uid,
                user,
                state,
                priority: task.priority,
                nice: task.nice,
                virt_bytes: task.vsize,
                res_bytes,
                shr_bytes,
                cpu_percent,
                mem_percent,
                cpu_time_secs,
                start_time_ns: task.start_time_ticks,
                comm: task.comm.clone(),
                cmdline: if task.cmdline.is_empty() {
                    format!("[{}]", task.comm)
                } else {
                    task.cmdline.clone()
                },
                container: container.map(|c| c.name),
                cgroup_path: task.cgroup_path.clone(),
                children: Vec::new(),
                prev_cpu_ns: total_cpu_ns,
                is_kernel_thread,
                is_thread: false,
                tid: *pid,
                tagged: false,
            });
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
            total_tasks: total,
            running_tasks: running,
            sleeping_tasks: sleeping,
        };

        Ok((sys_info, processes))
    }

    pub fn ebpf_loaded(&self) -> bool {
        self.ebpf.is_loaded()
    }
}

fn resolve_username(uid: u32) -> String {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string())
}
