use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// Manages eBPF program loading.
///
/// Note: BPF iterators (iter/task, iter/task_file) are not yet supported
/// in aya 0.13. The eBPF programs are compiled and ready but will be
/// activated when aya adds iterator support. Until then, we use /proc
/// as the primary data source.
pub struct EbpfLoader {
    loaded: bool,
}

impl EbpfLoader {
    /// Try to load eBPF programs.
    ///
    /// Currently a no-op since aya 0.13 doesn't support BPF iterators.
    /// Returns a loader that reports as not loaded, falling back to /proc.
    pub fn load() -> Result<Self> {
        // BPF iterators require aya support for iter/task program type.
        // Once available, this will:
        // 1. Load the compiled eBPF binary
        // 2. Attach the dump_task iterator
        // 3. Read binary TaskInfo structs from the iterator output
        Ok(Self { loaded: false })
    }

    /// Create a no-op loader for when eBPF is not available.
    pub fn noop() -> Self {
        Self { loaded: false }
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }
}

/// Read process info from /proc filesystem. This is the primary data
/// source until BPF iterator support is available in aya.
pub fn read_proc_tasks() -> Result<HashMap<u32, ProcTaskInfo>> {
    let mut tasks = HashMap::new();

    let entries = fs::read_dir("/proc").context("reading /proc")?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        match read_proc_task(pid) {
            Ok(info) => {
                tasks.insert(pid, info);
            }
            Err(_) => continue,
        }
    }

    Ok(tasks)
}

/// Information read from /proc/[pid]/ files.
pub struct ProcTaskInfo {
    pub pid: u32,
    pub ppid: u32,
    pub state: char,
    pub comm: String,
    pub cmdline: String,
    pub uid: u32,
    pub priority: i32,
    pub nice: i32,
    pub num_threads: u32,
    pub vsize: u64,
    pub rss_pages: u64,
    pub utime_ticks: u64,
    pub stime_ticks: u64,
    pub start_time_ticks: u64,
    pub cgroup_path: String,
}

fn read_proc_task(pid: u32) -> Result<ProcTaskInfo> {
    let stat_content =
        fs::read_to_string(format!("/proc/{pid}/stat")).context("reading stat")?;

    // Parse stat: pid (comm) state ppid ...
    // comm can contain spaces and parens, so find the last ')'
    let comm_start = stat_content
        .find('(')
        .context("parsing stat: no comm start")?;
    let comm_end = stat_content
        .rfind(')')
        .context("parsing stat: no comm end")?;
    let comm = stat_content[comm_start + 1..comm_end].to_string();
    let rest = &stat_content[comm_end + 2..]; // skip ") "
    let fields: Vec<&str> = rest.split_whitespace().collect();

    // Fields after (comm): state(0) ppid(1) pgrp(2) session(3) tty_nr(4)
    //   tpgid(5) flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10)
    //   utime(11) stime(12) cutime(13) cstime(14) priority(15) nice(16)
    //   num_threads(17) itrealvalue(18) starttime(19) vsize(20) rss(21)
    let state = fields.first().and_then(|s| s.chars().next()).unwrap_or('?');
    let ppid: u32 = fields.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let utime: u64 = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
    let stime: u64 = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let priority: i32 = fields.get(15).and_then(|s| s.parse().ok()).unwrap_or(20);
    let nice: i32 = fields.get(16).and_then(|s| s.parse().ok()).unwrap_or(0);
    let num_threads: u32 = fields.get(17).and_then(|s| s.parse().ok()).unwrap_or(1);
    let start_time: u64 = fields.get(19).and_then(|s| s.parse().ok()).unwrap_or(0);
    let vsize: u64 = fields.get(20).and_then(|s| s.parse().ok()).unwrap_or(0);
    let rss_pages: u64 = fields.get(21).and_then(|s| s.parse().ok()).unwrap_or(0);

    let cmdline = fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .to_string();

    let uid = read_uid(pid).unwrap_or(0);

    let cgroup_path = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|content| {
            for line in content.lines() {
                let parts: Vec<&str> = line.splitn(3, ':').collect();
                if parts.len() == 3 && parts[0] == "0" {
                    return Some(parts[2].to_string());
                }
            }
            content.lines().next().and_then(|line| {
                let parts: Vec<&str> = line.splitn(3, ':').collect();
                if parts.len() == 3 {
                    Some(parts[2].to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_default();

    Ok(ProcTaskInfo {
        pid,
        ppid,
        state,
        comm,
        cmdline,
        uid,
        priority,
        nice,
        num_threads,
        vsize,
        rss_pages,
        utime_ticks: utime,
        stime_ticks: stime,
        start_time_ticks: start_time,
        cgroup_path,
    })
}

fn read_uid(pid: u32) -> Result<u32> {
    let content = fs::read_to_string(format!("/proc/{pid}/status"))?;
    for line in content.lines() {
        if line.starts_with("Uid:") {
            let uid: u32 = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            return Ok(uid);
        }
    }
    Ok(0)
}

/// Read shared memory (SHR) for a process from /proc/[pid]/statm.
pub fn read_shared_pages(pid: u32) -> u64 {
    fs::read_to_string(format!("/proc/{pid}/statm"))
        .ok()
        .and_then(|content| {
            content
                .split_whitespace()
                .nth(2)
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(0)
}
