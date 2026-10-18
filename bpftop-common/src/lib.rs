/// Process/task information collected by the eBPF task iterator.
/// This struct is written by the eBPF program and read by userspace.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TaskInfo {
    /// Process ID (tgid in kernel terms)
    pub pid: u32,
    /// Thread ID (pid in kernel terms)
    pub tid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Effective user ID
    pub euid: u32,
    /// Real user ID
    pub ruid: u32,
    /// `__state | exit_state`: the kernel's raw TASK_*/EXIT_* bits.
    pub state: u32,
    /// User CPU time in nanoseconds: the leader's plus exited threads'.
    /// Live threads' time arrives separately as `ThreadCpu` records.
    pub utime_ns: u64,
    /// System CPU time in nanoseconds (same scope as `utime_ns`)
    pub stime_ns: u64,
    /// Virtual memory size in pages (mm->total_vm)
    pub vsize_pages: u64,
    /// Resident set size in pages
    pub rss_pages: u64,
    /// Process start time in nanoseconds (boot-relative)
    pub start_time_ns: u64,
    /// Process name (comm), null-terminated
    pub comm: [u8; 16],
    /// Kernel priority (task->prio)
    pub prio: i32,
    /// Static priority (nice = static_prio - 120)
    pub static_prio: i32,
    /// Shared memory pages (from mm_rss_stat MM_SHMEMPAGES)
    pub shmem_pages: u64,
    /// Cgroup inode ID for container detection
    pub cgroup_id: u64,
    /// `CmdlineEvent::gen` of this PID's CMDLINE_MAP entry, 0 if none.
    pub cmdline_gen: u64,
    /// Cumulative network bytes from NET_STATS (0 if no entry).
    pub net_tx_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_ifindex: u32,
    /// Live threads in the thread group (the iterator emits leaders only).
    pub nr_threads: u32,
    /// Value of the task's cgroup `cgroup.freeze` (0 or 1).
    pub frozen: u8,
    /// 1 if the task has PF_KTHREAD set.
    pub kthread: u8,
    pub _pad2: [u8; 6],
}

/// CPU time of one live non-leader thread, emitted by the task iterator in
/// place of a full `TaskInfo`. Shares the `pid`/`tid` prefix with
/// `TaskInfo`; `tid != pid` is what distinguishes the two in the stream.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ThreadCpu {
    pub pid: u32,
    pub tid: u32,
    pub cpu_ns: u64,
}

/// Command line event captured by sched_process_exec tracepoint.
/// Stored in CMDLINE_MAP keyed by PID.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CmdlineEvent {
    pub pid: u32,
    pub len: u32,
    pub cmdline: [u8; 256],
    /// Changes on every exec (ktime at exec; 1 for startup-seeded entries).
    pub gen: u64,
}

/// Per-process network I/O stats collected by kprobes on tcp/udp send/recv.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NetStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub ifindex: u32,
    pub _pad: u32,
}

// Keep in sync with bpftop-ebpf-c/bpftop.bpf.c (asserted on both sides).
const _: () = assert!(core::mem::size_of::<TaskInfo>() == 144);
const _: () = assert!(core::mem::size_of::<CmdlineEvent>() == 272);
const _: () = assert!(core::mem::size_of::<ThreadCpu>() == 16);

/// Parsed output of one task iterator walk.
#[derive(Debug, Default)]
pub struct IterRecords {
    /// One per thread-group leader.
    pub tasks: Vec<TaskInfo>,
    /// tgid → summed CPU ns of the group's live non-leader threads.
    pub thread_cpu_ns: std::collections::HashMap<u32, u64>,
    pub thread_records: usize,
}

/// Split the iterator's mixed `TaskInfo`/`ThreadCpu` stream. Returns the
/// byte offset of the first truncated record on error.
pub fn parse_iter_records(buf: &[u8]) -> Result<IterRecords, usize> {
    use core::mem::size_of;

    let mut out = IterRecords::default();
    let mut off = 0;
    while off < buf.len() {
        let rest = &buf[off..];
        if rest.len() < 8 {
            return Err(off);
        }
        let pid = u32::from_ne_bytes(rest[0..4].try_into().unwrap());
        let tid = u32::from_ne_bytes(rest[4..8].try_into().unwrap());
        if pid == tid {
            if rest.len() < size_of::<TaskInfo>() {
                return Err(off);
            }
            // SAFETY: length checked; TaskInfo is plain old data.
            out.tasks.push(unsafe { core::ptr::read_unaligned(rest.as_ptr() as *const TaskInfo) });
            off += size_of::<TaskInfo>();
        } else {
            if rest.len() < size_of::<ThreadCpu>() {
                return Err(off);
            }
            // SAFETY: length checked; ThreadCpu is plain old data.
            let t = unsafe { core::ptr::read_unaligned(rest.as_ptr() as *const ThreadCpu) };
            *out.thread_cpu_ns.entry(t.pid).or_default() += t.cpu_ns;
            out.thread_records += 1;
            off += size_of::<ThreadCpu>();
        }
    }
    Ok(out)
}

unsafe impl aya::Pod for TaskInfo {}

unsafe impl aya::Pod for CmdlineEvent {}

unsafe impl aya::Pod for NetStats {}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<T: Copy>(v: &T) -> Vec<u8> {
        // SAFETY: test-only view of a POD struct as bytes.
        unsafe { core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>()) }
            .to_vec()
    }

    fn leader(pid: u32) -> TaskInfo {
        // SAFETY: TaskInfo is plain old data; all-zero is valid.
        let mut t: TaskInfo = unsafe { core::mem::zeroed() };
        t.pid = pid;
        t.tid = pid;
        t
    }

    #[test]
    fn parses_mixed_leader_and_thread_records() {
        let mut buf = Vec::new();
        // Threads may arrive before or after their leader.
        buf.extend(bytes(&ThreadCpu { pid: 10, tid: 12, cpu_ns: 5 }));
        buf.extend(bytes(&leader(10)));
        buf.extend(bytes(&leader(20)));
        buf.extend(bytes(&ThreadCpu { pid: 10, tid: 11, cpu_ns: 7 }));

        let r = parse_iter_records(&buf).unwrap();
        assert_eq!(r.tasks.iter().map(|t| t.pid).collect::<Vec<_>>(), vec![10, 20]);
        assert_eq!(r.thread_cpu_ns.get(&10), Some(&12));
        assert_eq!(r.thread_cpu_ns.get(&20), None);
        assert_eq!(r.thread_records, 2);
    }

    #[test]
    fn rejects_truncated_records() {
        let full = bytes(&leader(10));
        assert_eq!(parse_iter_records(&full[..100]).unwrap_err(), 0);

        let mut buf = bytes(&ThreadCpu { pid: 1, tid: 2, cpu_ns: 3 });
        buf.extend_from_slice(&[0; 4]);
        assert_eq!(parse_iter_records(&buf).unwrap_err(), 16);
    }
}
