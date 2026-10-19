/// `/proc/<pid>/io`-style counters: bytes read from / written to storage
/// and read/write syscall counts. Zero where the kernel lacks
/// CONFIG_TASK_IO_ACCOUNTING / CONFIG_TASK_XACCT.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IoCounters {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub syscr: u64,
    pub syscw: u64,
}

impl std::ops::AddAssign for IoCounters {
    fn add_assign(&mut self, o: Self) {
        self.read_bytes += o.read_bytes;
        self.write_bytes += o.write_bytes;
        self.syscr += o.syscr;
        self.syscw += o.syscw;
    }
}

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
    /// Scheduler runtime (`se.sum_exec_runtime`) in ns: the leader's plus
    /// exited threads'. Live threads' time arrives as `ThreadRec` records.
    pub cpu_ns: u64,
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
    /// Shared pages: file-backed + shmem (statm "shared", htop's SHR)
    pub shared_pages: u64,
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
    /// I/O of the leader plus exited threads (live threads: `ThreadRec`).
    pub io: IoCounters,
    /// Value of the task's cgroup `cgroup.freeze` (0 or 1).
    pub frozen: u8,
    /// 1 if the task has PF_KTHREAD set.
    pub kthread: u8,
    pub _pad2: [u8; 6],
}

/// One live non-leader thread, emitted by the task iterator in place of a
/// full `TaskInfo` (everything else is shared with its process). Shares
/// the `pid`/`tid` prefix with `TaskInfo`; `tid != pid` is what
/// distinguishes the two in the stream.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ThreadRec {
    pub pid: u32,
    pub tid: u32,
    /// Scheduler runtime (`se.sum_exec_runtime`) in ns.
    pub cpu_ns: u64,
    /// `__state | exit_state`, as in `TaskInfo::state`.
    pub state: u32,
    pub _pad: u32,
    /// Thread name, null-terminated
    pub comm: [u8; 16],
    pub io: IoCounters,
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
    /// Untruncated cmdline length; `> len` means `cmdline` was cut short.
    pub full_len: u32,
    pub _pad: u32,
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
const _: () = assert!(core::mem::size_of::<TaskInfo>() == 168);
const _: () = assert!(core::mem::size_of::<CmdlineEvent>() == 280);
const _: () = assert!(core::mem::size_of::<ThreadRec>() == 72);

/// Parsed output of one task iterator walk.
#[derive(Debug, Default)]
pub struct IterRecords {
    /// One per thread-group leader.
    pub tasks: Vec<TaskInfo>,
    /// One per live non-leader thread.
    pub threads: Vec<ThreadRec>,
    /// tgid → summed CPU ns of the group's live non-leader threads.
    pub thread_cpu_ns: std::collections::HashMap<u32, u64>,
    /// tgid → summed I/O of the group's live non-leader threads.
    pub thread_io: std::collections::HashMap<u32, IoCounters>,
    pub thread_records: usize,
}

/// Split the iterator's mixed `TaskInfo`/`ThreadRec` stream. Returns the
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
            if rest.len() < size_of::<ThreadRec>() {
                return Err(off);
            }
            // SAFETY: length checked; ThreadRec is plain old data.
            let t = unsafe { core::ptr::read_unaligned(rest.as_ptr() as *const ThreadRec) };
            *out.thread_cpu_ns.entry(t.pid).or_default() += t.cpu_ns;
            *out.thread_io.entry(t.pid).or_default() += t.io;
            out.thread_records += 1;
            out.threads.push(t);
            off += size_of::<ThreadRec>();
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

    fn thread(pid: u32, tid: u32, cpu_ns: u64) -> ThreadRec {
        ThreadRec { pid, tid, cpu_ns, state: 0, _pad: 0, comm: [0; 16], io: IoCounters::default() }
    }

    #[test]
    fn parses_mixed_leader_and_thread_records() {
        let mut buf = Vec::new();
        // Threads may arrive before or after their leader.
        buf.extend(bytes(&thread(10, 12, 5)));
        buf.extend(bytes(&leader(10)));
        buf.extend(bytes(&leader(20)));
        buf.extend(bytes(&thread(10, 11, 7)));

        let r = parse_iter_records(&buf).unwrap();
        assert_eq!(r.tasks.iter().map(|t| t.pid).collect::<Vec<_>>(), vec![10, 20]);
        assert_eq!(r.thread_cpu_ns.get(&10), Some(&12));
        assert_eq!(r.thread_cpu_ns.get(&20), None);
        assert_eq!(r.thread_records, 2);
        assert_eq!(r.threads.iter().map(|t| t.tid).collect::<Vec<_>>(), vec![12, 11]);
    }

    #[test]
    fn rejects_truncated_records() {
        let full = bytes(&leader(10));
        assert_eq!(parse_iter_records(&full[..100]).unwrap_err(), 0);

        let mut buf = bytes(&thread(1, 2, 3));
        buf.extend_from_slice(&[0; 4]);
        assert_eq!(parse_iter_records(&buf).unwrap_err(), 72);
    }
}
