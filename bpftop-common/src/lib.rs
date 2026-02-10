#![cfg_attr(not(feature = "userspace"), no_std)]

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
    /// Process state (0=running, 1=sleeping, 2=disk_sleep, 4=zombie, 8=stopped)
    pub state: u8,
    pub _pad: [u8; 3],
    /// User CPU time in nanoseconds
    pub utime_ns: u64,
    /// System CPU time in nanoseconds
    pub stime_ns: u64,
    /// Virtual memory size in bytes
    pub vsize_bytes: u64,
    /// Resident set size in pages
    pub rss_pages: u64,
    /// Process start time in nanoseconds (boot-relative)
    pub start_time_ns: u64,
    /// Process name (comm), null-terminated
    pub comm: [u8; 16],
}

/// File descriptor information collected by the eBPF file iterator.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileInfo {
    /// Process ID that owns this FD
    pub pid: u32,
    /// File descriptor number
    pub fd: u32,
    /// Type of FD: 0=regular, 1=socket, 2=pipe, 3=other
    pub fd_type: u8,
    /// Socket address family (AF_INET=2, AF_INET6=10, AF_UNIX=1)
    pub sock_family: u8,
    /// Socket type (SOCK_STREAM=1, SOCK_DGRAM=2)
    pub sock_type: u8,
    /// TCP connection state
    pub sock_state: u8,
    /// Source address (IPv4 in first 4 bytes, or full IPv6)
    pub src_addr: [u8; 16],
    /// Destination address
    pub dst_addr: [u8; 16],
    /// Source port (network byte order)
    pub src_port: u16,
    /// Destination port (network byte order)
    pub dst_port: u16,
    /// File path or unix socket path, null-terminated
    pub path: [u8; 256],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for TaskInfo {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for FileInfo {}
