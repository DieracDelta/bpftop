use std::cmp::Ordering;
use std::sync::Arc;

/// Immutable shared string. Process snapshots are cloned into the UI's
/// lists every refresh, so text fields are refcounted instead of copied.
pub type Text = Arc<str>;

/// Full process information combining eBPF data and /proc supplements.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    #[allow(dead_code)]
    pub uid: u32,
    pub user: Text,
    pub state: ProcessState,
    pub priority: i32,
    pub nice: i32,
    pub virt_bytes: u64,
    pub res_bytes: u64,
    pub shr_bytes: u64,
    pub cpu_percent: f64,
    pub mem_percent: f64,
    pub gpu_percent: f64,
    pub gpu_mem_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub net_rate: f64,
    pub net_ifname: Text,
    /// Bytes/s read from / written to storage, and read+write syscalls/s.
    pub io_read_rate: f64,
    pub io_write_rate: f64,
    pub iops: f64,
    pub cpu_time_secs: f64,
    #[allow(dead_code)]
    pub start_time_ns: u64,
    pub comm: Text,
    pub cmdline: Text,
    pub container: Option<Text>,
    pub service: Option<Text>,
    pub cgroup_path: Text,
    /// Children PIDs for tree view.
    pub children: Vec<u32>,
    /// Previous utime+stime for delta calculation.
    pub prev_cpu_ns: u64,
    /// Whether this is a kernel thread (PF_KTHREAD).
    pub is_kernel_thread: bool,
    /// Whether this is a user thread (tid != pid).
    pub is_thread: bool,
    /// Thread ID (only differs from pid for threads).
    #[allow(dead_code)]
    pub tid: u32,
    /// Tagged by user (space key).
    pub tagged: bool,
    /// Whether this process's cgroup is currently frozen.
    pub frozen: bool,
    /// Tree view prefix (e.g. "├─- ") set during tree ordering.
    pub tree_prefix: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ProcessState {
    Running,
    Sleeping,
    DiskSleep,
    Zombie,
    Stopped,
    TracingStop,
    Dead,
    Parked,
    Idle,
    Unknown,
}

impl ProcessState {
    #[allow(dead_code)]
    pub fn from_proc_stat(c: char) -> Self {
        match c {
            'R' => Self::Running,
            'S' => Self::Sleeping,
            'D' => Self::DiskSleep,
            'Z' => Self::Zombie,
            'T' => Self::Stopped,
            't' => Self::TracingStop,
            'X' | 'x' => Self::Dead,
            'I' => Self::Idle,
            _ => Self::Unknown,
        }
    }

    /// Decode `__state | exit_state` the way the kernel does for /proc
    /// (`__task_state_index`): mask to the reportable bits, special-case
    /// TASK_IDLE and rtlock waits, then take the highest set bit.
    pub fn from_kernel_state(state: u32) -> Self {
        const TASK_UNINTERRUPTIBLE: u32 = 0x2;
        const TASK_NOLOAD: u32 = 0x400;
        const TASK_RTLOCK_WAIT: u32 = 0x1000;
        const TASK_REPORT: u32 = 0x7f;

        if state & (TASK_UNINTERRUPTIBLE | TASK_NOLOAD) == TASK_UNINTERRUPTIBLE | TASK_NOLOAD {
            return Self::Idle;
        }
        if state & TASK_RTLOCK_WAIT != 0 {
            return Self::DiskSleep;
        }
        match state & TASK_REPORT {
            0 => Self::Running,
            s => match 31 - s.leading_zeros() {
                0 => Self::Sleeping,     // TASK_INTERRUPTIBLE
                1 => Self::DiskSleep,    // TASK_UNINTERRUPTIBLE
                2 => Self::Stopped,      // __TASK_STOPPED
                3 => Self::TracingStop,  // __TASK_TRACED
                4 => Self::Dead,         // EXIT_DEAD
                5 => Self::Zombie,       // EXIT_ZOMBIE
                _ => Self::Parked,       // TASK_PARKED
            },
        }
    }

    pub fn as_char(&self) -> char {
        match self {
            Self::Running => 'R',
            Self::Sleeping => 'S',
            Self::DiskSleep => 'D',
            Self::Zombie => 'Z',
            Self::Stopped => 'T',
            Self::TracingStop => 't',
            Self::Dead => 'X',
            Self::Parked => 'P',
            Self::Idle => 'I',
            Self::Unknown => '?',
        }
    }
}

impl ProcessInfo {
    /// Update only volatile fields from a fresh snapshot, preserving stable
    /// fields like `tagged`, `tree_prefix`, and ordering position.
    pub fn update_dynamic_fields(&mut self, src: &ProcessInfo) {
        self.state = src.state;
        self.priority = src.priority;
        self.nice = src.nice;
        self.virt_bytes = src.virt_bytes;
        self.res_bytes = src.res_bytes;
        self.shr_bytes = src.shr_bytes;
        self.cpu_percent = src.cpu_percent;
        self.mem_percent = src.mem_percent;
        self.gpu_percent = src.gpu_percent;
        self.gpu_mem_bytes = src.gpu_mem_bytes;
        self.net_rx_bytes = src.net_rx_bytes;
        self.net_tx_bytes = src.net_tx_bytes;
        self.net_rate = src.net_rate;
        self.net_ifname = src.net_ifname.clone();
        self.io_read_rate = src.io_read_rate;
        self.io_write_rate = src.io_write_rate;
        self.iops = src.iops;
        self.user = src.user.clone();
        self.container = src.container.clone();
        self.cgroup_path = src.cgroup_path.clone();
        self.cpu_time_secs = src.cpu_time_secs;
        self.comm = src.comm.clone();
        self.cmdline = src.cmdline.clone();
        self.children = src.children.clone();
        self.prev_cpu_ns = src.prev_cpu_ns;
        self.frozen = src.frozen;
    }
}

/// Which field to yank from a process row.
#[derive(Debug, Clone, Copy)]
pub enum YankField {
    Row,
    Pid,
    User,
    Container,
    Service,
    Name,
    Cmdline,
    GpuPercent,
    GpuMem,
}

impl ProcessInfo {
    /// Format the requested field for clipboard yanking.
    pub fn yank_text(&self, field: YankField) -> String {
        match field {
            YankField::Row => format!(
                "{}\t{}\t{:.1}\t{:.1}\t{:.1}\t{}\t{}\t{}",
                self.pid,
                self.user,
                self.cpu_percent,
                self.mem_percent,
                self.gpu_percent,
                format_bytes(self.gpu_mem_bytes),
                format_time(self.cpu_time_secs),
                self.cmdline,
            ),
            YankField::Pid => self.pid.to_string(),
            YankField::User => self.user.to_string(),
            YankField::Container => self.container.as_deref().unwrap_or("-").to_string(),
            YankField::Service => self.service.as_deref().unwrap_or("-").to_string(),
            YankField::Name => self.comm.to_string(),
            YankField::Cmdline => self.cmdline.to_string(),
            YankField::GpuPercent => format!("{:.1}", self.gpu_percent),
            YankField::GpuMem => format_bytes(self.gpu_mem_bytes),
        }
    }
}

/// Column that the process table can be sorted by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Pid,
    User,
    Priority,
    Nice,
    Virt,
    Res,
    Shr,
    State,
    CpuPercent,
    MemPercent,
    GpuPercent,
    GpuMem,
    NetRate,
    NetTotal,
    NetIf,
    IoRead,
    IoWrite,
    Iops,
    Time,
    Container,
    Service,
    Command,
}

impl SortColumn {
    pub fn all() -> &'static [SortColumn] {
        &[
            Self::Pid,
            Self::User,
            Self::Priority,
            Self::Nice,
            Self::Virt,
            Self::Res,
            Self::Shr,
            Self::State,
            Self::CpuPercent,
            Self::MemPercent,
            Self::GpuPercent,
            Self::GpuMem,
            Self::NetRate,
            Self::NetTotal,
            Self::NetIf,
            Self::IoRead,
            Self::IoWrite,
            Self::Iops,
            Self::Time,
            Self::Container,
            Self::Service,
            Self::Command,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Pid => "PID",
            Self::User => "USER",
            Self::Priority => "PRI",
            Self::Nice => "NI",
            Self::Virt => "VIRT",
            Self::Res => "RES",
            Self::Shr => "SHR",
            Self::State => "S",
            Self::CpuPercent => "CPU%",
            Self::MemPercent => "MEM%",
            Self::GpuPercent => "GPU%",
            Self::GpuMem => "GMEM",
            Self::NetRate => "NET/s",
            Self::NetTotal => "NET TOT",
            Self::NetIf => "IF",
            Self::IoRead => "RD/s",
            Self::IoWrite => "WR/s",
            Self::Iops => "IOPS",
            Self::Time => "TIME+",
            Self::Container => "CONT",
            Self::Service => "UNIT",
            Self::Command => "Command",
        }
    }

    /// Column width in characters.
    pub fn width(&self) -> u16 {
        match self {
            Self::Pid => 7,
            Self::User => 9,
            Self::Priority => 4,
            Self::Nice => 4,
            Self::Virt => 7,
            Self::Res => 7,
            Self::Shr => 7,
            Self::State => 2,
            Self::CpuPercent => 6,
            Self::MemPercent => 6,
            Self::GpuPercent => 5,
            Self::GpuMem => 6,
            Self::NetRate => 8,
            Self::NetTotal => 7,
            Self::NetIf => 6,
            Self::IoRead => 8,
            Self::IoWrite => 8,
            Self::Iops => 6,
            Self::Time => 10,
            Self::Container => 12,
            Self::Service => 16,
            Self::Command => 0, // fills remaining space
        }
    }

    /// Default sort direction when first clicking a column header.
    /// Text columns default to ascending; numeric columns to descending.
    pub fn default_ascending(&self) -> bool {
        matches!(self, Self::Pid | Self::User | Self::State | Self::NetIf | Self::Container | Self::Service | Self::Command)
    }
}

/// Truncate a float to 1 decimal place for stable comparison.
/// Values that display identically (e.g. 0.04 and 0.02 both show "0.0")
/// compare as equal, letting the PID tiebreaker kick in.
fn quantize(v: f64) -> i64 {
    (v * 10.0) as i64
}

/// Compare two processes by the given sort column, with PID as a
/// stable tiebreaker so the display doesn't shuffle on equal values.
pub fn compare_processes(a: &ProcessInfo, b: &ProcessInfo, col: SortColumn, ascending: bool) -> Ordering {
    let ord = match col {
        SortColumn::Pid => a.pid.cmp(&b.pid),
        SortColumn::User => a.user.cmp(&b.user).then(a.pid.cmp(&b.pid)),
        SortColumn::Priority => a.priority.cmp(&b.priority).then(a.pid.cmp(&b.pid)),
        SortColumn::Nice => a.nice.cmp(&b.nice).then(a.pid.cmp(&b.pid)),
        SortColumn::Virt => a.virt_bytes.cmp(&b.virt_bytes).then(a.pid.cmp(&b.pid)),
        SortColumn::Res => a.res_bytes.cmp(&b.res_bytes).then(a.pid.cmp(&b.pid)),
        SortColumn::Shr => a.shr_bytes.cmp(&b.shr_bytes).then(a.pid.cmp(&b.pid)),
        SortColumn::State => (a.state.as_char()).cmp(&b.state.as_char()).then(a.pid.cmp(&b.pid)),
        SortColumn::CpuPercent => quantize(a.cpu_percent).cmp(&quantize(b.cpu_percent)).then(a.pid.cmp(&b.pid)),
        SortColumn::MemPercent => quantize(a.mem_percent).cmp(&quantize(b.mem_percent)).then(a.pid.cmp(&b.pid)),
        SortColumn::GpuPercent => quantize(a.gpu_percent).cmp(&quantize(b.gpu_percent)).then(a.pid.cmp(&b.pid)),
        SortColumn::GpuMem => a.gpu_mem_bytes.cmp(&b.gpu_mem_bytes).then(a.pid.cmp(&b.pid)),
        SortColumn::NetRate => quantize(a.net_rate).cmp(&quantize(b.net_rate)).then(a.pid.cmp(&b.pid)),
        SortColumn::NetTotal => (a.net_tx_bytes + a.net_rx_bytes).cmp(&(b.net_tx_bytes + b.net_rx_bytes)).then(a.pid.cmp(&b.pid)),
        SortColumn::NetIf => a.net_ifname.cmp(&b.net_ifname).then(a.pid.cmp(&b.pid)),
        SortColumn::IoRead => quantize(a.io_read_rate).cmp(&quantize(b.io_read_rate)).then(a.pid.cmp(&b.pid)),
        SortColumn::IoWrite => quantize(a.io_write_rate).cmp(&quantize(b.io_write_rate)).then(a.pid.cmp(&b.pid)),
        SortColumn::Iops => quantize(a.iops).cmp(&quantize(b.iops)).then(a.pid.cmp(&b.pid)),
        SortColumn::Time => quantize(a.cpu_time_secs).cmp(&quantize(b.cpu_time_secs)).then(a.pid.cmp(&b.pid)),
        SortColumn::Container => a.container.cmp(&b.container).then(a.pid.cmp(&b.pid)),
        SortColumn::Service => a.service.cmp(&b.service).then(a.pid.cmp(&b.pid)),
        SortColumn::Command => a.cmdline.cmp(&b.cmdline).then(a.pid.cmp(&b.pid)),
    };
    if ascending { ord } else { ord.reverse() }
}

/// Filter processes by a search string (matches against comm and cmdline).
/// `filter_lower` is `filter.to_lowercase()`, computed once by the caller.
pub fn matches_filter(proc: &ProcessInfo, filter: &str, filter_lower: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    proc.comm.to_lowercase().contains(filter_lower)
        || proc.cmdline.to_lowercase().contains(filter_lower)
        || proc.pid.to_string().contains(filter)
        || proc.user.to_lowercase().contains(filter_lower)
        || proc.service.as_deref().is_some_and(|s| s.to_lowercase().contains(filter_lower))
        || (!proc.net_ifname.is_empty() && proc.net_ifname.to_lowercase().contains(filter_lower))
}

/// Decode raw process text (cmdline, comm) for display: lossy UTF-8, with
/// control characters (the NUL arg separators, but also newlines or
/// escape sequences a process put in its own argv) shown as spaces.
pub fn display_text(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Format bytes into human-readable form (K, M, G).
pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.0}M", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.0}K", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}

/// Format a network rate (bytes/sec) into human-readable form with /s suffix.
pub fn format_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1}G/s", bytes_per_sec / (1024.0 * 1024.0 * 1024.0))
    } else if bytes_per_sec >= 1024.0 * 1024.0 {
        format!("{:.1}M/s", bytes_per_sec / (1024.0 * 1024.0))
    } else if bytes_per_sec >= 1024.0 {
        format!("{:.0}K/s", bytes_per_sec / 1024.0)
    } else {
        format!("{:.0}B/s", bytes_per_sec)
    }
}

/// Format an operations-per-second rate compactly (e.g. 12, 3.4K, 1.2M).
pub fn format_ops(ops_per_sec: f64) -> String {
    if ops_per_sec >= 1_000_000.0 {
        format!("{:.1}M", ops_per_sec / 1_000_000.0)
    } else if ops_per_sec >= 1_000.0 {
        format!("{:.1}K", ops_per_sec / 1_000.0)
    } else {
        format!("{:.0}", ops_per_sec)
    }
}

/// Format CPU time as HH:MM:SS.cc.
pub fn format_time(secs: f64) -> String {
    let total_centisecs = (secs * 100.0) as u64;
    let hours = total_centisecs / 360000;
    let mins = (total_centisecs % 360000) / 6000;
    let s = (total_centisecs % 6000) / 100;
    let cs = total_centisecs % 100;
    if hours > 0 {
        format!("{hours}:{mins:02}:{s:02}.{cs:02}")
    } else {
        format!("{mins}:{s:02}.{cs:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: u32, cpu_percent: f64) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 1,
            uid: 1000,
            user: Text::from("test"),
            state: ProcessState::Sleeping,
            priority: 20,
            nice: 0,
            virt_bytes: 0,
            res_bytes: 0,
            shr_bytes: 0,
            cpu_percent,
            mem_percent: 0.0,
            gpu_percent: 0.0,
            gpu_mem_bytes: 0,
            net_rx_bytes: 0,
            net_tx_bytes: 0,
            net_rate: 0.0,
            net_ifname: Text::from(""),
            io_read_rate: 0.0,
            io_write_rate: 0.0,
            iops: 0.0,
            cpu_time_secs: 0.0,
            start_time_ns: 0,
            comm: Text::from("test"),
            cmdline: Text::from("test"),
            container: None,
            service: None,
            cgroup_path: Text::from(""),
            children: Vec::new(),
            prev_cpu_ns: 0,
            is_kernel_thread: false,
            is_thread: false,
            tid: pid,
            tagged: false,
            frozen: false,
            tree_prefix: String::new(),
        }
    }

    #[test]
    fn kernel_state_decoding() {
        let s = ProcessState::from_kernel_state;
        assert_eq!(s(0x0), ProcessState::Running);
        assert_eq!(s(0x1), ProcessState::Sleeping);
        assert_eq!(s(0x2), ProcessState::DiskSleep);
        assert_eq!(s(0x102), ProcessState::DiskSleep); // TASK_KILLABLE
        assert_eq!(s(0x402), ProcessState::Idle); // TASK_IDLE
        assert_eq!(s(0x104), ProcessState::Stopped); // TASK_STOPPED (with WAKEKILL)
        assert_eq!(s(0x8), ProcessState::TracingStop);
        assert_eq!(s(0x80 | 0x20), ProcessState::Zombie); // TASK_DEAD | EXIT_ZOMBIE
        assert_eq!(s(0x40), ProcessState::Parked);
        assert_eq!(s(0x1000 | 0x2), ProcessState::DiskSleep); // rtlock wait
    }

    #[test]
    fn display_text_replaces_control_chars() {
        assert_eq!(display_text(b"python3\0-c\0import os\nos.exit()\0"), "python3 -c import os os.exit()");
        assert_eq!(display_text(b"\x1b[31mred\0"), "[31mred");
        assert_eq!(display_text(b"caf\xc3\xa9"), "caf\u{e9}");
    }

    #[test]
    fn quantized_sort_stability() {
        // Processes with CPU% that all display as "0.0" should sort by PID
        let mut procs = vec![
            make_proc(300, 0.04),
            make_proc(100, 0.02),
            make_proc(200, 0.01),
        ];

        // Sort descending by CPU% (default)
        procs.sort_by(|a, b| compare_processes(a, b, SortColumn::CpuPercent, false));
        let pids: Vec<u32> = procs.iter().map(|p| p.pid).collect();
        // All quantize to 0, so PID tiebreaker (reversed) gives 300, 200, 100
        assert_eq!(pids, vec![300, 200, 100]);

        // Re-sort with slightly jittered values — order must not change
        procs[0].cpu_percent = 0.03;
        procs[1].cpu_percent = 0.05;
        procs[2].cpu_percent = 0.01;
        procs.sort_by(|a, b| compare_processes(a, b, SortColumn::CpuPercent, false));
        let pids2: Vec<u32> = procs.iter().map(|p| p.pid).collect();
        assert_eq!(pids2, vec![300, 200, 100]);
    }

    #[test]
    fn quantized_sort_distinguishes_different_values() {
        // Processes with clearly different CPU% should still sort correctly
        let mut procs = vec![
            make_proc(1, 0.5),
            make_proc(2, 5.0),
            make_proc(3, 1.2),
        ];

        procs.sort_by(|a, b| compare_processes(a, b, SortColumn::CpuPercent, false));
        let pids: Vec<u32> = procs.iter().map(|p| p.pid).collect();
        assert_eq!(pids, vec![2, 3, 1]);
    }
}
