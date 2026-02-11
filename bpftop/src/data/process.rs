use std::cmp::Ordering;

/// Full process information combining eBPF data and /proc supplements.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub user: String,
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
    pub cpu_time_secs: f64,
    pub start_time_ns: u64,
    pub comm: String,
    pub cmdline: String,
    pub container: Option<String>,
    pub cgroup_path: String,
    /// Children PIDs for tree view.
    pub children: Vec<u32>,
    /// Previous utime+stime for delta calculation.
    pub prev_cpu_ns: u64,
    /// Whether this is a kernel thread (ppid=2 or pid=2).
    pub is_kernel_thread: bool,
    /// Whether this is a user thread (tid != pid).
    pub is_thread: bool,
    /// Thread ID (only differs from pid for threads).
    pub tid: u32,
    /// Tagged by user (space key).
    pub tagged: bool,
    /// Tree view prefix (e.g. "├─- ") set during tree ordering.
    pub tree_prefix: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Sleeping,
    DiskSleep,
    Zombie,
    Stopped,
    TracingStop,
    Dead,
    Idle,
    Unknown,
}

impl ProcessState {
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

    pub fn from_kernel_state(state: u8) -> Self {
        // Kernel task states are bitmask values
        match state {
            0 => Self::Running,
            1 => Self::Sleeping,
            2 => Self::DiskSleep,
            4 => Self::Zombie,
            8 => Self::Stopped,
            _ => Self::Unknown,
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
        self.cpu_time_secs = src.cpu_time_secs;
        self.comm = src.comm.clone();
        self.cmdline = src.cmdline.clone();
        self.children = src.children.clone();
        self.prev_cpu_ns = src.prev_cpu_ns;
    }
}

/// Which field to yank from a process row.
#[derive(Debug, Clone, Copy)]
pub enum YankField {
    Row,
    Pid,
    User,
    Container,
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
            YankField::User => self.user.clone(),
            YankField::Container => self.container.clone().unwrap_or_else(|| "-".to_string()),
            YankField::Name => self.comm.clone(),
            YankField::Cmdline => self.cmdline.clone(),
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
    Time,
    Container,
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
            Self::Time,
            Self::Container,
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
            Self::Time => "TIME+",
            Self::Container => "CONT",
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
            Self::Time => 10,
            Self::Container => 12,
            Self::Command => 0, // fills remaining space
        }
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
        SortColumn::Time => quantize(a.cpu_time_secs).cmp(&quantize(b.cpu_time_secs)).then(a.pid.cmp(&b.pid)),
        SortColumn::Container => a.container.cmp(&b.container).then(a.pid.cmp(&b.pid)),
        SortColumn::Command => a.cmdline.cmp(&b.cmdline).then(a.pid.cmp(&b.pid)),
    };
    if ascending { ord } else { ord.reverse() }
}

/// Filter processes by a search string (matches against comm and cmdline).
pub fn matches_filter(proc: &ProcessInfo, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    let filter_lower = filter.to_lowercase();
    proc.comm.to_lowercase().contains(&filter_lower)
        || proc.cmdline.to_lowercase().contains(&filter_lower)
        || proc.pid.to_string().contains(filter)
        || proc.user.to_lowercase().contains(&filter_lower)
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
            user: String::from("test"),
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
            cpu_time_secs: 0.0,
            start_time_ns: 0,
            comm: String::from("test"),
            cmdline: String::from("test"),
            container: None,
            cgroup_path: String::new(),
            children: Vec::new(),
            prev_cpu_ns: 0,
            is_kernel_thread: false,
            is_thread: false,
            tid: pid,
            tagged: false,
            tree_prefix: String::new(),
        }
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
