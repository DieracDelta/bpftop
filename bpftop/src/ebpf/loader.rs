use std::fs;
use std::io::Read;

use std::collections::HashMap;

use anyhow::{Context, Result};
use aya::maps::HashMap as BpfHashMap;
use aya::programs::iter::{Iter, IterLink};
use aya::programs::{KProbe, TracePoint};
use aya::{Btf, Ebpf};
use bpftop_common::{CmdlineEvent, NetStats, TaskInfo};

/// The compiled eBPF object. Built by xtask (cargo xtask build-ebpf)
/// before the userspace crate is compiled.
///
/// Path is relative to this source file:
///   loader.rs  ∈  bpftop/src/ebpf/
///   workspace root = ../../../
///   eBPF binary    = bpftop-ebpf/target/bpfel-unknown-none/release/bpftop-ebpf
///
/// NOTE: eBPF programs MUST be built in release mode because debug builds
/// include core::fmt code that exceeds BPF's function argument limit.
static BPF_OBJ: &[u8] =
    aya::include_bytes_aligned!("../../../bpftop-ebpf/target/bpfel-unknown-none/release/bpftop-ebpf");

/// Manages eBPF program loading, attachment, and data retrieval.
pub struct EbpfLoader {
    bpf: Option<Ebpf>,
}

impl EbpfLoader {
    /// Load and attach all eBPF programs (iterator + tracepoints).
    pub fn load() -> Result<Self> {
        let mut bpf = Ebpf::load(BPF_OBJ).context("loading eBPF object")?;
        let btf = Btf::from_sys_fs().context("reading kernel BTF")?;

        // Load the task iterator (attachment happens per-read)
        let iter_prog: &mut Iter = bpf
            .program_mut("dump_task")
            .context("dump_task program not found")?
            .try_into()
            .context("dump_task is not an Iter program")?;
        iter_prog
            .load("task", &btf)
            .context("loading dump_task iterator")?;

        // Load and attach exec tracepoint
        let exec_prog: &mut TracePoint = bpf
            .program_mut("capture_cmdline")
            .context("capture_cmdline program not found")?
            .try_into()
            .context("capture_cmdline is not a TracePoint")?;
        exec_prog.load().context("loading capture_cmdline")?;
        exec_prog
            .attach("sched", "sched_process_exec")
            .context("attaching capture_cmdline")?;

        // Load and attach exit tracepoint
        let exit_prog: &mut TracePoint = bpf
            .program_mut("cleanup_cmdline")
            .context("cleanup_cmdline program not found")?
            .try_into()
            .context("cleanup_cmdline is not a TracePoint")?;
        exit_prog.load().context("loading cleanup_cmdline")?;
        exit_prog
            .attach("sched", "sched_process_exit")
            .context("attaching cleanup_cmdline")?;

        // Load and attach network kprobes/kretprobes
        for (prog_name, func_name) in &[
            ("kprobe_tcp_sendmsg", "tcp_sendmsg"),
            ("kprobe_udp_sendmsg", "udp_sendmsg"),
            ("kprobe_tcp_recvmsg", "tcp_recvmsg"),
            ("kprobe_udp_recvmsg", "udp_recvmsg"),
        ] {
            let prog: &mut KProbe = bpf
                .program_mut(prog_name)
                .context(format!("{prog_name} not found"))?
                .try_into()
                .context(format!("{prog_name} is not a KProbe"))?;
            prog.load().context(format!("loading {prog_name}"))?;
            prog.attach(func_name, 0)
                .context(format!("attaching {prog_name}"))?;
        }
        for (prog_name, func_name) in &[
            ("kretprobe_tcp_recvmsg", "tcp_recvmsg"),
            ("kretprobe_udp_recvmsg", "udp_recvmsg"),
        ] {
            let prog: &mut KProbe = bpf
                .program_mut(prog_name)
                .context(format!("{prog_name} not found"))?
                .try_into()
                .context(format!("{prog_name} is not a KProbe"))?;
            prog.load().context(format!("loading {prog_name}"))?;
            prog.attach(func_name, 0)
                .context(format!("attaching {prog_name}"))?;
        }

        Ok(Self { bpf: Some(bpf) })
    }

    /// Create a no-op loader (used as placeholder after moving the real one).
    pub fn noop() -> Self {
        Self { bpf: None }
    }

    pub fn is_loaded(&self) -> bool {
        self.bpf.is_some()
    }

    /// Run the task iterator once, returning all TaskInfo structs.
    ///
    /// Each call creates a new iterator link, reads all output, and
    /// drops the link. The iterator walks every task in the kernel.
    pub fn read_tasks(&mut self) -> Result<Vec<TaskInfo>> {
        let bpf = self
            .bpf
            .as_mut()
            .context("eBPF not loaded")?;

        let prog: &mut Iter = bpf
            .program_mut("dump_task")
            .context("dump_task program not found")?
            .try_into()
            .context("dump_task is not an Iter program")?;

        let link_id = prog.attach().context("attaching dump_task iterator")?;
        let link: IterLink = prog
            .take_link(link_id)
            .context("taking dump_task link")?;
        let mut file = link.into_file().context("creating iterator file")?;

        let mut buf = Vec::with_capacity(64 * 1024);
        file.read_to_end(&mut buf)
            .context("reading iterator output")?;

        let task_size = std::mem::size_of::<TaskInfo>();
        let tasks: Vec<TaskInfo> = buf
            .chunks_exact(task_size)
            .map(|chunk| unsafe { std::ptr::read_unaligned(chunk.as_ptr() as *const TaskInfo) })
            .collect();

        Ok(tasks)
    }

    /// Look up a cmdline for a PID from the BPF CMDLINE_MAP.
    pub fn get_cmdline(&self, pid: u32) -> Option<String> {
        let bpf = self.bpf.as_ref()?;
        let map = bpf.map("CMDLINE_MAP")?;
        let hash = BpfHashMap::<_, u32, CmdlineEvent>::try_from(map).ok()?;
        let event = hash.get(&pid, 0).ok()?;

        let len = (event.len as usize).min(event.cmdline.len());
        let raw = &event.cmdline[..len];
        // cmdline uses NUL as separator between args; replace with spaces
        let s: String = raw
            .iter()
            .map(|&b| if b == 0 { ' ' } else { b as char })
            .collect::<String>()
            .trim()
            .to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// Read per-PID network stats from the BPF NET_STATS map.
    /// Returns a map of pid -> (tx_bytes, rx_bytes, ifindex).
    pub fn read_net_stats(&self) -> HashMap<u32, (u64, u64, u32)> {
        let mut result = HashMap::new();
        let bpf = match self.bpf.as_ref() {
            Some(b) => b,
            None => return result,
        };
        let map = match bpf.map("NET_STATS") {
            Some(m) => m,
            None => return result,
        };
        let hash = match BpfHashMap::<_, u32, NetStats>::try_from(map) {
            Ok(h) => h,
            Err(_) => return result,
        };
        for item in hash.iter() {
            if let Ok((pid, stats)) = item {
                result.insert(pid, (stats.tx_bytes, stats.rx_bytes, stats.ifindex));
            }
        }
        result
    }

    /// Insert a cmdline entry into the BPF map (used for startup seeding).
    pub fn seed_cmdline(&mut self, pid: u32, cmdline: &str) -> Result<()> {
        let bpf = self
            .bpf
            .as_mut()
            .context("eBPF not loaded")?;
        let map = bpf
            .map_mut("CMDLINE_MAP")
            .context("CMDLINE_MAP not found")?;
        let mut hash = BpfHashMap::<_, u32, CmdlineEvent>::try_from(map)
            .map_err(|e| anyhow::anyhow!("CMDLINE_MAP is not a HashMap: {e}"))?;

        let mut event = CmdlineEvent {
            pid,
            len: 0,
            cmdline: [0u8; 256],
        };
        let bytes = cmdline.as_bytes();
        let copy_len = bytes.len().min(255);
        event.cmdline[..copy_len].copy_from_slice(&bytes[..copy_len]);
        event.len = copy_len as u32;

        hash.insert(pid, event, 0)
            .context("inserting into CMDLINE_MAP")?;
        Ok(())
    }
}

/// One-shot scan of /proc/*/cmdline to seed the CMDLINE_MAP for
/// processes that were already running before the BPF tracepoints
/// were attached. After this, no per-PID /proc reads occur.
pub fn seed_cmdlines_from_proc(loader: &mut EbpfLoader) {
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return,
    };
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

        let cmdline = match fs::read_to_string(format!("/proc/{pid}/cmdline")) {
            Ok(s) => s.replace('\0', " ").trim().to_string(),
            Err(_) => continue,
        };
        if cmdline.is_empty() {
            continue;
        }
        let _ = loader.seed_cmdline(pid, &cmdline);
    }
}
