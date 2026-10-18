use std::fs;
use std::io::{ErrorKind, Read};

use anyhow::{Context, Result};
use aya::maps::HashMap as BpfHashMap;
use aya::programs::iter::{Iter, IterLink};
use aya::programs::{FExit, KProbe, TracePoint};
use aya::{Btf, Ebpf};
use bpftop_common::{parse_iter_records, CmdlineEvent, IterRecords};

use crate::data::process::display_text;

/// The compiled eBPF object. Built before the userspace crate is compiled.
///
/// Path is relative to this source file:
///   loader.rs  ∈  bpftop/src/ebpf/
///   workspace root = ../../../
///   eBPF object    = bpftop-ebpf-c/target/bpftop.bpf.o
static BPF_OBJ: &[u8] =
    aya::include_bytes_aligned!("../../../bpftop-ebpf-c/target/bpftop.bpf.o");

/// The kernel hands out BPF iterator output in chunks of at most
/// PAGE_SIZE << 3 bytes, so each read() asks for at least that much.
const ITER_READ_CHUNK: usize = 64 * 1024;

/// A kernel function traced for per-process network bytes. It's
/// accounted by `fexit_<func>` where the kernel supports it, else by the
/// kprobe (and optional kretprobe) programs.
struct NetProbe {
    func: &'static str,
    kprobe: &'static str,
    kretprobe: Option<&'static str>,
    /// The IPv6 UDP functions are optional (e.g. ipv6.disable=1).
    required: bool,
}

const NET_PROBES: &[NetProbe] = &[
    NetProbe { func: "tcp_sendmsg", kprobe: "kprobe_tcp_sendmsg", kretprobe: None, required: true },
    NetProbe { func: "udp_sendmsg", kprobe: "kprobe_udp_sendmsg", kretprobe: None, required: true },
    NetProbe { func: "udpv6_sendmsg", kprobe: "kprobe_udpv6_sendmsg", kretprobe: None, required: false },
    NetProbe {
        func: "tcp_recvmsg",
        kprobe: "kprobe_tcp_recvmsg",
        kretprobe: Some("kretprobe_tcp_recvmsg"),
        required: true,
    },
    NetProbe {
        func: "udp_recvmsg",
        kprobe: "kprobe_udp_recvmsg",
        kretprobe: Some("kretprobe_udp_recvmsg"),
        required: true,
    },
    NetProbe {
        func: "udpv6_recvmsg",
        kprobe: "kprobe_udpv6_recvmsg",
        kretprobe: Some("kretprobe_udpv6_recvmsg"),
        required: false,
    },
];

/// How the network accounting programs ended up attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetProbeMode {
    /// BPF trampolines (5.17+; arm64 6.0+). Cheapest per send/recv.
    FExit,
    /// kprobe + kretprobe fallback for kernels without fexit support.
    KProbe,
    /// fexit for some functions, kprobes for others.
    Mixed,
}

/// Manages eBPF program loading, attachment, and data retrieval.
pub struct EbpfLoader {
    bpf: Option<Ebpf>,
    pub net_probe_mode: Option<NetProbeMode>,
    /// Iterator output buffer, reused across cycles.
    iter_buf: Vec<u8>,
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

        // Network accounting: fexit where the kernel supports it, else
        // kprobes, chosen per function. Each function is accounted by
        // exactly one mechanism. BPFTOP_NET_PROBES=kprobe forces kprobes.
        let force_kprobe = std::env::var("BPFTOP_NET_PROBES").is_ok_and(|v| v == "kprobe");
        let net_probe_mode = attach_net_probes(&mut bpf, &btf, force_kprobe)?;

        Ok(Self {
            bpf: Some(bpf),
            net_probe_mode: Some(net_probe_mode),
            iter_buf: Vec::new(),
        })
    }

    /// Create a no-op loader (used as placeholder after moving the real one).
    pub fn noop() -> Self {
        Self { bpf: None, net_probe_mode: None, iter_buf: Vec::new() }
    }

    pub fn is_loaded(&self) -> bool {
        self.bpf.is_some()
    }

    /// Run the task iterator once, returning a TaskInfo per thread-group
    /// leader plus the CPU time of every other live thread.
    ///
    /// Each call creates a new iterator link, reads all output, and
    /// drops the link. The iterator walks every task in the kernel.
    pub fn read_tasks(&mut self) -> Result<IterRecords> {
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

        let buf = &mut self.iter_buf;
        buf.clear();
        loop {
            let len = buf.len();
            buf.resize(len + ITER_READ_CHUNK, 0);
            match file.read(&mut buf[len..]) {
                Ok(0) => {
                    buf.truncate(len);
                    break;
                }
                Ok(n) => buf.truncate(len + n),
                Err(e) if e.kind() == ErrorKind::Interrupted => buf.truncate(len),
                Err(e) => return Err(e).context("reading iterator output"),
            }
        }

        parse_iter_records(buf)
            .map_err(|off| anyhow::anyhow!("truncated iterator record at byte {off} of {}", buf.len()))
    }

    /// Look up a cmdline for a PID from the BPF CMDLINE_MAP, returning the
    /// entry's generation along with it. Entries are capped at 255 bytes;
    /// longer cmdlines are read from /proc (once per exec, since callers
    /// cache by generation).
    pub fn get_cmdline(&self, pid: u32) -> Option<(u64, String)> {
        let bpf = self.bpf.as_ref()?;
        let map = bpf.map("CMDLINE_MAP")?;
        let hash = BpfHashMap::<_, u32, CmdlineEvent>::try_from(map).ok()?;
        let event = hash.get(&pid, 0).ok()?;

        let len = (event.len as usize).min(event.cmdline.len());
        if event.full_len as usize > len {
            if let Some(full) = read_proc_cmdline(pid) {
                return Some((event.gen, full));
            }
        }
        let s = display_text(&event.cmdline[..len]);
        if s.is_empty() {
            None
        } else {
            Some((event.gen, s))
        }
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
            // Exec'd entries use ktime, which is never 1.
            gen: SEEDED_GEN,
            full_len: 0,
            _pad: 0,
        };
        let bytes = cmdline.as_bytes();
        let copy_len = bytes.len().min(255);
        event.cmdline[..copy_len].copy_from_slice(&bytes[..copy_len]);
        event.len = copy_len as u32;
        event.full_len = bytes.len().try_into().unwrap_or(u32::MAX);

        hash.insert(&pid, &event, 0)
            .context("inserting into CMDLINE_MAP")?;
        Ok(())
    }
}

fn attach_net_probes(bpf: &mut Ebpf, btf: &Btf, force_kprobe: bool) -> Result<NetProbeMode> {
    let (mut fexit, mut kprobe) = (0, 0);
    for probe in NET_PROBES {
        let via_fexit = if force_kprobe {
            Err(anyhow::anyhow!("disabled by BPFTOP_NET_PROBES=kprobe"))
        } else {
            attach_fexit(bpf, btf, probe.func)
        };
        let err = match via_fexit {
            Ok(()) => {
                fexit += 1;
                continue;
            }
            Err(e) => e,
        };
        match attach_kprobes(bpf, probe) {
            Ok(()) => {
                log::info!("{}: fexit unavailable ({err:#}); using kprobes", probe.func);
                kprobe += 1;
            }
            Err(e) if !probe.required => {
                log::info!("{}: not traced ({e:#})", probe.func);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(match (fexit, kprobe) {
        (_, 0) => NetProbeMode::FExit,
        (0, _) => NetProbeMode::KProbe,
        _ => NetProbeMode::Mixed,
    })
}

/// Load and attach `fexit_<func>`, unloading it again on failure.
fn attach_fexit(bpf: &mut Ebpf, btf: &Btf, func: &str) -> Result<()> {
    let name = format!("fexit_{func}");
    let prog: &mut FExit = bpf
        .program_mut(&name)
        .with_context(|| format!("{name} not found"))?
        .try_into()
        .with_context(|| format!("{name} is not an FExit"))?;
    let result = prog
        .load(func, btf)
        .with_context(|| format!("loading {name}"))
        .and_then(|()| prog.attach().map(drop).with_context(|| format!("attaching {name}")));
    if result.is_err() {
        let _ = prog.unload();
    }
    result
}

/// Attach the kprobe (and kretprobe, if any) for one function. Partial
/// attachment is undone so an entry probe never runs without its return
/// probe draining RECV_SOCK_STASH.
fn attach_kprobes(bpf: &mut Ebpf, probe: &NetProbe) -> Result<()> {
    let mut attached = Vec::new();
    for prog_name in std::iter::once(probe.kprobe).chain(probe.kretprobe) {
        let prog: &mut KProbe = bpf
            .program_mut(prog_name)
            .with_context(|| format!("{prog_name} not found"))?
            .try_into()
            .with_context(|| format!("{prog_name} is not a KProbe"))?;
        let result = prog
            .load()
            .with_context(|| format!("loading {prog_name}"))
            .and_then(|()| {
                prog.attach(probe.func, 0)
                    .map(drop)
                    .with_context(|| format!("attaching {prog_name} to {}", probe.func))
            });
        if let Err(e) = result {
            let _ = prog.unload();
            for done in attached {
                let prog: Option<&mut KProbe> =
                    bpf.program_mut(done).and_then(|p| p.try_into().ok());
                if let Some(prog) = prog {
                    let _ = prog.unload();
                }
            }
            return Err(e);
        }
        attached.push(prog_name);
    }
    Ok(())
}

/// Generation of CMDLINE_MAP entries seeded from /proc at startup.
pub const SEEDED_GEN: u64 = 1;

fn read_proc_cmdline(pid: u32) -> Option<String> {
    let s = display_text(&fs::read(format!("/proc/{pid}/cmdline")).ok()?);
    (!s.is_empty()).then_some(s)
}

/// One-shot scan of /proc/*/cmdline to seed the CMDLINE_MAP for
/// processes that were already running before the BPF tracepoints
/// were attached. Returns the full (untruncated) cmdlines so the caller
/// can cache them under `SEEDED_GEN`. After this, /proc is only read for
/// cmdlines longer than a map entry, once per exec.
pub fn seed_cmdlines_from_proc(loader: &mut EbpfLoader) -> Vec<(u32, String)> {
    let mut seeded = Vec::new();
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return seeded,
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

        let Some(cmdline) = read_proc_cmdline(pid) else {
            continue;
        };
        if loader.seed_cmdline(pid, &cmdline).is_ok() {
            seeded.push((pid, cmdline));
        }
    }
    seeded
}
