#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel},
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::HashMap,
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use bpftop_common::{CmdlineEvent, NetStats, TaskInfo};

// ============================================================
// Kernel struct field byte offsets (Linux 6.12, from BTF)
// ============================================================
//
// Generated from: pahole -C <struct> /sys/kernel/btf/vmlinux
// These are NOT portable across kernel versions. Without CO-RE
// support in aya-ebpf, we must regenerate if the kernel changes.
//
// Build with --features arch-x86_64 or --features arch-aarch64.

#[cfg(not(any(feature = "arch-x86_64", feature = "arch-aarch64")))]
compile_error!("must enable exactly one of: arch-x86_64, arch-aarch64");

// --- task_struct offsets ---

// Fields at identical offsets on both architectures (Linux 6.12):
const TASK_STATE: usize = 24;       // __state: u32
const TASK_PRIO: usize = 124;       // prio: i32
const TASK_STATIC_PRIO: usize = 128; // static_prio: i32

#[cfg(feature = "arch-x86_64")]
mod offsets {
    // task_struct
    pub const TASK_MM: usize = 1712;
    pub const TASK_PID: usize = 1840;
    pub const TASK_TGID: usize = 1844;
    pub const TASK_REAL_PARENT: usize = 1856;
    pub const TASK_UTIME: usize = 2064;
    pub const TASK_STIME: usize = 2072;
    pub const TASK_START_TIME: usize = 2184;
    pub const TASK_CRED: usize = 2368;
    pub const TASK_COMM: usize = 2384;
    pub const TASK_CGROUPS: usize = 2872;
    // mm_struct (rss_stat is percpu_counter[4]; each 40 bytes, count at +8)
    pub const MM_TOTAL_VM: usize = 248;
    pub const MM_ARG_START: usize = 368;
    pub const MM_ARG_END: usize = 376;
    pub const MM_RSS_FILE_COUNT: usize = 824;  // rss_stat[0].count
    pub const MM_RSS_ANON_COUNT: usize = 864;  // rss_stat[1].count
    pub const MM_RSS_SHMEM_COUNT: usize = 944; // rss_stat[3].count
    // css_set
    pub const CSS_SET_DFL_CGRP: usize = 136;
}

#[cfg(feature = "arch-aarch64")]
mod offsets {
    // task_struct
    pub const TASK_MM: usize = 1616;
    pub const TASK_PID: usize = 1744;
    pub const TASK_TGID: usize = 1748;
    pub const TASK_REAL_PARENT: usize = 1760;
    pub const TASK_UTIME: usize = 1968;
    pub const TASK_STIME: usize = 1976;
    pub const TASK_START_TIME: usize = 2088;
    pub const TASK_CRED: usize = 2272;
    pub const TASK_COMM: usize = 2288;
    pub const TASK_CGROUPS: usize = 2744;
    // mm_struct (rss_stat is percpu_counter[4]; each 40 bytes, count at +8)
    pub const MM_TOTAL_VM: usize = 232;
    pub const MM_ARG_START: usize = 352;
    pub const MM_ARG_END: usize = 360;
    pub const MM_RSS_FILE_COUNT: usize = 792;  // rss_stat[0].count
    pub const MM_RSS_ANON_COUNT: usize = 832;  // rss_stat[1].count
    pub const MM_RSS_SHMEM_COUNT: usize = 912; // rss_stat[3].count
    // css_set
    pub const CSS_SET_DFL_CGRP: usize = 120;
}

use offsets::*;

// cred (same on both architectures)
const CRED_UID: usize = 8;          // uid: kuid_t
const CRED_EUID: usize = 24;        // euid: kuid_t

// cgroup (same on both architectures)
const CGROUP_KN: usize = 256;       // kn: *kernfs_node

// kernfs_node (same on both architectures)
const KN_ID: usize = 96;            // id: u64

// --- network struct offsets (same on both architectures, Linux 6.12) ---
const SOCK_DST_CACHE: usize = 528;  // sock.sk_dst_cache: *dst_entry
const SOCK_BOUND_DEV_IF: usize = 20; // sock.__sk_common.skc_bound_dev_if: i32
const DST_DEV: usize = 0;           // dst_entry.dev: *net_device
const NETDEV_IFINDEX: usize = 224;  // net_device.ifindex: i32

// ============================================================
// Helper: read a kernel field at a fixed byte offset
// ============================================================

#[inline(always)]
unsafe fn read_field<T: Copy>(base: *const u8, offset: usize) -> Result<T, i64> {
    bpf_probe_read_kernel(base.add(offset) as *const T)
}

// ============================================================
// BPF Iterator: iter/task
// ============================================================

/// Matches kernel `struct bpf_iter_meta`.
#[repr(C)]
struct IterMeta {
    seq: *mut core::ffi::c_void,
}

/// Matches kernel `struct bpf_iter__task`.
#[repr(C)]
pub struct IterTaskCtx {
    meta: *mut IterMeta,
    task: *const u8,
}

#[no_mangle]
#[link_section = "iter/task"]
pub fn dump_task(ctx: *mut IterTaskCtx) -> i32 {
    unsafe { try_dump_task(ctx).unwrap_or(0) }
}

unsafe fn try_dump_task(ctx: *mut IterTaskCtx) -> Result<i32, i64> {
    let task = (*ctx).task;
    if task.is_null() {
        return Ok(1);
    }
    let seq = (*(*ctx).meta).seq;

    let tgid: i32 = read_field(task, TASK_TGID).unwrap_or(0);
    let tid: i32 = read_field(task, TASK_PID).unwrap_or(0);
    let pid = tgid as u32;

    // Parent PID
    let parent_ptr: *const u8 = read_field(task, TASK_REAL_PARENT).unwrap_or(core::ptr::null());
    let ppid = if !parent_ptr.is_null() {
        read_field::<i32>(parent_ptr, TASK_TGID).unwrap_or(0) as u32
    } else {
        0
    };

    // Credentials
    let cred_ptr: *const u8 = read_field(task, TASK_CRED).unwrap_or(core::ptr::null());
    let (euid, ruid) = if !cred_ptr.is_null() {
        let euid: u32 = read_field(cred_ptr, CRED_EUID).unwrap_or(0);
        let ruid: u32 = read_field(cred_ptr, CRED_UID).unwrap_or(0);
        (euid, ruid)
    } else {
        (0, 0)
    };

    // Task state
    let state: u32 = read_field(task, TASK_STATE).unwrap_or(0);

    // CPU times (nanoseconds)
    let utime: u64 = read_field(task, TASK_UTIME).unwrap_or(0);
    let stime: u64 = read_field(task, TASK_STIME).unwrap_or(0);

    // Priority
    let prio: i32 = read_field(task, TASK_PRIO).unwrap_or(120);
    let static_prio: i32 = read_field(task, TASK_STATIC_PRIO).unwrap_or(120);

    // Memory info
    let mm_ptr: *const u8 = read_field(task, TASK_MM).unwrap_or(core::ptr::null());
    let (vsize, rss_pages, shmem_pages) = if !mm_ptr.is_null() {
        let total_vm: u64 = read_field(mm_ptr, MM_TOTAL_VM).unwrap_or(0);
        let file_count: i64 = read_field(mm_ptr, MM_RSS_FILE_COUNT).unwrap_or(0);
        let anon_count: i64 = read_field(mm_ptr, MM_RSS_ANON_COUNT).unwrap_or(0);
        let shmem_count: i64 = read_field(mm_ptr, MM_RSS_SHMEM_COUNT).unwrap_or(0);
        let vsize_bytes = total_vm * 4096;
        // percpu_counter.count can be slightly negative due to per-cpu batching
        let rss = (file_count.max(0) + anon_count.max(0)) as u64;
        let shmem = shmem_count.max(0) as u64;
        (vsize_bytes, rss, shmem)
    } else {
        (0, 0, 0)
    };

    // Start time
    let start_time: u64 = read_field(task, TASK_START_TIME).unwrap_or(0);

    // Comm
    let comm: [u8; 16] = read_field(task, TASK_COMM).unwrap_or([0u8; 16]);

    // Cgroup ID: task->cgroups->dfl_cgrp->kn->id
    let cgroup_id = read_cgroup_id(task).unwrap_or(0);

    let info = TaskInfo {
        pid,
        tid: tid as u32,
        ppid,
        euid,
        ruid,
        state: state as u8,
        _pad: [0; 3],
        utime_ns: utime,
        stime_ns: stime,
        vsize_bytes: vsize,
        rss_pages,
        start_time_ns: start_time,
        comm,
        prio,
        static_prio,
        shmem_pages,
        cgroup_id,
    };

    // Write the struct to the seq_file output
    let ptr = &info as *const TaskInfo as *const u8;
    let size = core::mem::size_of::<TaskInfo>() as u32;
    aya_ebpf::helpers::bpf_seq_write(seq as *mut _, ptr as *const _, size);

    Ok(0)
}

/// Read the default cgroup2 inode ID from task->cgroups->dfl_cgrp->kn->id.
unsafe fn read_cgroup_id(task: *const u8) -> Result<u64, i64> {
    let css_set: *const u8 = read_field(task, TASK_CGROUPS)?;
    if css_set.is_null() {
        return Ok(0);
    }
    let cgrp: *const u8 = read_field(css_set, CSS_SET_DFL_CGRP)?;
    if cgrp.is_null() {
        return Ok(0);
    }
    let kn: *const u8 = read_field(cgrp, CGROUP_KN)?;
    if kn.is_null() {
        return Ok(0);
    }
    let id: u64 = read_field(kn, KN_ID)?;
    Ok(id)
}

// ============================================================
// Tracepoints + CMDLINE_MAP
// ============================================================

#[map]
static CMDLINE_MAP: HashMap<u32, CmdlineEvent> = HashMap::with_max_entries(32768, 0);

/// Capture cmdline at exec time. The new mm->arg_start..arg_end
/// contains the argv of the newly exec'd process.
#[tracepoint(category = "sched", name = "sched_process_exec")]
pub fn capture_cmdline(_ctx: TracePointContext) -> i32 {
    unsafe { try_capture_cmdline().unwrap_or(0) }
}

unsafe fn try_capture_cmdline() -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let task = bpf_get_current_task() as *const u8;
    let mm: *const u8 = read_field(task, TASK_MM).map_err(|_| -1i64)?;
    if mm.is_null() {
        return Ok(0);
    }
    let arg_start: u64 = read_field(mm, MM_ARG_START).map_err(|_| -1i64)?;
    let arg_end: u64 = read_field(mm, MM_ARG_END).map_err(|_| -1i64)?;

    if arg_start == 0 || arg_end <= arg_start {
        return Ok(0);
    }

    let mut event = CmdlineEvent {
        pid,
        len: 0,
        cmdline: [0u8; 256],
    };

    let max_len = ((arg_end - arg_start) as usize).min(255);
    match aya_ebpf::helpers::bpf_probe_read_user_str_bytes(
        arg_start as *const u8,
        &mut event.cmdline[..max_len],
    ) {
        Ok(bytes) => event.len = bytes.len() as u32,
        Err(_) => {}
    }

    CMDLINE_MAP.insert(&pid, &event, 0).map_err(|_| -1i64)?;
    Ok(0)
}

/// Clean up CMDLINE_MAP and NET_STATS entries when a process exits.
#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn cleanup_cmdline(_ctx: TracePointContext) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = CMDLINE_MAP.remove(&pid);
    let _ = NET_STATS.remove(&pid);
    0
}

// ============================================================
// Network kprobes + NET_STATS map
// ============================================================

#[map]
static NET_STATS: HashMap<u32, NetStats> = HashMap::with_max_entries(32768, 0);

/// Read the interface index from a sock's cached route destination.
/// Falls back to sk_bound_dev_if if sk_dst_cache is NULL.
/// Returns 0 if both are unavailable.
#[inline(always)]
unsafe fn read_sock_ifindex(sk: *const u8) -> u32 {
    // Try sk->sk_dst_cache->dev->ifindex
    let dst: *const u8 = read_field(sk, SOCK_DST_CACHE).unwrap_or(core::ptr::null());
    if !dst.is_null() {
        let dev: *const u8 = read_field(dst, DST_DEV).unwrap_or(core::ptr::null());
        if !dev.is_null() {
            let ifidx: i32 = read_field(dev, NETDEV_IFINDEX).unwrap_or(0);
            if ifidx > 0 {
                return ifidx as u32;
            }
        }
    }
    // Fallback: sk->__sk_common.skc_bound_dev_if
    let bound: i32 = read_field(sk, SOCK_BOUND_DEV_IF).unwrap_or(0);
    if bound > 0 { bound as u32 } else { 0 }
}

/// Update NET_STATS for the current pid, adding tx_bytes.
#[inline(always)]
unsafe fn account_tx(size: u64, sk: *const u8) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let ifindex = read_sock_ifindex(sk);

    match NET_STATS.get_ptr_mut(&pid) {
        Some(stats) => {
            (*stats).tx_bytes += size;
            if ifindex != 0 {
                (*stats).ifindex = ifindex;
            }
        }
        None => {
            let stats = NetStats {
                tx_bytes: size,
                rx_bytes: 0,
                ifindex,
                _pad: 0,
            };
            let _ = NET_STATS.insert(&pid, &stats, 0);
        }
    }
}

/// Update NET_STATS for the current pid, adding rx_bytes + ifindex from stashed sock.
#[inline(always)]
unsafe fn account_rx(size: u64, sk: *const u8) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let ifindex = if !sk.is_null() {
        read_sock_ifindex(sk)
    } else {
        0
    };

    match NET_STATS.get_ptr_mut(&pid) {
        Some(stats) => {
            (*stats).rx_bytes += size;
            if ifindex != 0 {
                (*stats).ifindex = ifindex;
            }
        }
        None => {
            let stats = NetStats {
                tx_bytes: 0,
                rx_bytes: size,
                ifindex,
                _pad: 0,
            };
            let _ = NET_STATS.insert(&pid, &stats, 0);
        }
    }
}

/// Stash map: pid_tgid -> sock pointer, used to pass sock from kprobe entry to kretprobe.
#[map]
static RECV_SOCK_STASH: HashMap<u64, u64> = HashMap::with_max_entries(8192, 0);

// --- TCP ---

#[kprobe]
pub fn kprobe_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    unsafe { try_tcp_sendmsg(&ctx).unwrap_or(0) }
}

unsafe fn try_tcp_sendmsg(ctx: &ProbeContext) -> Result<u32, i64> {
    // tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
    let sk: *const u8 = ctx.arg(0).ok_or(-1i64)?;
    let size: u64 = ctx.arg(2).ok_or(-1i64)?;
    account_tx(size, sk);
    Ok(0)
}

/// Stash sock pointer on tcp_recvmsg entry for the kretprobe to read.
#[kprobe]
pub fn kprobe_tcp_recvmsg(ctx: ProbeContext) -> u32 {
    unsafe { try_stash_recv_sock(&ctx).unwrap_or(0) }
}

#[kretprobe]
pub fn kretprobe_tcp_recvmsg(ctx: RetProbeContext) -> u32 {
    unsafe { try_tcp_recvmsg(&ctx).unwrap_or(0) }
}

unsafe fn try_tcp_recvmsg(ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let sk = pop_recv_sock(pid_tgid);
    // tcp_recvmsg returns int (32-bit); upper 32 bits of rax may be garbage
    let ret: i32 = ctx.ret();
    if ret > 0 {
        account_rx(ret as u64, sk as *const u8);
    }
    Ok(0)
}

// --- UDP ---

#[kprobe]
pub fn kprobe_udp_sendmsg(ctx: ProbeContext) -> u32 {
    unsafe { try_udp_sendmsg(&ctx).unwrap_or(0) }
}

unsafe fn try_udp_sendmsg(ctx: &ProbeContext) -> Result<u32, i64> {
    // udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
    let sk: *const u8 = ctx.arg(0).ok_or(-1i64)?;
    let size: u64 = ctx.arg(2).ok_or(-1i64)?;
    account_tx(size, sk);
    Ok(0)
}

/// Stash sock pointer on udp_recvmsg entry for the kretprobe to read.
#[kprobe]
pub fn kprobe_udp_recvmsg(ctx: ProbeContext) -> u32 {
    unsafe { try_stash_recv_sock(&ctx).unwrap_or(0) }
}

#[kretprobe]
pub fn kretprobe_udp_recvmsg(ctx: RetProbeContext) -> u32 {
    unsafe { try_udp_recvmsg(&ctx).unwrap_or(0) }
}

unsafe fn try_udp_recvmsg(ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let sk = pop_recv_sock(pid_tgid);
    // udp_recvmsg returns int (32-bit); upper 32 bits of rax may be garbage
    let ret: i32 = ctx.ret();
    if ret > 0 {
        account_rx(ret as u64, sk as *const u8);
    }
    Ok(0)
}

/// Shared: stash sock pointer (arg0) keyed by pid_tgid for kretprobe to retrieve.
unsafe fn try_stash_recv_sock(ctx: &ProbeContext) -> Result<u32, i64> {
    let sk: u64 = ctx.arg(0).ok_or(-1i64)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = RECV_SOCK_STASH.insert(&pid_tgid, &sk, 0);
    Ok(0)
}

/// Pop the stashed sock pointer for this pid_tgid (removes from map).
unsafe fn pop_recv_sock(pid_tgid: u64) -> u64 {
    let sk = RECV_SOCK_STASH
        .get(&pid_tgid)
        .copied()
        .unwrap_or(0);
    let _ = RECV_SOCK_STASH.remove(&pid_tgid);
    sk
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
