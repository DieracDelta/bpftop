#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_probe_read_kernel, bpf_get_current_pid_tgid},
    macros::iter,
    programs::IterContext,
};
use bpftop_common::TaskInfo;

/// BPF iterator program that walks all tasks in the kernel.
///
/// This attaches to `iter/task` and for each `task_struct` it encounters,
/// it extracts process metadata and writes a `TaskInfo` struct to the
/// seq_file output. Userspace reads this via the BPF link's seq file.
#[iter(name = "dump_task")]
pub fn dump_task(ctx: IterContext) -> i32 {
    match try_dump_task(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

/// Inner function for the task iterator. Returns 0 to continue iteration,
/// 1 to stop.
///
/// # Safety
/// Accesses raw kernel pointers via bpf_probe_read_kernel. The BPF verifier
/// ensures memory safety of these accesses at load time.
unsafe fn try_dump_task(ctx: &IterContext) -> Result<i32, i64> {
    // The iterator provides a pointer to the current task_struct.
    // A null pointer signals end of iteration.
    let task_ptr = ctx.ctx as *const u8;
    if task_ptr.is_null() {
        return Ok(1);
    }

    // Read fields from task_struct using CO-RE compatible offsets.
    // These offsets are for a typical 6.x kernel - CO-RE relocations
    // handle differences across kernel versions.

    // task_struct field offsets (these are approximate and will be
    // fixed by CO-RE relocations at load time):
    // pid (tid) is at a well-known offset
    // tgid (pid) follows pid
    // For safety, we read the full task_struct pointer and extract fields.

    let task = task_ptr as *const TaskStruct;

    let pid = bpf_probe_read_kernel(&(*task).tgid).unwrap_or(0) as u32;
    let tid = bpf_probe_read_kernel(&(*task).pid).unwrap_or(0) as u32;

    // Read parent pointer and then ppid from it
    let parent_ptr = bpf_probe_read_kernel(&(*task).parent).unwrap_or(core::ptr::null());
    let ppid = if !parent_ptr.is_null() {
        bpf_probe_read_kernel(&(*parent_ptr).tgid).unwrap_or(0) as u32
    } else {
        0
    };

    // Read credentials
    let cred_ptr = bpf_probe_read_kernel(&(*task).cred).unwrap_or(core::ptr::null());
    let (euid, ruid) = if !cred_ptr.is_null() {
        let euid = bpf_probe_read_kernel(&(*cred_ptr).euid).unwrap_or(0);
        let ruid = bpf_probe_read_kernel(&(*cred_ptr).uid).unwrap_or(0);
        (euid, ruid)
    } else {
        (0, 0)
    };

    // Read task state
    let state = bpf_probe_read_kernel(&(*task).__state).unwrap_or(0) as u8;

    // Read CPU times (in nanoseconds)
    let utime = bpf_probe_read_kernel(&(*task).utime).unwrap_or(0);
    let stime = bpf_probe_read_kernel(&(*task).stime).unwrap_or(0);

    // Read memory info from mm_struct
    let mm_ptr = bpf_probe_read_kernel(&(*task).mm).unwrap_or(core::ptr::null());
    let (vsize, rss_pages) = if !mm_ptr.is_null() {
        let total_vm = bpf_probe_read_kernel(&(*mm_ptr).total_vm).unwrap_or(0);
        // RSS = file_pages + anon_pages + shmem_pages from mm_rss_stat
        // For simplicity, we read the counter array
        let file_pages = bpf_probe_read_kernel(&(*mm_ptr).rss_stat_file).unwrap_or(0) as u64;
        let anon_pages = bpf_probe_read_kernel(&(*mm_ptr).rss_stat_anon).unwrap_or(0) as u64;
        let vsize_bytes = total_vm * 4096; // pages to bytes
        (vsize_bytes, file_pages + anon_pages)
    } else {
        (0, 0)
    };

    // Read start_time
    let start_time = bpf_probe_read_kernel(&(*task).start_time).unwrap_or(0);

    // Read comm (process name)
    let mut comm = [0u8; 16];
    let comm_src = bpf_probe_read_kernel(&(*task).comm).unwrap_or([0u8; 16]);
    comm.copy_from_slice(&comm_src);

    let info = TaskInfo {
        pid,
        tid,
        ppid,
        euid,
        ruid,
        state,
        _pad: [0; 3],
        utime_ns: utime,
        stime_ns: stime,
        vsize_bytes: vsize,
        rss_pages,
        start_time_ns: start_time,
        comm,
    };

    // Write the struct to the seq_file output
    let ptr = &info as *const TaskInfo as *const u8;
    let size = core::mem::size_of::<TaskInfo>() as u32;
    let ret = aya_bpf::helpers::gen::bpf_seq_write(
        ctx.seq as *mut _,
        ptr as *const _,
        size,
    );
    if ret < 0 {
        return Ok(0);
    }

    Ok(0)
}

/// Minimal representation of task_struct fields we need.
/// CO-RE relocations adjust the actual offsets at load time.
#[repr(C)]
struct TaskStruct {
    // We only define the fields we access. The BPF CO-RE mechanism
    // will relocate field accesses to the correct offsets for the
    // running kernel. These are placeholder layouts.
    _pad0: [u8; 0],
    pub __state: u32,
    _pad1: [u8; 0],
    pub pid: i32,     // This is the thread ID (tid)
    pub tgid: i32,    // This is the process ID (pid)
    _pad2: [u8; 0],
    pub parent: *const TaskStruct,
    _pad3: [u8; 0],
    pub mm: *const MmStruct,
    _pad4: [u8; 0],
    pub cred: *const Cred,
    _pad5: [u8; 0],
    pub utime: u64,
    pub stime: u64,
    pub start_time: u64,
    _pad6: [u8; 0],
    pub comm: [u8; 16],
}

#[repr(C)]
struct MmStruct {
    _pad0: [u8; 0],
    pub total_vm: u64,
    pub rss_stat_file: i64,
    pub rss_stat_anon: i64,
}

#[repr(C)]
struct Cred {
    _pad0: [u8; 0],
    pub uid: u32,
    pub euid: u32,
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
