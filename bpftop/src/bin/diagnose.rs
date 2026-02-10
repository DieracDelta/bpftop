//! Diagnostic binary for the BPF process monitoring pipeline.
//!
//! Exercises each step of the BPF loading pipeline independently,
//! printing PASS/FAIL with full error details to stdout/stderr.
//!
//! Run: sudo ./target/release/diagnose

use std::io::Read;

use aya::maps::HashMap as BpfHashMap;
use aya::programs::iter::{Iter, IterLink};
use aya::programs::TracePoint;
use aya::{Btf, Ebpf};
use bpftop_common::{CmdlineEvent, TaskInfo};

/// Path relative to this file (src/bin/diagnose.rs):
///   ../../../../bpftop-ebpf/target/bpfel-unknown-none/release/bpftop-ebpf
static BPF_OBJ: &[u8] =
    aya::include_bytes_aligned!("../../../bpftop-ebpf/target/bpfel-unknown-none/release/bpftop-ebpf");

fn main() {
    let mut pass = 0u32;
    let mut fail = 0u32;
    let total = 10u32;

    println!("=== BPF Pipeline Diagnostic ===\n");

    // ── Step 1: Validate eBPF ELF binary ──────────────────────
    print_step(1, "Validate eBPF ELF binary");
    let step1 = validate_elf();
    report(&step1, &mut pass, &mut fail);

    // ── Step 2: Ebpf::load ────────────────────────────────────
    print_step(2, "Ebpf::load(BPF_OBJ)");
    let mut bpf = match Ebpf::load(BPF_OBJ) {
        Ok(b) => {
            report(&Ok("loaded successfully".into()), &mut pass, &mut fail);
            b
        }
        Err(e) => {
            // Print full error chain for debugging
            println!("  Error (Display): {e}");
            println!("  Error (Debug):   {e:?}");
            println!("  Error (Alt):     {e:#}");
            let mut source = std::error::Error::source(&e);
            let mut depth = 1;
            while let Some(s) = source {
                println!("  Caused by [{depth}]: {s}");
                println!("  Caused by [{depth}] (Debug): {s:?}");
                source = std::error::Error::source(s);
                depth += 1;
            }
            report(&Err::<String, _>(format!("{e:#}")), &mut pass, &mut fail);
            summary(pass, fail, total);
            return;
        }
    };

    // Enumerate all programs in the ELF
    println!("  Programs in ELF:");
    for (name, prog) in bpf.programs() {
        println!("    {name:30} type={:?}", prog.prog_type());
    }
    println!("  Maps in ELF:");
    for (name, _map) in bpf.maps() {
        println!("    {name}");
    }
    println!();

    // ── Step 3: Btf::from_sys_fs ─────────────────────────────
    print_step(3, "Btf::from_sys_fs()");
    let btf = match Btf::from_sys_fs() {
        Ok(b) => {
            report(&Ok("kernel BTF loaded".into()), &mut pass, &mut fail);
            b
        }
        Err(e) => {
            report(&Err::<String, _>(format!("{e:#}")), &mut pass, &mut fail);
            summary(pass, fail, total);
            return;
        }
    };

    // ── Step 4: Find dump_task program ────────────────────────
    print_step(4, "Find dump_task iter program");
    match bpf.program("dump_task") {
        Some(prog) => {
            report(
                &Ok(format!("found, type={:?}", prog.prog_type())),
                &mut pass,
                &mut fail,
            );
        }
        None => {
            report(
                &Err::<String, _>("dump_task NOT FOUND in programs".into()),
                &mut pass,
                &mut fail,
            );
            println!("  Available programs:");
            for (name, prog) in bpf.programs() {
                println!("    {name:30} type={:?}", prog.prog_type());
            }
            summary(pass, fail, total);
            return;
        }
    }

    // ── Step 5: Load dump_task (BPF verifier) ─────────────────
    print_step(5, "iter_prog.load(\"task\", &btf) — BPF verifier");
    let step5 = (|| -> Result<String, String> {
        let iter_prog: &mut Iter = bpf
            .program_mut("dump_task")
            .ok_or("dump_task not found")?
            .try_into()
            .map_err(|e| format!("not an Iter: {e}"))?;
        iter_prog
            .load("task", &btf)
            .map_err(|e| format!("verifier rejected: {e:#}"))?;
        Ok("verifier PASSED".into())
    })();
    report(&step5, &mut pass, &mut fail);
    if step5.is_err() {
        summary(pass, fail, total);
        return;
    }

    // ── Step 6: Load+attach capture_cmdline ───────────────────
    print_step(6, "Load+attach capture_cmdline tracepoint");
    let step6 = (|| -> Result<String, String> {
        let prog: &mut TracePoint = bpf
            .program_mut("capture_cmdline")
            .ok_or("capture_cmdline not found")?
            .try_into()
            .map_err(|e| format!("not a TracePoint: {e}"))?;
        prog.load().map_err(|e| format!("load: {e:#}"))?;
        prog.attach("sched", "sched_process_exec")
            .map_err(|e| format!("attach: {e:#}"))?;
        Ok("loaded and attached".into())
    })();
    report(&step6, &mut pass, &mut fail);

    // ── Step 7: Load+attach cleanup_cmdline ───────────────────
    print_step(7, "Load+attach cleanup_cmdline tracepoint");
    let step7 = (|| -> Result<String, String> {
        let prog: &mut TracePoint = bpf
            .program_mut("cleanup_cmdline")
            .ok_or("cleanup_cmdline not found")?
            .try_into()
            .map_err(|e| format!("not a TracePoint: {e}"))?;
        prog.load().map_err(|e| format!("load: {e:#}"))?;
        prog.attach("sched", "sched_process_exit")
            .map_err(|e| format!("attach: {e:#}"))?;
        Ok("loaded and attached".into())
    })();
    report(&step7, &mut pass, &mut fail);

    // ── Step 8: Run iterator ──────────────────────────────────
    print_step(8, "Run iterator: attach → into_file → read_to_end");
    let buf = match run_iterator(&mut bpf) {
        Ok(buf) => {
            report(
                &Ok(format!("{} bytes read", buf.len())),
                &mut pass,
                &mut fail,
            );
            buf
        }
        Err(e) => {
            report(&Err::<String, _>(e), &mut pass, &mut fail);
            summary(pass, fail, total);
            return;
        }
    };

    if buf.is_empty() {
        println!("  WARN: 0 bytes — bpf_seq_write is likely failing");
        println!("  This usually means IterTaskCtx/IterMeta struct layout doesn't match kernel");
        println!("  Check that seq pointer is correctly extracted from the context");
        fail += 1; // count as failure for remaining steps
        summary(pass, fail, total);
        return;
    }

    // ── Step 9: Validate TaskInfo struct alignment ────────────
    print_step(9, "Validate TaskInfo struct alignment");
    let task_size = std::mem::size_of::<TaskInfo>();
    let count = buf.len() / task_size;
    let remainder = buf.len() % task_size;
    println!("  TaskInfo size (userspace): {} bytes", task_size);
    println!("  Total bytes from iterator: {}", buf.len());
    println!("  Task count: {count}");
    println!("  Remainder bytes: {remainder}");
    if remainder != 0 {
        report(
            &Err::<String, _>(format!(
                "BPF-side TaskInfo size differs! remainder={remainder} (BPF writes different size)"
            )),
            &mut pass,
            &mut fail,
        );
    } else if count == 0 {
        report(
            &Err::<String, _>("0 tasks parsed despite non-zero bytes".into()),
            &mut pass,
            &mut fail,
        );
    } else {
        report(
            &Ok(format!("{count} tasks, alignment OK")),
            &mut pass,
            &mut fail,
        );
    }

    // ── Step 10: Validate sample data ─────────────────────────
    print_step(10, "Validate sample data");
    let tasks: Vec<TaskInfo> = buf
        .chunks_exact(task_size)
        .map(|chunk| unsafe { std::ptr::read_unaligned(chunk.as_ptr() as *const TaskInfo) })
        .collect();

    // Show first 20 tasks
    println!("  Sample tasks (first 20):");
    for task in tasks.iter().take(20) {
        let comm = comm_str(&task.comm);
        println!(
            "    PID={:<6} TID={:<6} PPID={:<6} EUID={:<6} state={} prio={:<4} rss={:<8} comm={}",
            task.pid, task.tid, task.ppid, task.euid, task.state, task.prio, task.rss_pages, comm
        );
    }

    // Stats
    let total_tasks = tasks.len();
    let unique_pids: std::collections::HashSet<u32> = tasks.iter().map(|t| t.pid).collect();
    let nonzero_pids = tasks.iter().filter(|t| t.pid != 0).count();
    let nonzero_comm = tasks
        .iter()
        .filter(|t| t.comm.iter().any(|&b| b != 0))
        .count();
    let nonzero_rss = tasks.iter().filter(|t| t.rss_pages > 0).count();
    let zero_everything = tasks
        .iter()
        .filter(|t| t.pid == 0 && t.tid == 0 && t.ppid == 0 && t.comm == [0u8; 16])
        .count();

    println!("\n  Statistics:");
    println!("    Total tasks (including threads): {total_tasks}");
    println!("    Unique PIDs: {}", unique_pids.len());
    println!("    Non-zero PIDs: {nonzero_pids}");
    println!("    Non-zero comm: {nonzero_comm}");
    println!("    Non-zero RSS: {nonzero_rss}");
    println!("    All-zero entries: {zero_everything}");

    // Cross-check with /proc
    let proc_count = count_proc_pids();
    println!("    /proc PID count: {proc_count}");
    println!(
        "    BPF unique PIDs: {} (ratio: {:.1}x)",
        unique_pids.len(),
        unique_pids.len() as f64 / proc_count.max(1) as f64
    );

    if zero_everything == total_tasks {
        report(
            &Err::<String, _>(
                "ALL entries are zeros — task pointer offset is wrong in IterTaskCtx".into(),
            ),
            &mut pass,
            &mut fail,
        );
    } else if nonzero_comm == 0 {
        report(
            &Err::<String, _>(
                "All comms are empty — TASK_COMM offset is likely wrong".into(),
            ),
            &mut pass,
            &mut fail,
        );
    } else if nonzero_pids < total_tasks / 2 {
        report(
            &Err::<String, _>(format!(
                "Only {nonzero_pids}/{total_tasks} have non-zero PIDs — check field offsets"
            )),
            &mut pass,
            &mut fail,
        );
    } else {
        report(
            &Ok(format!(
                "data looks valid: {nonzero_pids} tasks with PIDs, {nonzero_comm} with comms"
            )),
            &mut pass,
            &mut fail,
        );
    }

    // ── Bonus: Check CMDLINE_MAP ──────────────────────────────
    println!("\n--- CMDLINE_MAP check ---");
    check_cmdline_map(&bpf);

    println!();
    summary(pass, fail, total);
}

fn validate_elf() -> Result<String, String> {
    let size = BPF_OBJ.len();
    if size < 16 {
        return Err(format!("eBPF binary too small: {size} bytes"));
    }
    // ELF magic: 0x7f 'E' 'L' 'F'
    if &BPF_OBJ[0..4] != b"\x7fELF" {
        return Err(format!(
            "Not an ELF: magic={:02x} {:02x} {:02x} {:02x}",
            BPF_OBJ[0], BPF_OBJ[1], BPF_OBJ[2], BPF_OBJ[3]
        ));
    }
    Ok(format!("valid ELF, {size} bytes"))
}

fn run_iterator(bpf: &mut Ebpf) -> Result<Vec<u8>, String> {
    let prog: &mut Iter = bpf
        .program_mut("dump_task")
        .ok_or("dump_task not found")?
        .try_into()
        .map_err(|e| format!("not an Iter: {e}"))?;

    let link_id = prog
        .attach()
        .map_err(|e| format!("attach: {e:#}"))?;
    let link: IterLink = prog
        .take_link(link_id)
        .map_err(|e| format!("take_link: {e:#}"))?;
    let mut file = link
        .into_file()
        .map_err(|e| format!("into_file: {e:#}"))?;

    let mut buf = Vec::with_capacity(64 * 1024);
    file.read_to_end(&mut buf)
        .map_err(|e| format!("read_to_end: {e:#}"))?;
    Ok(buf)
}

fn check_cmdline_map(bpf: &Ebpf) {
    match bpf.map("CMDLINE_MAP") {
        Some(map) => {
            match BpfHashMap::<_, u32, CmdlineEvent>::try_from(map) {
                Ok(hash) => {
                    let mut count = 0;
                    let mut shown = 0;
                    for item in hash.iter() {
                        if let Ok((pid, event)) = item {
                            count += 1;
                            if shown < 5 {
                                let len = (event.len as usize).min(event.cmdline.len());
                                let cmdline = String::from_utf8_lossy(&event.cmdline[..len])
                                    .replace('\0', " ");
                                println!("  PID={pid:<6} cmdline={}", cmdline.trim());
                                shown += 1;
                            }
                        }
                    }
                    println!("  Total CMDLINE_MAP entries: {count}");
                    if count == 0 {
                        println!("  (empty — tracepoints may not have fired yet, try running a command first)");
                    }
                }
                Err(e) => println!("  ERROR: cannot read CMDLINE_MAP: {e}"),
            }
        }
        None => println!("  CMDLINE_MAP not found in BPF object"),
    }
}

fn comm_str(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&comm[..end]).to_string()
}

fn count_proc_pids() -> usize {
    std::fs::read_dir("/proc")
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .map(|s| s.chars().all(|c| c.is_ascii_digit()))
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

fn print_step(n: u32, desc: &str) {
    println!("[Step {n:>2}] {desc}");
}

fn report(result: &Result<String, String>, pass: &mut u32, fail: &mut u32) {
    match result {
        Ok(msg) => {
            println!("  ✓ PASS: {msg}\n");
            *pass += 1;
        }
        Err(msg) => {
            println!("  ✗ FAIL: {msg}\n");
            *fail += 1;
        }
    }
}

fn summary(pass: u32, fail: u32, total: u32) {
    println!("=== Summary: {pass}/{total} passed, {fail} failed ===");
    if fail > 0 {
        std::process::exit(1);
    }
}
