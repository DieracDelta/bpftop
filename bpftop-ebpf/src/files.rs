//! File iterator eBPF program.
//!
//! Uses `iter/task_file` to walk open file descriptors for each task.
//! For each file, it determines the type (regular, socket, pipe) and
//! extracts relevant information (path, socket addresses, etc.).
//!
//! This is a secondary data source - the main task iterator in main.rs
//! collects process-level info, while this collects per-FD info for
//! network and file details.

// NOTE: This module is compiled as part of the bpftop-ebpf crate but
// the file iterator is a separate BPF program entry point. For now,
// it serves as documentation and a placeholder for the file iterator
// implementation. The actual BPF program will be added when the
// iter/task_file infrastructure is needed.
//
// The task_file iterator is less widely supported than iter/task,
// so we initially rely on /proc/[pid]/fd for file information in
// userspace, and will add this eBPF program when needed for performance.
