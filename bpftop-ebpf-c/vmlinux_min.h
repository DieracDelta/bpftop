#ifndef BPFTOP_VMLINUX_MIN_H
#define BPFTOP_VMLINUX_MIN_H

typedef signed char s8;
typedef short s16;
typedef int s32;
typedef long long s64;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned long size_t;

typedef unsigned short __be16;
typedef unsigned int __be32;
typedef unsigned int __wsum;

typedef s32 pid_t;
typedef _Bool bool;

typedef struct {
	int counter;
} atomic_t;

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef struct {
	u32 val;
} kuid_t;

struct cred {
	kuid_t uid;
	kuid_t gid;
	kuid_t suid;
	kuid_t sgid;
	kuid_t euid;
};

struct percpu_counter {
	s64 count;
};

struct mm_struct {
	unsigned long total_vm;
	unsigned long arg_start;
	unsigned long arg_end;
	struct percpu_counter rss_stat[4];
};

struct kernfs_node {
	u64 id;
};

struct cgroup_freezer_state {
	bool freeze;
};

struct cgroup {
	struct kernfs_node *kn;
	struct cgroup_freezer_state freezer;
};

struct css_set {
	struct cgroup *dfl_cgrp;
};

/* Per-task I/O counters (/proc/<pid>/io). syscr/syscw need
 * CONFIG_TASK_XACCT, read_bytes/write_bytes CONFIG_TASK_IO_ACCOUNTING;
 * readers guard each with bpf_core_field_exists. */
struct task_io_accounting {
	u64 syscr;
	u64 syscw;
	u64 read_bytes;
	u64 write_bytes;
};

struct signal_struct {
	atomic_t live;
	int nr_threads;
	unsigned long long sum_sched_runtime;
	struct task_io_accounting ioac;
};

struct sched_entity {
	u64 sum_exec_runtime;
};

/* Only the first word is declared; readers copy as many words as they
 * keep with bpf_probe_read_kernel. */
struct cpumask {
	unsigned long bits[1];
};

/* Kernels before 5.16 keep the CPU a task runs on in thread_info
 * (task_struct___thread_info below); later ones in task_struct.cpu. */
struct thread_info {
	u32 cpu;
};

struct task_struct {
	unsigned int __state;
	unsigned int flags;
	int exit_state;
	int prio;
	int static_prio;
	struct mm_struct *mm;
	pid_t pid;
	pid_t tgid;
	struct task_struct *real_parent;
	struct sched_entity se;
	u64 start_time;
	const struct cred *cred;
	char comm[16];
	struct css_set *cgroups;
	struct signal_struct *signal;
	struct task_io_accounting ioac;
	unsigned int cpu;
	int nr_cpus_allowed;
	const struct cpumask *cpus_ptr;
};

struct task_struct___thread_info {
	struct thread_info thread_info;
};

struct net_device {
	int ifindex;
};

struct dst_entry {
	struct net_device *dev;
};

struct sock_common {
	unsigned short skc_family;
	int skc_bound_dev_if;
};

struct sock {
	struct sock_common __sk_common;
	struct dst_entry *sk_dst_cache;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

struct bpf_iter_meta {
	void *seq;
};

struct bpf_iter__task {
	struct bpf_iter_meta *meta;
	struct task_struct *task;
};

struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
};

struct user_pt_regs {
	unsigned long regs[31];
	unsigned long sp;
	unsigned long pc;
	unsigned long pstate;
};

enum {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_ANY = 0,
};

#endif
