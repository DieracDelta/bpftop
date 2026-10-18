#include "vmlinux_min.h"

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define NULL ((void *)0)

struct task_info {
	u32 pid;
	u32 tid;
	u32 ppid;
	u32 euid;
	u32 ruid;
	u8 state;
	u8 _pad[3];
	u64 utime_ns;
	u64 stime_ns;
	u64 vsize_bytes;
	u64 rss_pages;
	u64 start_time_ns;
	char comm[16];
	s32 prio;
	s32 static_prio;
	u64 shmem_pages;
	u64 cgroup_id;
	u64 cmdline_gen;
	u64 net_tx_bytes;
	u64 net_rx_bytes;
	u32 net_ifindex;
	u32 nr_threads;
	u8 frozen;
	u8 _pad2[7];
};

/* Emitted for non-leader threads, so userspace can sum a process's CPU
 * time across its live threads. tid != pid distinguishes it from a
 * task_info record (whose tid == pid) in the iterator stream. */
struct thread_cpu {
	u32 pid;
	u32 tid;
	u64 cpu_ns;
};

struct cmdline_event {
	u32 pid;
	u32 len;
	u8 cmdline[256];
	/* Changes on every exec; lets userspace refetch only changed cmdlines. */
	u64 gen;
};

/* Keep in sync with bpftop-common/src/lib.rs (asserted on both sides). */
_Static_assert(sizeof(struct task_info) == 144, "task_info ABI");
_Static_assert(sizeof(struct cmdline_event) == 272, "cmdline_event ABI");
_Static_assert(sizeof(struct thread_cpu) == 16, "thread_cpu ABI");

struct net_stats {
	u64 tx_bytes;
	u64 rx_bytes;
	u32 ifindex;
	u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, u32);
	__type(value, struct cmdline_event);
} CMDLINE_MAP SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, u32);
	__type(value, struct net_stats);
} NET_STATS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, u64);
} RECV_SOCK_STASH SEC(".maps");

static __always_inline void read_cgroup(struct task_struct *task, struct task_info *info)
{
	struct css_set *css = BPF_CORE_READ(task, cgroups);
	if (!css)
		return;

	struct cgroup *cgrp = BPF_CORE_READ(css, dfl_cgrp);
	if (!cgrp)
		return;

	/* Same value userspace would read from <cgroup>/cgroup.freeze. */
	info->frozen = BPF_CORE_READ(cgrp, freezer.freeze);

	struct kernfs_node *kn = BPF_CORE_READ(cgrp, kn);
	if (!kn)
		return;

	info->cgroup_id = BPF_CORE_READ(kn, id);
}

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct task_struct *task = ctx->task;
	if (!task)
		return 1;

	struct task_info info = {};
	info.pid = (u32)BPF_CORE_READ(task, tgid);
	info.tid = (u32)BPF_CORE_READ(task, pid);

	/* Full records for thread-group leaders only; other threads just
	 * contribute their CPU time. */
	if (info.tid != info.pid) {
		struct thread_cpu tc = {
			.pid = info.pid,
			.tid = info.tid,
			.cpu_ns = BPF_CORE_READ(task, utime) + BPF_CORE_READ(task, stime),
		};
		bpf_seq_write(ctx->meta->seq, &tc, sizeof(tc));
		return 0;
	}

	struct signal_struct *sig = BPF_CORE_READ(task, signal);
	info.nr_threads = BPF_CORE_READ(sig, nr_threads);

	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	if (parent)
		info.ppid = (u32)BPF_CORE_READ(parent, tgid);

	const struct cred *cred = BPF_CORE_READ(task, cred);
	if (cred) {
		info.euid = BPF_CORE_READ(cred, euid.val);
		info.ruid = BPF_CORE_READ(cred, uid.val);
	}

	info.state = (u8)BPF_CORE_READ(task, __state);
	/* Leader's own time plus that of already-exited threads, which the
	 * kernel folds into signal_struct. Live threads arrive as thread_cpu. */
	info.utime_ns = BPF_CORE_READ(task, utime) + BPF_CORE_READ(sig, utime);
	info.stime_ns = BPF_CORE_READ(task, stime) + BPF_CORE_READ(sig, stime);
	info.prio = BPF_CORE_READ(task, prio);
	info.static_prio = BPF_CORE_READ(task, static_prio);

	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (mm) {
		s64 file_count = BPF_CORE_READ(mm, rss_stat[0].count);
		s64 anon_count = BPF_CORE_READ(mm, rss_stat[1].count);
		s64 shmem_count = BPF_CORE_READ(mm, rss_stat[3].count);

		info.vsize_bytes = BPF_CORE_READ(mm, total_vm) * 4096;
		info.rss_pages =
			(u64)(file_count > 0 ? file_count : 0) +
			(u64)(anon_count > 0 ? anon_count : 0);
		info.shmem_pages = (u64)(shmem_count > 0 ? shmem_count : 0);
	}

	info.start_time_ns = BPF_CORE_READ(task, start_time);
	BPF_CORE_READ_INTO(&info.comm, task, comm);
	read_cgroup(task, &info);

	/* Join the per-process maps here so userspace needs no per-PID
	 * map syscalls in the steady state. */
	struct cmdline_event *ev = bpf_map_lookup_elem(&CMDLINE_MAP, &info.pid);
	if (ev)
		info.cmdline_gen = ev->gen;

	struct net_stats *net = bpf_map_lookup_elem(&NET_STATS, &info.pid);
	if (net) {
		info.net_tx_bytes = net->tx_bytes;
		info.net_rx_bytes = net->rx_bytes;
		info.net_ifindex = net->ifindex;
	}

	bpf_seq_write(ctx->meta->seq, &info, sizeof(info));
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int capture_cmdline(void *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct mm_struct *mm = BPF_CORE_READ(task, mm);

	if (!mm)
		return 0;

	u64 arg_start = BPF_CORE_READ(mm, arg_start);
	u64 arg_end = BPF_CORE_READ(mm, arg_end);
	if (!arg_start || arg_end <= arg_start)
		return 0;

	struct cmdline_event event = {};
	event.pid = pid;
	event.gen = bpf_ktime_get_ns();

	u64 len = arg_end - arg_start;
	if (len > 255)
		len = 255;

	/* argv is NUL-separated, so a _str read would stop after argv[0].
	 * Copy the raw bytes; userspace turns the NULs into spaces. */
	if (bpf_probe_read_user(event.cmdline, len, (const void *)arg_start) == 0) {
		event.len = len;
	} else {
		long ret = bpf_probe_read_user_str(event.cmdline, len, (const void *)arg_start);
		if (ret > 0)
			event.len = ret;
	}

	bpf_map_update_elem(&CMDLINE_MAP, &pid, &event, BPF_ANY);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int cleanup_cmdline(void *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	/* Fires for every exiting thread. Only drop per-process state once
	 * the whole group is dead (signal->live is decremented before this
	 * tracepoint), otherwise any thread exit loses the cmdline. */
	if (BPF_CORE_READ(task, signal, live.counter) != 0)
		return 0;

	bpf_map_delete_elem(&CMDLINE_MAP, &pid);
	bpf_map_delete_elem(&NET_STATS, &pid);
	return 0;
}

static __always_inline u32 read_sock_ifindex(struct sock *sk)
{
	struct dst_entry *dst = BPF_CORE_READ(sk, sk_dst_cache);
	if (dst) {
		struct net_device *dev = BPF_CORE_READ(dst, dev);
		if (dev) {
			s32 ifidx = BPF_CORE_READ(dev, ifindex);
			if (ifidx > 0)
				return ifidx;
		}
	}

	s32 bound = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
	return bound > 0 ? bound : 0;
}

static __always_inline void account_tx(u64 size, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 ifindex = read_sock_ifindex(sk);
	struct net_stats *stats = bpf_map_lookup_elem(&NET_STATS, &pid);

	if (stats) {
		stats->tx_bytes += size;
		if (ifindex)
			stats->ifindex = ifindex;
		return;
	}

	struct net_stats init = {
		.tx_bytes = size,
		.ifindex = ifindex,
	};
	bpf_map_update_elem(&NET_STATS, &pid, &init, BPF_ANY);
}

static __always_inline void account_rx(u64 size, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 ifindex = sk ? read_sock_ifindex(sk) : 0;
	struct net_stats *stats = bpf_map_lookup_elem(&NET_STATS, &pid);

	if (stats) {
		stats->rx_bytes += size;
		if (ifindex)
			stats->ifindex = ifindex;
		return;
	}

	struct net_stats init = {
		.rx_bytes = size,
		.ifindex = ifindex,
	};
	bpf_map_update_elem(&NET_STATS, &pid, &init, BPF_ANY);
}

static __always_inline void stash_recv_sock(struct sock *sk)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 ptr = (u64)sk;

	bpf_map_update_elem(&RECV_SOCK_STASH, &pid_tgid, &ptr, BPF_ANY);
}

static __always_inline struct sock *pop_recv_sock(u64 pid_tgid)
{
	u64 *ptr = bpf_map_lookup_elem(&RECV_SOCK_STASH, &pid_tgid);
	u64 sk = ptr ? *ptr : 0;

	bpf_map_delete_elem(&RECV_SOCK_STASH, &pid_tgid);
	return (struct sock *)sk;
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	u64 size = PT_REGS_PARM3(ctx);

	account_tx(size, sk);
	return 0;
}

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	u64 size = PT_REGS_PARM3(ctx);

	account_tx(size, sk);
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg(struct pt_regs *ctx)
{
	stash_recv_sock((struct sock *)PT_REGS_PARM1(ctx));
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe_tcp_recvmsg(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sock *sk = pop_recv_sock(pid_tgid);
	s32 ret = PT_REGS_RC(ctx);

	if (ret > 0)
		account_rx(ret, sk);
	return 0;
}

SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx)
{
	stash_recv_sock((struct sock *)PT_REGS_PARM1(ctx));
	return 0;
}

SEC("kretprobe/udp_recvmsg")
int kretprobe_udp_recvmsg(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sock *sk = pop_recv_sock(pid_tgid);
	s32 ret = PT_REGS_RC(ctx);

	if (ret > 0)
		account_rx(ret, sk);
	return 0;
}

/*
 * fexit variants of the probes above, preferred by the loader. One BPF
 * trampoline call per send/recv instead of kprobe + kretprobe, no
 * RECV_SOCK_STASH round trip, and TX counts bytes actually sent rather
 * than requested. Return values come from bpf_get_func_ret (5.17+) so
 * the programs don't depend on the arg count, which changed for
 * tcp/udp_recvmsg in 5.19.
 */
static __always_inline int func_ret(void *ctx)
{
	u64 ret = 0;

	bpf_get_func_ret(ctx, &ret);
	return (int)ret;
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(fexit_tcp_sendmsg, struct sock *sk)
{
	int ret = func_ret(ctx);

	if (ret > 0)
		account_tx(ret, sk);
	return 0;
}

SEC("fexit/udp_sendmsg")
int BPF_PROG(fexit_udp_sendmsg, struct sock *sk)
{
	int ret = func_ret(ctx);

	if (ret > 0)
		account_tx(ret, sk);
	return 0;
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(fexit_tcp_recvmsg, struct sock *sk)
{
	int ret = func_ret(ctx);

	if (ret > 0)
		account_rx(ret, sk);
	return 0;
}

SEC("fexit/udp_recvmsg")
int BPF_PROG(fexit_udp_recvmsg, struct sock *sk)
{
	int ret = func_ret(ctx);

	if (ret > 0)
		account_rx(ret, sk);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
