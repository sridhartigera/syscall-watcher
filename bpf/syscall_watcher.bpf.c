// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
//
// Syscall watcher — traces interesting syscalls for a target PID and its children.
// Filters out runtime noise (futex, epoll, clock_gettime, etc.) and only reports
// syscalls that reveal what the process is actually doing:
//   - Process: execve, clone, fork, exit_group
//   - File I/O: openat, read, write, close, unlink, rename, stat
//   - Network: socket, connect, accept, bind, sendto, recvfrom
//
// Syscalls to trace are specified via the syscall_filter map (set by userspace).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_ARGS 6
#define SYSCALL_NAME_LEN 32
#define MAX_SYSCALLS 512
#define MAX_PATH_LEN 128

struct syscall_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u64 syscall_nr;
	__u64 args[MAX_ARGS];
	char  comm[TASK_COMM_LEN];
	__s64 ret;
};

#define FD_NAME_LEN 64

struct pending_syscall {
	__u64 syscall_nr;
	__u64 args[MAX_ARGS];
	__u64 timestamp_ns;
	__u32 ppid;
	__u32 uid;
	char  comm[TASK_COMM_LEN];
	char  path[MAX_PATH_LEN];    // resolved path for openat/execve/etc.
	char  fd_name[FD_NAME_LEN];  // dentry name for fd-based syscalls
};

// watcher_config[0] = target_pid, watcher_config[1] = follow_children (1=yes)
// watcher_config[2] = target_cgroupid (0 = disabled, nonzero = filter by cgroup)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} watcher_config SEC(".maps");

// Tracks PIDs we're watching (target + children)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u8);
} pid_filter SEC(".maps");

// Syscall allow-list: only trace syscalls present in this map.
// Key = syscall number, value = 1. Populated by userspace.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, __u32);
	__type(value, __u8);
} syscall_filter SEC(".maps");

// Perf ring buffer
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Per-CPU scratch for building the output event (calico pattern)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct syscall_event);
} scratch SEC(".maps");

// Stash syscall args on enter, retrieve on exit. Keyed by TID.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct pending_syscall);
} pending SEC(".maps");

// Syscall number -> name lookup. Populated by userspace at load time.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_SYSCALLS);
	__type(key, __u32);
	__type(value, char[SYSCALL_NAME_LEN]);
} syscall_names SEC(".maps");

// Cumulative stats per syscall number. Read by userspace for summary view.
struct syscall_stats {
	__u64 count;
	__u64 bytes_in;   // bytes read/received
	__u64 bytes_out;  // bytes written/sent
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 128);
	__type(key, __u32);
	__type(value, struct syscall_stats);
} stats SEC(".maps");

// Per-CPU scratch for building pending_syscall (avoids stack overflow)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pending_syscall);
} pending_scratch SEC(".maps");

// Check if a dentry name is an anonymous inode we want to skip
// (eventfd, timerfd, eventpoll, signalfd — runtime noise).
static __always_inline int is_anon_noise(const char *name)
{
	// anon_inode names start with "anon_inode:" in the kernel,
	// but the dentry d_name is just the short form like "[eventfd]".
	if (name[0] != '[')
		return 0;
	// [eventfd], [timerfd], [eventpoll], [signalfd]
	if (name[1] == 'e' && name[2] == 'v' && name[3] == 'e' && name[4] == 'n')
		return 1; // [eventfd] or [eventpoll]
	if (name[1] == 't' && name[2] == 'i' && name[3] == 'm')
		return 1; // [timerfd]
	if (name[1] == 's' && name[2] == 'i' && name[3] == 'g')
		return 1; // [signalfd]
	return 0;
}

// Resolve fd -> filename by walking task->files->fdt->fd[n]->f_path.dentry->d_name
// Returns the dentry name (basename, not full path — full path would require
// walking up d_parent which is too many reads for the verifier).
static __always_inline int resolve_fd_name(char *buf, int buf_len, __u32 fd)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	// task->files
	struct files_struct *files;
	files = BPF_CORE_READ(task, files);
	if (!files)
		return -1;

	// files->fdt
	struct fdtable *fdt;
	fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return -1;

	// fdt->fd (array of struct file *)
	struct file **fd_array;
	fd_array = BPF_CORE_READ(fdt, fd);
	if (!fd_array)
		return -1;

	// fd_array[fd]
	struct file *f;
	bpf_probe_read_kernel(&f, sizeof(f), &fd_array[fd]);
	if (!f)
		return -1;

	// f->f_path.dentry->d_name.name
	struct dentry *dentry;
	dentry = BPF_CORE_READ(f, f_path.dentry);
	if (!dentry)
		return -1;

	const unsigned char *dname;
	dname = BPF_CORE_READ(dentry, d_name.name);
	if (!dname)
		return -1;

	return bpf_probe_read_kernel_str(buf, buf_len, dname);
}

static __always_inline int should_trace(__u32 pid)
{
	__u32 key;
	__u64 *val;

	// Check cgroup filter first — matches all processes in a container
	key = 2;
	val = bpf_map_lookup_elem(&watcher_config, &key);
	if (val && *val != 0) {
		__u64 cgid = bpf_get_current_cgroup_id();
		if (cgid == *val)
			return 1;
		// If cgroup mode is set, don't fall through to PID checks
		// (unless PID is also set, for hybrid filtering)
	}

	// Check PID filter map (children)
	if (bpf_map_lookup_elem(&pid_filter, &pid))
		return 1;

	// Check target PID
	key = 0;
	val = bpf_map_lookup_elem(&watcher_config, &key);
	if (val && *val != 0 && *val == (__u64)pid)
		return 1;

	return 0;
}

static __always_inline int should_trace_syscall(__u32 nr)
{
	return bpf_map_lookup_elem(&syscall_filter, &nr) != NULL;
}

// x86_64 syscall numbers for path-carrying syscalls
#if defined(__TARGET_ARCH_x86)
#define SYS_READ      0
#define SYS_WRITE     1
#define SYS_OPEN      2
#define SYS_CLOSE     3
#define SYS_STAT      4
#define SYS_CONNECT   42
#define SYS_ACCEPT    43
#define SYS_SENDTO    44
#define SYS_RECVFROM  45
#define SYS_SENDMSG   46
#define SYS_RECVMSG   47
#define SYS_SHUTDOWN  48
#define SYS_BIND      49
#define SYS_LISTEN    50
#define SYS_SOCKET    41
#define SYS_ACCEPT4   288
#define SYS_CLONE     56
#define SYS_FORK      57
#define SYS_EXECVE    59
#define SYS_EXIT_GRP  231
#define SYS_OPENAT    257
#define SYS_UNLINKAT  263
#define SYS_RENAMEAT  264
#define SYS_RENAMEAT2 316
#endif

SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	if (!should_trace(pid))
		return 0;

	__u32 nr = (__u32)ctx->args[1];
	if (!should_trace_syscall(nr))
		return 0;

	__u32 zero = 0;
	struct pending_syscall *p = bpf_map_lookup_elem(&pending_scratch, &zero);
	if (!p)
		return 0;

	__builtin_memset(p, 0, sizeof(*p));

	p->timestamp_ns = bpf_ktime_get_ns();
	p->syscall_nr = nr;
	p->uid = (__u32)bpf_get_current_uid_gid();

	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
#if defined(__TARGET_ARCH_x86)
	bpf_probe_read(&p->args[0], 8, &regs->di);
	bpf_probe_read(&p->args[1], 8, &regs->si);
	bpf_probe_read(&p->args[2], 8, &regs->dx);
	bpf_probe_read(&p->args[3], 8, &regs->r10);
	bpf_probe_read(&p->args[4], 8, &regs->r8);
	bpf_probe_read(&p->args[5], 8, &regs->r9);
#elif defined(__TARGET_ARCH_arm64)
	bpf_probe_read(&p->args[0], 8, &regs->regs[0]);
	bpf_probe_read(&p->args[1], 8, &regs->regs[1]);
	bpf_probe_read(&p->args[2], 8, &regs->regs[2]);
	bpf_probe_read(&p->args[3], 8, &regs->regs[3]);
	bpf_probe_read(&p->args[4], 8, &regs->regs[4]);
	bpf_probe_read(&p->args[5], 8, &regs->regs[5]);
#else
#error "Unsupported architecture"
#endif

	// For path-carrying syscalls, resolve the filename while we're in
	// sys_enter context (the pointer may not be valid on sys_exit).
	switch (nr) {
	case SYS_OPENAT:
	case SYS_UNLINKAT:
		// arg1 = pathname
		bpf_probe_read_user_str(p->path, sizeof(p->path),
					(void *)p->args[1]);
		break;
	case SYS_EXECVE:
	case SYS_OPEN:
	case SYS_STAT:
		// arg0 = pathname
		bpf_probe_read_user_str(p->path, sizeof(p->path),
					(void *)p->args[0]);
		break;
	case SYS_RENAMEAT:
	case SYS_RENAMEAT2:
		// arg1 = oldpath (most interesting)
		bpf_probe_read_user_str(p->path, sizeof(p->path),
					(void *)p->args[1]);
		break;
	case SYS_READ:
	case SYS_WRITE:
	case SYS_CLOSE:
	case SYS_SENDTO:
	case SYS_RECVFROM:
	case SYS_SENDMSG:
	case SYS_RECVMSG:
	case SYS_SHUTDOWN:
		// resolve fd -> dentry name
		resolve_fd_name(p->fd_name, sizeof(p->fd_name), (__u32)p->args[0]);
		break;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	p->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&p->comm, sizeof(p->comm));

	bpf_map_update_elem(&pending, &tid, p, BPF_ANY);
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	if (!should_trace(pid))
		return 0;

	struct pending_syscall *p = bpf_map_lookup_elem(&pending, &tid);
	if (!p)
		return 0;

	__u32 zero = 0;
	struct syscall_event *evt = bpf_map_lookup_elem(&scratch, &zero);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));

	evt->timestamp_ns = p->timestamp_ns;
	evt->pid = pid;
	evt->tid = tid;
	evt->ppid = p->ppid;
	evt->uid = p->uid;
	evt->syscall_nr = p->syscall_nr;
	evt->ret = ctx->args[1];

	__builtin_memcpy(evt->args, p->args, sizeof(evt->args));
	__builtin_memcpy(evt->comm, p->comm, sizeof(evt->comm));

	__u32 nr = (__u32)evt->syscall_nr;
	char *name = bpf_map_lookup_elem(&syscall_names, &nr);

	// Skip reads/writes to anon inode noise (eventfd, timerfd, eventpoll, signalfd)
	if ((nr == SYS_READ || nr == SYS_WRITE || nr == SYS_CLOSE) &&
	    is_anon_noise(p->fd_name)) {
		bpf_map_delete_elem(&pending, &tid);
		return 0;
	}

	// Human-readable output per syscall type
	__s64 ret = evt->ret;

	switch (nr) {
	case SYS_EXECVE:
		if (ret == 0)
			bpf_printk("EXEC  %s", p->path);
		else
			bpf_printk("EXEC  %s FAILED(%lld)", p->path, ret);
		break;

	case SYS_OPENAT:
	case SYS_OPEN:
		if (ret >= 0)
			bpf_printk("OPEN  \"%s\" -> fd %lld", p->path, ret);
		else
			bpf_printk("OPEN  \"%s\" FAILED(%lld)", p->path, ret);
		break;

	case SYS_READ:
		if (ret > 0)
			bpf_printk("READ  %lld bytes from \"%s\"", ret, p->fd_name);
		else if (ret == 0)
			bpf_printk("READ  EOF on \"%s\"", p->fd_name);
		else
			bpf_printk("READ  \"%s\" FAILED(%lld)", p->fd_name, ret);
		break;

	case SYS_WRITE:
		if (ret > 0)
			bpf_printk("WRITE %lld bytes to \"%s\"", ret, p->fd_name);
		else
			bpf_printk("WRITE \"%s\" FAILED(%lld)", p->fd_name, ret);
		break;

	case SYS_CLOSE:
		bpf_printk("CLOSE \"%s\"", p->fd_name);
		break;

	case SYS_CONNECT:
		if (ret == 0)
			bpf_printk("CONNECT fd %llu OK", evt->args[0]);
		else if (ret == -115) // EINPROGRESS
			bpf_printk("CONNECT fd %llu (in progress)", evt->args[0]);
		else
			bpf_printk("CONNECT fd %llu FAILED(%lld)", evt->args[0], ret);
		break;

	case SYS_ACCEPT:
	case SYS_ACCEPT4:
		if (ret >= 0)
			bpf_printk("ACCEPT -> new fd %lld", ret);
		else
			bpf_printk("ACCEPT FAILED(%lld)", ret);
		break;

	case SYS_SOCKET:
		if (ret >= 0)
			bpf_printk("SOCKET -> fd %lld", ret);
		break;

	case SYS_BIND:
		if (ret == 0)
			bpf_printk("BIND  fd %llu OK", evt->args[0]);
		else
			bpf_printk("BIND  fd %llu FAILED(%lld)", evt->args[0], ret);
		break;

	case SYS_LISTEN:
		bpf_printk("LISTEN fd %llu backlog=%llu", evt->args[0], evt->args[1]);
		break;

	case SYS_SENDTO:
	case SYS_SENDMSG:
		if (ret > 0)
			bpf_printk("SEND  %lld bytes to \"%s\"", ret, p->fd_name);
		else
			bpf_printk("SEND  \"%s\" FAILED(%lld)", p->fd_name, ret);
		break;

	case SYS_RECVFROM:
	case SYS_RECVMSG:
		if (ret > 0)
			bpf_printk("RECV  %lld bytes from \"%s\"", ret, p->fd_name);
		else if (ret == 0)
			bpf_printk("RECV  \"%s\" peer closed", p->fd_name);
		else
			bpf_printk("RECV  \"%s\" FAILED(%lld)", p->fd_name, ret);
		break;

	case SYS_SHUTDOWN:
		bpf_printk("SHUTDOWN \"%s\"", p->fd_name);
		break;

	case SYS_CLONE:
	case SYS_FORK:
		if (ret > 0)
			bpf_printk("SPAWN child pid %lld", ret);
		break;

	case SYS_EXIT_GRP:
		bpf_printk("EXIT  code %llu", evt->args[0]);
		break;

	case SYS_STAT:
		if (ret == 0)
			bpf_printk("STAT  \"%s\" OK", p->path);
		else
			bpf_printk("STAT  \"%s\" NOT FOUND", p->path);
		break;

	case SYS_UNLINKAT:
		if (ret == 0)
			bpf_printk("DELETE \"%s\"", p->path);
		else
			bpf_printk("DELETE \"%s\" FAILED(%lld)", p->path, ret);
		break;

	case SYS_RENAMEAT:
	case SYS_RENAMEAT2:
		if (ret == 0)
			bpf_printk("RENAME \"%s\"", p->path);
		else
			bpf_printk("RENAME \"%s\" FAILED(%lld)", p->path, ret);
		break;

	default:
		if (name)
			bpf_printk("%s = %lld", name, ret);
		break;
	}

	// Update cumulative stats
	struct syscall_stats *st = bpf_map_lookup_elem(&stats, &nr);
	if (st) {
		__sync_fetch_and_add(&st->count, 1);
		if ((nr == SYS_READ || nr == SYS_RECVFROM || nr == SYS_RECVMSG) && ret > 0)
			__sync_fetch_and_add(&st->bytes_in, ret);
		if ((nr == SYS_WRITE || nr == SYS_SENDTO || nr == SYS_SENDMSG) && ret > 0)
			__sync_fetch_and_add(&st->bytes_out, ret);
	} else {
		struct syscall_stats new_st = { .count = 1 };
		if ((nr == SYS_READ || nr == SYS_RECVFROM || nr == SYS_RECVMSG) && ret > 0)
			new_st.bytes_in = ret;
		if ((nr == SYS_WRITE || nr == SYS_SENDTO || nr == SYS_SENDMSG) && ret > 0)
			new_st.bytes_out = ret;
		bpf_map_update_elem(&stats, &nr, &new_st, BPF_NOEXIST);
	}

	bpf_map_delete_elem(&pending, &tid);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
	return 0;
}

// Auto-track children when target forks
SEC("raw_tracepoint/sched_process_fork")
int sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 key = 1;
	__u64 *follow = bpf_map_lookup_elem(&watcher_config, &key);
	if (!follow || *follow == 0)
		return 0;

	struct task_struct *parent = (struct task_struct *)ctx->args[0];
	struct task_struct *child = (struct task_struct *)ctx->args[1];

	__u32 parent_pid = BPF_CORE_READ(parent, tgid);

	if (!should_trace(parent_pid))
		return 0;

	__u32 child_pid = BPF_CORE_READ(child, tgid);

	__u8 val = 1;
	bpf_map_update_elem(&pid_filter, &child_pid, &val, BPF_ANY);

	bpf_printk("FORK parent=%d child=%d", parent_pid, child_pid);
	return 0;
}

// Cleanup on process exit
SEC("raw_tracepoint/sched_process_exit")
int sched_process_exit(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *task = (struct task_struct *)ctx->args[0];
	__u32 pid = BPF_CORE_READ(task, tgid);
	bpf_map_delete_elem(&pid_filter, &pid);
	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
