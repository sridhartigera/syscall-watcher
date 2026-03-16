// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
//
// Syscall policy enforcement via fmod_ret — blocks operations for targeted
// PIDs/containers by modifying the return value of security_* kernel functions.
// Runs alongside or independently from the tracer.
//
// Uses BPF_MODIFY_RETURN (fmod_ret) instead of LSM BPF, so no "bpf" in lsm=
// boot parameter is needed. Requires kernel 5.17+ (for bpf_loop).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// errno value (not available via vmlinux.h)
#define EPERM 1

// Operation IDs
#define OP_EXEC       0
#define OP_FILE_OPEN  1
#define OP_CONNECT    2
#define OP_SOCKET     3
#define OP_BIND       4
#define OP_LISTEN     5
#define OP_KILL       6
#define OP_UNLINK     7
#define OP_RENAME     8
#define OP_MKDIR      9
#define OP_RMDIR      10
#define OP_READ       11
#define OP_WRITE      12
#define OP_FORK       13

#define MAX_OPS       14

// file_permission mask bits (kernel defines, not in vmlinux.h)
#define MAY_READ  4
#define MAY_WRITE 2

#define PATH_MAX_LEN     64
#define MAX_PROTECTED     8
#define MAX_PATH_DEPTH    8

// policy_config[0] = target_pid, [1] = follow_children, [2] = cgroup_id
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} policy_config SEC(".maps");

// Tracked PIDs under enforcement
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u8);
} policy_pid_filter SEC(".maps");

// Operation enum -> block flag (1=block globally)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_OPS);
	__type(key, __u32);
	__type(value, __u8);
} policy_map SEC(".maps");

// Protected directory prefixes (64-byte fixed strings)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PROTECTED);
	__type(key, __u32);
	__type(value, char[PATH_MAX_LEN]);
} policy_protected_paths SEC(".maps");

// Bitmask of blocked operations per protected path slot
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PROTECTED);
	__type(key, __u32);
	__type(value, __u32);
} policy_path_ops SEC(".maps");

// Number of active protected path entries
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} policy_path_count SEC(".maps");

// Denial counts per operation (per-CPU for lock-free updates)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_OPS);
	__type(key, __u32);
	__type(value, __u64);
} policy_stats SEC(".maps");

// Per-CPU scratch for dentry name comparison (avoids stack overflow)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[PATH_MAX_LEN]);
} policy_scratch SEC(".maps");

// Check if current task should be subject to policy enforcement.
// Same logic as should_trace() in syscall_watcher.bpf.c but uses policy maps.
static __always_inline int should_enforce(__u32 pid)
{
	__u32 key;
	__u64 *val;

	// Check cgroup filter first
	key = 2;
	val = bpf_map_lookup_elem(&policy_config, &key);
	if (val && *val != 0) {
		__u64 cgid = bpf_get_current_cgroup_id();
		if (cgid == *val)
			return 1;
	}

	// Check PID filter map (children)
	if (bpf_map_lookup_elem(&policy_pid_filter, &pid))
		return 1;

	// Check target PID
	key = 0;
	val = bpf_map_lookup_elem(&policy_config, &key);
	if (val && *val != 0 && *val == (__u64)pid)
		return 1;

	return 0;
}

// Check global policy for an operation. Returns -EPERM if blocked, 0 otherwise.
static __always_inline int check_policy(__u32 op)
{
	__u8 *blocked = bpf_map_lookup_elem(&policy_map, &op);
	if (blocked && *blocked) {
		// Increment denial stats
		__u64 *cnt = bpf_map_lookup_elem(&policy_stats, &op);
		if (cnt) {
			__sync_fetch_and_add(cnt, 1);
		} else {
			__u64 one = 1;
			bpf_map_update_elem(&policy_stats, &op, &one, BPF_NOEXIST);
		}
		return -EPERM;
	}
	return 0;
}

// Context passed to the bpf_loop callback for path slot iteration.
// dirname is copied in (not a pointer) to preserve verifier validity.
#define DIRNAME_LEN 32

struct path_check_ctx {
	char dirname[DIRNAME_LEN]; // top-level directory name (copied from scratch)
	__u32 op;                  // operation being checked
	__u32 denied;              // 0 = no match, 1 = blocked
};

// bpf_loop callback: check one protected path slot against the dirname.
// Returns 1 to stop (match found), 0 to continue.
static long check_path_slot(__u32 slot, void *ctx)
{
	struct path_check_ctx *pc = ctx;

	char *ppath = bpf_map_lookup_elem(&policy_protected_paths, &slot);
	if (!ppath)
		return 0;

	// Skip leading '/'
	int off = (ppath[0] == '/') ? 1 : 0;

	// Compare first path component against dirname
	int match = 1;
	#pragma unroll
	for (int c = 0; c < DIRNAME_LEN; c++) {
		char pc_ch = ppath[off + c];
		char sc = pc->dirname[c];
		if (pc_ch == '/' || pc_ch == '\0') {
			if (sc != '\0')
				match = 0;
			break;
		}
		if (pc_ch != sc) {
			match = 0;
			break;
		}
	}

	if (!match)
		return 0;

	__u32 *ops_mask = bpf_map_lookup_elem(&policy_path_ops, &slot);
	if (!ops_mask)
		return 0;

	__u32 op = pc->op;
	if (op >= MAX_OPS)
		return 0;

	if (*ops_mask & (1u << op)) {
		__u64 *cnt = bpf_map_lookup_elem(&policy_stats, &op);
		if (cnt) {
			__sync_fetch_and_add(cnt, 1);
		} else {
			__u64 one = 1;
			bpf_map_update_elem(&policy_stats, &op, &one, BPF_NOEXIST);
		}
		pc->denied = 1;
		return 1; // stop iterating
	}

	return 0;
}

// Check if dentry is under a protected path. Walks up the dentry chain to find
// the top-level directory (child of root), then uses bpf_loop to compare against
// each protected path entry.
static __always_inline int check_path_policy(__u32 op, struct dentry *dentry)
{
	if (!dentry)
		return 0;

	__u32 zero = 0;
	__u32 *count = bpf_map_lookup_elem(&policy_path_count, &zero);
	if (!count || *count == 0)
		return 0;

	__u32 num_paths = *count;
	if (num_paths > MAX_PROTECTED)
		num_paths = MAX_PROTECTED;

	char *scratch = bpf_map_lookup_elem(&policy_scratch, &zero);
	if (!scratch)
		return 0;

	// Walk up to find the top-level ancestor (direct child of root).
	// For /etc/passwd: walk passwd→etc, etc's parent is root, so "etc" is our match target.
	struct dentry *cur = dentry;

	#pragma unroll
	for (int level = 0; level < MAX_PATH_DEPTH; level++) {
		struct dentry *parent = BPF_CORE_READ(cur, d_parent);
		if (!parent || parent == cur)
			break;

		struct dentry *grandparent = BPF_CORE_READ(parent, d_parent);
		if (grandparent == parent) {
			// parent is root → cur is top-level dir (e.g. "etc")
			const unsigned char *dname = BPF_CORE_READ(cur, d_name.name);
			if (!dname)
				return 0;

			__builtin_memset(scratch, 0, PATH_MAX_LEN);
			bpf_probe_read_kernel_str(scratch, PATH_MAX_LEN, dname);

			struct path_check_ctx ctx = {};
			__builtin_memset(&ctx, 0, sizeof(ctx));
			__builtin_memcpy(ctx.dirname, scratch, DIRNAME_LEN);
			ctx.op = op;
			ctx.denied = 0;
			bpf_loop(num_paths, check_path_slot, &ctx, 0);
			return ctx.denied ? -EPERM : 0;
		}

		cur = parent;
	}

	return 0;
}

// --- fmod_ret hooks (modify return of security_* functions) ---
// Works without "bpf" in lsm= boot parameter — attaches via BPF trampoline.

SEC("fmod_ret/security_bprm_check")
int BPF_PROG(policy_bprm_check, struct linux_binprm *bprm)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_enforce(pid))
		return 0;

	int ret = check_policy(OP_EXEC);
	if (ret) {
		bpf_printk("POLICY DENY op=exec pid=%d", pid);
		return ret;
	}

	// Path-scoped check via bprm->file->f_path.dentry
	struct dentry *dentry = BPF_CORE_READ(bprm, file, f_path.dentry);
	ret = check_path_policy(OP_EXEC, dentry);
	if (ret)
		bpf_printk("POLICY DENY op=exec(path) pid=%d", pid);
	return ret;
}

SEC("fmod_ret/security_file_open")
int BPF_PROG(policy_file_open, struct file *file)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_enforce(pid))
		return 0;

	int ret = check_policy(OP_FILE_OPEN);
	if (ret) {
		bpf_printk("POLICY DENY op=file_open pid=%d", pid);
		return ret;
	}

	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	ret = check_path_policy(OP_FILE_OPEN, dentry);
	if (ret)
		bpf_printk("POLICY DENY op=file_open(path) pid=%d", pid);
	return ret;
}

SEC("fmod_ret/security_socket_connect")
int BPF_PROG(policy_socket_connect, struct socket *sock,
	     struct sockaddr *address, int addrlen)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_enforce(pid))
		return 0;

	int ret = check_policy(OP_CONNECT);
	if (ret)
		bpf_printk("POLICY DENY op=connect pid=%d", pid);
	return ret;
}

SEC("fmod_ret/security_socket_create")
int BPF_PROG(policy_socket_create, int family, int type,
	     int protocol, int kern)
{
	// Skip kernel-internal sockets
	if (kern)
		return 0;

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_enforce(pid))
		return 0;

	int ret = check_policy(OP_SOCKET);
	if (ret)
		bpf_printk("POLICY DENY op=socket pid=%d", pid);
	return ret;
}

SEC("fmod_ret/security_socket_bind")
int BPF_PROG(policy_socket_bind, struct socket *sock,
	     struct sockaddr *address, int addrlen)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_enforce(pid))
		return 0;

	int ret = check_policy(OP_BIND);
	if (ret)
		bpf_printk("POLICY DENY op=bind pid=%d", pid);
	return ret;
}

SEC("fmod_ret/security_socket_listen")
int BPF_PROG(policy_socket_listen, struct socket *sock, int backlog)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_enforce(pid))
		return 0;

	int ret = check_policy(OP_LISTEN);
	if (ret)
		bpf_printk("POLICY DENY op=listen pid=%d", pid);
	return ret;
}

SEC("fmod_ret/security_task_kill")
int BPF_PROG(policy_task_kill, struct task_struct *target,
	     struct kernel_siginfo *info, int sig, const struct cred *cred)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_enforce(pid))
		return 0;

	int ret = check_policy(OP_KILL);
	if (ret)
		bpf_printk("POLICY DENY op=kill pid=%d sig=%d", pid, sig);
	return ret;
}

SEC("fmod_ret/security_inode_unlink")
int BPF_PROG(policy_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_enforce(pid))
		return 0;

	int ret = check_policy(OP_UNLINK);
	if (ret) {
		bpf_printk("POLICY DENY op=unlink pid=%d", pid);
		return ret;
	}

	ret = check_path_policy(OP_UNLINK, dentry);
	if (ret)
		bpf_printk("POLICY DENY op=unlink(path) pid=%d", pid);
	return ret;
}

SEC("fmod_ret/security_inode_rename")
int BPF_PROG(policy_inode_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_enforce(pid))
		return 0;

	int ret = check_policy(OP_RENAME);
	if (ret) {
		bpf_printk("POLICY DENY op=rename pid=%d", pid);
		return ret;
	}

	ret = check_path_policy(OP_RENAME, old_dentry);
	if (ret)
		bpf_printk("POLICY DENY op=rename(path) pid=%d", pid);
	return ret;
}

SEC("fmod_ret/security_inode_mkdir")
int BPF_PROG(policy_inode_mkdir, struct inode *dir, struct dentry *dentry,
	     umode_t mode)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_enforce(pid))
		return 0;

	int ret = check_policy(OP_MKDIR);
	if (ret) {
		bpf_printk("POLICY DENY op=mkdir pid=%d", pid);
		return ret;
	}

	ret = check_path_policy(OP_MKDIR, dentry);
	if (ret)
		bpf_printk("POLICY DENY op=mkdir(path) pid=%d", pid);
	return ret;
}

SEC("fmod_ret/security_inode_rmdir")
int BPF_PROG(policy_inode_rmdir, struct inode *dir, struct dentry *dentry)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_enforce(pid))
		return 0;

	int ret = check_policy(OP_RMDIR);
	if (ret) {
		bpf_printk("POLICY DENY op=rmdir pid=%d", pid);
		return ret;
	}

	ret = check_path_policy(OP_RMDIR, dentry);
	if (ret)
		bpf_printk("POLICY DENY op=rmdir(path) pid=%d", pid);
	return ret;
}

SEC("fmod_ret/security_file_permission")
int BPF_PROG(policy_file_permission, struct file *file, int mask)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_enforce(pid))
		return 0;

	int ret = 0;

	if (mask & MAY_READ) {
		ret = check_policy(OP_READ);
		if (ret) {
			bpf_printk("POLICY DENY op=read pid=%d", pid);
			return ret;
		}
		struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
		ret = check_path_policy(OP_READ, dentry);
		if (ret) {
			bpf_printk("POLICY DENY op=read(path) pid=%d", pid);
			return ret;
		}
	}

	if (mask & MAY_WRITE) {
		ret = check_policy(OP_WRITE);
		if (ret) {
			bpf_printk("POLICY DENY op=write pid=%d", pid);
			return ret;
		}
		struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
		ret = check_path_policy(OP_WRITE, dentry);
		if (ret) {
			bpf_printk("POLICY DENY op=write(path) pid=%d", pid);
			return ret;
		}
	}

	return 0;
}

SEC("fmod_ret/security_task_alloc")
int BPF_PROG(policy_task_alloc, struct task_struct *task,
	     unsigned long clone_flags)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_enforce(pid))
		return 0;

	int ret = check_policy(OP_FORK);
	if (ret)
		bpf_printk("POLICY DENY op=fork pid=%d", pid);
	return ret;
}

// --- Child tracking (same pattern as watcher) ---

SEC("raw_tracepoint/sched_process_fork")
int policy_sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 key = 1;
	__u64 *follow = bpf_map_lookup_elem(&policy_config, &key);
	if (!follow || *follow == 0)
		return 0;

	struct task_struct *parent = (struct task_struct *)ctx->args[0];
	struct task_struct *child = (struct task_struct *)ctx->args[1];

	__u32 parent_pid = BPF_CORE_READ(parent, tgid);

	if (!should_enforce(parent_pid))
		return 0;

	__u32 child_pid = BPF_CORE_READ(child, tgid);

	__u8 val = 1;
	bpf_map_update_elem(&policy_pid_filter, &child_pid, &val, BPF_ANY);

	bpf_printk("POLICY TRACK child=%d parent=%d", child_pid, parent_pid);
	return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int policy_sched_process_exit(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *task = (struct task_struct *)ctx->args[0];
	__u32 pid = BPF_CORE_READ(task, tgid);
	bpf_map_delete_elem(&policy_pid_filter, &pid);
	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
