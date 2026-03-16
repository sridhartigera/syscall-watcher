# syscall-watcher

eBPF-based syscall tracer that watches what a process or container is actually
doing — file access, network calls, process spawning — filtering out runtime
noise. Built following Calico's BPF patterns (CO-RE, raw tracepoints, perf ring
buffer, per-CPU scratch maps).

## Prerequisites

```bash
sudo apt install clang llvm linux-tools-common linux-tools-$(uname -r)
```

Requires kernel 5.8+ with BTF support (`/sys/kernel/btf/vmlinux` must exist).

## Quick Start

```bash
# Build
make

# Trace a process (+ all children it spawns)
sudo make load PID=<pid>
sudo make watch

# Trace a Docker container
sudo make load CONTAINER=<container_id_or_name>
sudo make watch

# Cumulative stats summary (refreshes every 5s)
sudo make summary

# Stop tracing
sudo make unload
```

## Filter Profiles

Control how much you see with `FILTER=`:

```bash
sudo make load PID=<pid> FILTER=minimal    # just exec, open, close, connect
sudo make load PID=<pid> FILTER=network    # socket/connect/send/recv + process
sudo make load PID=<pid> FILTER=file       # all file ops + process
sudo make load PID=<pid> FILTER=default    # recommended mix of file + network
sudo make load PID=<pid> FILTER=all        # everything (noisy)
```

## Output

Human-readable trace output:

```
EXEC  /usr/bin/node
OPEN  "/home/user/.config/settings.json" -> fd 3
READ  1024 bytes from "settings.json"
READ  EOF on "settings.json"
CLOSE "settings.json"
SOCKET -> fd 4
CONNECT fd 4 OK
WRITE 256 bytes to "TCP"
READ  512 bytes from "TCP"
SPAWN child pid 52538
FORK  parent=52537 child=52538
DELETE "/tmp/output.txt"
EXIT  code 0
```

Cumulative stats view (`make summary`):

```
=== Syscall Watcher — Cumulative Stats (every 5s) ===

SYSCALL                   COUNT     BYTES IN    BYTES OUT
--------------------------------------------------------
read                      4,231      2.1 MB            -
write                     3,892            -      1.8 MB
openat                      847            -            -
close                       845            -            -
connect                     123            -            -
execve                        3            -            -
--------------------------------------------------------
TOTAL                    10,141      2.3 MB      1.8 MB
```

## Container Support

Traces all processes inside a container using cgroup v2 filtering
(`bpf_get_current_cgroup_id`). Works with Docker, containerd, and CRI-O.

```bash
# By container ID or name
sudo make load CONTAINER=my-nginx
sudo make load CONTAINER=abc123def456

# Combine with filters
sudo make load CONTAINER=my-app FILTER=network
```

## AI Agent Detection

Analyzes syscall patterns to determine if the traced workload is an AI agent.
Takes differential snapshots over a time window and scores five signals (0-100):

| Signal | Max | What it measures |
|--------|-----|-----------------|
| Execve Rate | 25 | Constant shelling out (tool calls) |
| Connect:Execve Ratio | 25 | LLM API call → tool → LLM API cycling |
| Fork Fan-Out | 20 | Many short-lived child processes |
| Read-Write Churn | 15 | Balanced high-volume file I/O |
| Burst Pattern | 15 | Bursty activity (high coefficient of variation) |

```bash
# Default: 10 samples, 3s apart = 30s observation window
sudo make detect

# Custom window
sudo make detect DETECT_SAMPLES=5 DETECT_INTERVAL=2

# JSON output
sudo ./detect_agent.sh --json

# Continuous re-scoring
sudo ./detect_agent.sh --watch
```

Example output:

```
=== AI Agent Detection (30s observation window) ===

Score: 73/100 — LIKELY AI AGENT

Signal Breakdown:
  Execve Rate (4.2/s)          [23/25]  ████████████████████████░
  Connect:Execve Ratio (1.1)   [24/25]  ████████████████████████░
  Fork Fan-Out (3.5/s)         [16/20]  ████████████████░░░░
  Read-Write Churn (0.6)       [ 7/15]  ███████░░░░░░░░░
  Burst Pattern (CV=0.3)       [ 3/15]  ███░░░░░░░░░░░░░
```

Verdicts: 0-20 NOT AN AGENT, 21-45 UNLIKELY, 46-65 POSSIBLE, 66-85 LIKELY, 86-100 ALMOST CERTAINLY.

## Syscall Policy Enforcement

Active enforcement: block operations for targeted PIDs or containers. Uses
`fmod_ret` (BPF_MODIFY_RETURN) to intercept `security_*` kernel functions and
return `-EPERM` before they execute. No boot parameter changes needed.

### Prerequisites

Requires kernel 5.17+ with BTF support (same as the tracer, plus `bpf_loop()`).

### Usage

```bash
# Block all network access for a process
sudo make policy-load PID=<pid> POLICY_FILE=policies/no-network.policy

# Block exec (process can't run any programs)
sudo make policy-load PID=<pid> POLICY_FILE=policies/no-exec.policy

# Read-only filesystem
sudo make policy-load PID=<pid> POLICY_FILE=policies/read-only-fs.policy

# Protect system directories from modification
sudo make policy-load PID=<pid> POLICY_FILE=policies/protect-system.policy

# Target a container
sudo make policy-load CONTAINER=my-app POLICY_FILE=policies/no-network.policy

# View denial stats
sudo make policy-summary

# Watch denials in real time
sudo make watch

# Remove policy
sudo make policy-unload
```

### Built-in Policies

| Policy | File | Effect |
|--------|------|--------|
| No Network | `policies/no-network.policy` | Blocks socket, connect, bind, listen |
| No Exec | `policies/no-exec.policy` | Blocks execve |
| Read-Only FS | `policies/read-only-fs.policy` | Blocks write, unlink, rename, mkdir, rmdir |
| Protect System | `policies/protect-system.policy` | Protects /etc, /usr, /boot + blocks bind/listen |

### Custom Policy Format

```
# Global blocks — deny operation for ALL files/paths
block <operation>

# Path-scoped blocks — deny operations only under a directory
protect <path> <op1> [op2 ...]
```

Operations: `exec`, `file_open`, `connect`, `socket`, `bind`, `listen`, `kill`,
`unlink`, `rename`, `mkdir`, `rmdir`, `read`, `write`, `fork`.

### Running Alongside the Tracer

The policy enforcer and tracer are independent BPF objects. You can run both
on the same PID/container simultaneously — the tracer logs what happens, the
policy blocks what shouldn't:

```bash
sudo make load PID=<pid>                                    # start tracing
sudo make policy-load PID=<pid> POLICY_FILE=policies/no-network.policy  # add enforcement
sudo make watch                                             # see both trace + denials
```

## Architecture

```
Tracer (syscall_watcher.bpf.o):
  raw_tracepoint/sys_enter   ─── capture args, resolve fd names, stash in pending map
  raw_tracepoint/sys_exit    ─── combine with return value, filter noise, emit event
  sched_process_fork         ─── auto-track child PIDs
  sched_process_exit         ─── cleanup

  Filtering:
    watcher_config  ARRAY[3]        target_pid, follow_children, cgroup_id
    pid_filter      HASH            tracked PIDs (target + children)
    syscall_filter  HASH            syscall allow-list (populated by profile)
    + anon inode suppression        skips [eventfd], [timerfd], [eventpoll], [signalfd]

  Output:
    bpf_printk → trace_pipe         human-readable live trace
    events     PERF_EVENT_ARRAY     structured events (for userspace readers)
    stats      PERCPU_HASH          cumulative counts + bytes per syscall

  Scratch:
    scratch         PERCPU_ARRAY    output event builder (avoids 512B stack limit)
    pending_scratch PERCPU_ARRAY    pending syscall builder
    pending         HASH            tid → stashed args for sys_enter/exit correlation
    syscall_names   ARRAY[512]      nr → name lookup (populated at load time)

Policy Enforcer (syscall_policy.bpf.o) — uses fmod_ret/security_* hooks:
  security_bprm_check        ─── block exec
  security_file_open         ─── block file open
  security_socket_connect    ─── block connect
  security_socket_create     ─── block socket creation
  security_socket_bind       ─── block bind
  security_socket_listen     ─── block listen
  security_task_kill         ─── block kill
  security_inode_unlink      ─── block delete
  security_inode_rename      ─── block rename
  security_inode_mkdir       ─── block mkdir
  security_inode_rmdir       ─── block rmdir
  security_file_permission   ─── block read/write
  security_task_alloc        ─── block fork
  sched_process_fork/exit    ─── child PID tracking

  Maps:
    policy_config           ARRAY[3]      target_pid, follow_children, cgroup_id
    policy_pid_filter       HASH          tracked PIDs under enforcement
    policy_map              HASH          operation → block flag (global)
    policy_protected_paths  ARRAY[8]      directory prefixes to protect
    policy_path_ops         ARRAY[8]      per-path blocked operation bitmask
    policy_path_count       ARRAY[1]      number of active protected paths
    policy_stats            PERCPU_HASH   denial counts per operation
```
