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

## Architecture

```
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
```
