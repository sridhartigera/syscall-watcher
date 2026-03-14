# syscall-watcher

eBPF-based syscall tracer that watches all syscalls made by a process and its
children. Built following Calico's BPF patterns (CO-RE, raw tracepoints, perf
ring buffer, per-CPU scratch maps).

Perfect for watching what an AI agent does under the hood.

## Prerequisites

```bash
sudo apt install clang llvm linux-tools-common linux-tools-$(uname -r)
```

Requires kernel 5.8+ with BTF support (`/sys/kernel/btf/vmlinux` must exist).

## Quick Start

```bash
# Build
make

# Start your target process, note its PID
# e.g.: claude --chat &; echo $!

# Load and attach (traces PID + all children it spawns)
sudo make load PID=<target_pid>

# Watch syscalls in real time
sudo make watch

# Stop tracing
sudo make unload
```

## Output Format

The `trace_pipe` output shows:

```
SYSCALL pid=12345 nr=1 comm=claude       # sys_enter: write()
SYSRET  pid=12345 nr=1 ret=42            # sys_exit:  write() returned 42
FORK    parent=12345 child=12346          # child process spawned, auto-tracked
```

Syscall numbers map to names via `ausyscall --dump` or `/usr/include/asm/unistd_64.h`.

## Architecture

```
raw_tracepoint/sys_enter  ──┐
raw_tracepoint/sys_exit   ──┤── perf ring buffer ──> trace_pipe / userspace reader
sched_process_fork        ──┤   (+ bpf_printk)
sched_process_exit        ──┘

Maps:
  config      ARRAY[2]         target_pid, follow_children flags
  pid_filter  HASH             tracked PIDs (target + children)
  events      PERF_EVENT_ARRAY ring buffer for structured events
  scratch     PERCPU_ARRAY     scratch space (avoids 512B stack limit)
  pending     HASH             tid -> syscall_nr for enter/exit correlation
```

## Iterating

The perf ring buffer (`events` map) emits structured `syscall_event` records.
A Go/C/Python userspace reader can consume these for richer output (syscall
name resolution, argument decoding, latency measurement, etc.). The
`bpf_printk` + `trace_pipe` path is for quick iteration.
