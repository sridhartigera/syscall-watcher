#!/bin/bash
# Populate the syscall_filter BPF map with the set of "interesting" syscalls.
# These are the syscalls that reveal what a process is actually doing,
# filtering out runtime noise (futex, epoll, clock_gettime, mprotect, etc.)

set -e

MAP_ID="$1"
FILTER="${2:-default}"

BPFTOOL="${BPFTOOL:-bpftool}"

add_syscall() {
    local nr="$1"
    local key
    key=$(printf '%02x %02x %02x %02x' \
        $((nr & 0xff)) $(((nr >> 8) & 0xff)) $(((nr >> 16) & 0xff)) $(((nr >> 24) & 0xff)))
    $BPFTOOL map update id "$MAP_ID" key hex $key value hex 01 2>/dev/null
}

resolve_nr() {
    local name="$1"
    if command -v ausyscall &>/dev/null; then
        ausyscall "$name" 2>/dev/null
    else
        grep -w "__NR_$name" /usr/include/asm/unistd_64.h 2>/dev/null | awk '{print $3}' || \
        grep -w "__NR_$name" /usr/include/x86_64-linux-gnu/asm/unistd_64.h 2>/dev/null | awk '{print $3}'
    fi
}

# Syscall categories — add to these lists to trace more
PROCESS_SYSCALLS="execve execveat clone clone3 fork vfork exit_group kill"
FILE_SYSCALLS="open openat openat2 close read write pread64 pwrite64 stat fstat lstat newfstatat unlink unlinkat rename renameat renameat2 mkdir mkdirat rmdir truncate ftruncate chmod fchmod fchmodat chown fchown fchownat link linkat symlink symlinkat readlink readlinkat"
NETWORK_SYSCALLS="socket connect accept accept4 bind listen sendto recvfrom sendmsg recvmsg shutdown setsockopt getsockopt getpeername getsockname"
PIPE_SYSCALLS="pipe pipe2 dup dup2 dup3"

case "$FILTER" in
    minimal)
        # Bare minimum: just process + open/close + connect
        SYSCALLS="execve clone fork openat close connect accept socket"
        ;;
    network)
        # Only data-flow network syscalls, not metadata (setsockopt, getsockname, etc.)
        SYSCALLS="socket connect accept accept4 bind listen sendto recvfrom sendmsg recvmsg shutdown $PROCESS_SYSCALLS"
        ;;
    file)
        SYSCALLS="$FILE_SYSCALLS $PROCESS_SYSCALLS"
        ;;
    all)
        # Everything (noisy, but complete)
        echo "WARNING: 'all' filter will be very noisy" >&2
        SYSCALLS="$PROCESS_SYSCALLS $FILE_SYSCALLS $NETWORK_SYSCALLS $PIPE_SYSCALLS"
        ;;
    *)
        # Default: the interesting stuff for watching an AI agent
        SYSCALLS="execve execveat clone clone3 fork exit_group openat close read write connect accept accept4 socket bind sendto recvfrom pipe pipe2 dup2 unlinkat renameat2 kill"
        ;;
esac

count=0
for name in $SYSCALLS; do
    nr=$(resolve_nr "$name")
    if [ -n "$nr" ]; then
        add_syscall "$nr"
        count=$((count + 1))
    fi
done

echo "Added $count syscalls to filter (profile=$FILTER)"
