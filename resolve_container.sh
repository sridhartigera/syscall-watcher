#!/bin/bash
# Resolve a container ID (Docker/containerd/CRI-O) to its cgroup v2 ID.
# The cgroup ID is the inode number of the cgroup directory, which matches
# what bpf_get_current_cgroup_id() returns in the kernel.
#
# Usage: ./resolve_container.sh <container_id_or_name>
# Output: cgroup ID (decimal)

set -e

CONTAINER="$1"
if [ -z "$CONTAINER" ]; then
    echo "Usage: $0 <container_id_or_name>" >&2
    exit 1
fi

# Try Docker first
if command -v docker &>/dev/null; then
    # Get full container ID
    FULL_ID=$(docker inspect --format '{{.Id}}' "$CONTAINER" 2>/dev/null) || true
    if [ -n "$FULL_ID" ]; then
        # Docker cgroup path varies by driver:
        #   cgroupfs: /sys/fs/cgroup/system.slice/docker-<id>.scope
        #   systemd:  /sys/fs/cgroup/system.slice/docker-<id>.scope
        #   Also check: /sys/fs/cgroup/docker/<id>
        for cg_path in \
            "/sys/fs/cgroup/system.slice/docker-${FULL_ID}.scope" \
            "/sys/fs/cgroup/docker/${FULL_ID}" \
            "/sys/fs/cgroup/system.slice/containerd-${FULL_ID}.scope"; do
            if [ -d "$cg_path" ]; then
                CGID=$(stat -c %i "$cg_path")
                echo "$CGID"
                exit 0
            fi
        done

        # Fallback: read cgroup from /proc/<pid>/cgroup
        PID=$(docker inspect --format '{{.State.Pid}}' "$CONTAINER" 2>/dev/null) || true
        if [ -n "$PID" ] && [ "$PID" != "0" ]; then
            # cgroup v2: single line like "0::/system.slice/docker-<id>.scope"
            CG_REL=$(grep '^0::' "/proc/$PID/cgroup" 2>/dev/null | cut -d: -f3)
            if [ -n "$CG_REL" ]; then
                CG_ABS="/sys/fs/cgroup${CG_REL}"
                if [ -d "$CG_ABS" ]; then
                    CGID=$(stat -c %i "$CG_ABS")
                    echo "$CGID"
                    exit 0
                fi
            fi
        fi
    fi
fi

# Try crictl (CRI-O / containerd via CRI)
if command -v crictl &>/dev/null; then
    PID=$(crictl inspect --output go-template --template '{{.info.pid}}' "$CONTAINER" 2>/dev/null) || true
    if [ -n "$PID" ] && [ "$PID" != "0" ]; then
        CG_REL=$(grep '^0::' "/proc/$PID/cgroup" 2>/dev/null | cut -d: -f3)
        if [ -n "$CG_REL" ]; then
            CG_ABS="/sys/fs/cgroup${CG_REL}"
            if [ -d "$CG_ABS" ]; then
                CGID=$(stat -c %i "$CG_ABS")
                echo "$CGID"
                exit 0
            fi
        fi
    fi
fi

# Try by PID directly (user might pass a PID of a containerized process)
if [ -f "/proc/$CONTAINER/cgroup" ]; then
    CG_REL=$(grep '^0::' "/proc/$CONTAINER/cgroup" 2>/dev/null | cut -d: -f3)
    if [ -n "$CG_REL" ]; then
        CG_ABS="/sys/fs/cgroup${CG_REL}"
        if [ -d "$CG_ABS" ]; then
            CGID=$(stat -c %i "$CG_ABS")
            echo "$CGID"
            exit 0
        fi
    fi
fi

echo "ERROR: Could not resolve cgroup ID for '$CONTAINER'" >&2
echo "Tried: docker, crictl, /proc/<pid>/cgroup" >&2
exit 1
