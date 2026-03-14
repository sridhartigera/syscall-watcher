#!/bin/bash
# Populate the syscall_names BPF map with syscall number -> name mappings.
# Reads from ausyscall or falls back to /usr/include/asm/unistd_64.h.

set -e

MAP_ID="$1"
if [ -z "$MAP_ID" ]; then
    echo "Usage: $0 <map_id>"
    echo "Find the map id with: bpftool map show | grep syscall_names"
    exit 1
fi

BPFTOOL="${BPFTOOL:-bpftool}"

populate_entry() {
    local nr="$1"
    local name="$2"

    # Pad name to 32 bytes (SYSCALL_NAME_LEN) with nulls
    local hex_name
    hex_name=$(printf '%s' "$name" | xxd -p | sed 's/../& /g')
    local name_len=${#name}
    local pad=$((32 - name_len))
    local hex_pad
    hex_pad=$(printf '%0*d' $((pad * 2)) 0 | sed 's/../& /g')

    # Key: nr as 4-byte little-endian
    local key
    key=$(printf '%02x %02x %02x %02x' \
        $((nr & 0xff)) $(((nr >> 8) & 0xff)) $(((nr >> 16) & 0xff)) $(((nr >> 24) & 0xff)))

    $BPFTOOL map update id "$MAP_ID" key hex $key value hex $hex_name $hex_pad 2>/dev/null
}

count=0

# Try ausyscall first (cleanest source)
if command -v ausyscall &>/dev/null; then
    while IFS=$'\t' read -r name nr; do
        [ -z "$nr" ] && continue
        populate_entry "$nr" "$name"
        count=$((count + 1))
    done < <(ausyscall --dump 2>/dev/null | tail -n +2)
else
    # Fall back to unistd_64.h
    header="/usr/include/asm/unistd_64.h"
    if [ ! -f "$header" ]; then
        header="/usr/include/x86_64-linux-gnu/asm/unistd_64.h"
    fi
    if [ -f "$header" ]; then
        while read -r _ name nr; do
            name="${name#__NR_}"
            populate_entry "$nr" "$name"
            count=$((count + 1))
        done < <(grep '^#define __NR_' "$header")
    else
        echo "ERROR: No syscall source found. Install auditd or linux-libc-dev."
        exit 1
    fi
fi

echo "Populated $count syscall names into map id $MAP_ID"
