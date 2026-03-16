#!/bin/bash
# Populate policy BPF maps from a policy file.
#
# Usage: ./populate_policy.sh <policy_map_id> <paths_map_id> <path_ops_map_id> <path_count_map_id> <policy_file>
#
# Policy file format:
#   block <operation>                      — block operation globally
#   protect <path> <op1> [op2 ...]         — block operations under a directory
#   # comments and blank lines are ignored

set -e

POLICY_MAP_ID="$1"
PATHS_MAP_ID="$2"
PATH_OPS_MAP_ID="$3"
PATH_COUNT_MAP_ID="$4"
POLICY_FILE="$5"

BPFTOOL="${BPFTOOL:-bpftool}"

if [ -z "$POLICY_FILE" ] || [ ! -f "$POLICY_FILE" ]; then
    echo "ERROR: Policy file not found: $POLICY_FILE" >&2
    exit 1
fi

# Operation name -> ID mapping
op_id() {
    case "$1" in
        exec)      echo 0 ;;
        file_open) echo 1 ;;
        connect)   echo 2 ;;
        socket)    echo 3 ;;
        bind)      echo 4 ;;
        listen)    echo 5 ;;
        kill)      echo 6 ;;
        unlink)    echo 7 ;;
        rename)    echo 8 ;;
        mkdir)     echo 9 ;;
        rmdir)     echo 10 ;;
        read)      echo 11 ;;
        write)     echo 12 ;;
        fork)      echo 13 ;;
        *)         echo "" ;;
    esac
}

# Encode u32 as 4-byte little-endian hex
le32() {
    local v="$1"
    printf '%02x %02x %02x %02x' \
        $((v & 0xff)) $(((v >> 8) & 0xff)) $(((v >> 16) & 0xff)) $(((v >> 24) & 0xff))
}

block_count=0
path_slot=0

while IFS= read -r line || [ -n "$line" ]; do
    # Strip comments and whitespace
    line="${line%%#*}"
    line="$(echo "$line" | xargs)"
    [ -z "$line" ] && continue

    # Parse directive
    directive=$(echo "$line" | awk '{print $1}')

    case "$directive" in
        block)
            op_name=$(echo "$line" | awk '{print $2}')
            id=$(op_id "$op_name")
            if [ -z "$id" ]; then
                echo "WARNING: Unknown operation '$op_name', skipping" >&2
                continue
            fi
            $BPFTOOL map update id "$POLICY_MAP_ID" \
                key hex $(le32 "$id") \
                value hex 01 2>/dev/null
            block_count=$((block_count + 1))
            echo "  block $op_name (op=$id)"
            ;;

        protect)
            if [ "$path_slot" -ge 8 ]; then
                echo "WARNING: Maximum 8 protected paths, skipping: $line" >&2
                continue
            fi

            path=$(echo "$line" | awk '{print $2}')
            # Remaining words are operation names
            ops=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i}')

            # Build bitmask of operations
            mask=0
            op_list=""
            for op_name in $ops; do
                id=$(op_id "$op_name")
                if [ -z "$id" ]; then
                    echo "WARNING: Unknown operation '$op_name', skipping" >&2
                    continue
                fi
                mask=$((mask | (1 << id)))
                op_list="$op_list $op_name"
            done

            if [ "$mask" -eq 0 ]; then
                echo "WARNING: No valid operations for path '$path', skipping" >&2
                continue
            fi

            # Write path string (pad to 64 bytes with nulls)
            path_hex=$(printf '%s' "$path" | xxd -p | sed 's/../& /g')
            path_len=${#path}
            pad_len=$((64 - path_len))
            pad_hex=""
            for i in $(seq 1 $pad_len); do
                pad_hex="$pad_hex 00"
            done

            $BPFTOOL map update id "$PATHS_MAP_ID" \
                key hex $(le32 "$path_slot") \
                value hex $path_hex $pad_hex 2>/dev/null

            # Write operations bitmask
            $BPFTOOL map update id "$PATH_OPS_MAP_ID" \
                key hex $(le32 "$path_slot") \
                value hex $(le32 "$mask") 2>/dev/null

            echo "  protect $path [$op_list] (slot=$path_slot mask=0x$(printf '%x' $mask))"
            path_slot=$((path_slot + 1))

            # Update path count
            $BPFTOOL map update id "$PATH_COUNT_MAP_ID" \
                key hex 00 00 00 00 \
                value hex $(le32 "$path_slot") 2>/dev/null
            ;;

        *)
            echo "WARNING: Unknown directive '$directive', skipping" >&2
            ;;
    esac
done < "$POLICY_FILE"

echo "Policy loaded: $block_count global blocks, $path_slot protected paths"
