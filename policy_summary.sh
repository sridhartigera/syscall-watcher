#!/bin/bash
# Print policy enforcement summary: denial counts and protected paths.
#
# Usage: sudo ./policy_summary.sh

set -e

BPFTOOL="${BPFTOOL:-bpftool}"

# Find maps by name
find_map() {
    $BPFTOOL map show --json 2>/dev/null | \
        python3 -c "import sys,json; ms=json.load(sys.stdin); print(next((m['id'] for m in ms if m.get('name')=='$1'),''))" 2>/dev/null
}

STATS_ID=$(find_map "policy_stats")
PATHS_ID=$(find_map "policy_protected_paths")
PATH_OPS_ID=$(find_map "policy_path_ops")
PATH_COUNT_ID=$(find_map "policy_path_count")
POLICY_MAP_ID=$(find_map "policy_map")

if [ -z "$STATS_ID" ]; then
    echo "ERROR: Could not find policy_stats map. Is the policy loaded?"
    exit 1
fi

echo "=== Syscall Policy Enforcement — Summary ==="
echo ""

# Dump stats and display
$BPFTOOL map dump id "$STATS_ID" --json 2>/dev/null | python3 -c "
import sys, json

OP_NAMES = {
    0: 'exec', 1: 'file_open', 2: 'connect', 3: 'socket',
    4: 'bind', 5: 'listen', 6: 'kill', 7: 'unlink',
    8: 'rename', 9: 'mkdir', 10: 'rmdir', 11: 'read',
    12: 'write', 13: 'fork'
}

def parse_int(x):
    if isinstance(x, str):
        return int(x, 0)
    return int(x) if x else 0

try:
    data = json.load(sys.stdin)
except:
    data = []

agg = {}
for entry in data:
    # Parse key: 4-byte LE operation ID
    key_bytes = entry.get('key', [])
    if isinstance(key_bytes, list):
        op = 0
        for i, b in enumerate(key_bytes[:4]):
            op |= parse_int(b) << (i * 8)
    else:
        op = parse_int(key_bytes)

    # Per-CPU map: sum across CPUs
    values = entry.get('values', [])
    if not isinstance(values, list):
        values = [values]

    total = 0
    for v in values:
        val = v
        if isinstance(v, dict) and 'value' in v:
            val = v['value']
        if isinstance(val, (int, str)):
            total += parse_int(val)
        elif isinstance(val, list):
            # Raw bytes — u64 = 8 bytes LE
            raw = [parse_int(b) for b in val]
            if len(raw) >= 8:
                total += sum(raw[i] << (i*8) for i in range(8))

    agg[op] = agg.get(op, 0) + total

if agg:
    print(f'{\"OPERATION\":<16} {\"DENIALS\":>10}')
    print('-' * 28)
    for op in sorted(agg.keys()):
        name = OP_NAMES.get(op, f'op_{op}')
        print(f'{name:<16} {agg[op]:>10,}')
    print('-' * 28)
    print(f'{\"TOTAL\":<16} {sum(agg.values()):>10,}')
else:
    print('No denials recorded yet.')
"

echo ""

# Show protected paths if any
if [ -n "$PATH_COUNT_ID" ] && [ -n "$PATHS_ID" ] && [ -n "$PATH_OPS_ID" ]; then
    $BPFTOOL map dump id "$PATH_COUNT_ID" --json 2>/dev/null | python3 -c "
import sys, json, subprocess

OP_NAMES = {
    0: 'exec', 1: 'file_open', 2: 'connect', 3: 'socket',
    4: 'bind', 5: 'listen', 6: 'kill', 7: 'unlink',
    8: 'rename', 9: 'mkdir', 10: 'rmdir', 11: 'read',
    12: 'write', 13: 'fork'
}

def parse_int(x):
    if isinstance(x, str):
        return int(x, 0)
    return int(x) if x else 0

try:
    data = json.load(sys.stdin)
except:
    data = []

count = 0
for entry in data:
    val = entry.get('value', 0)
    if isinstance(val, list):
        raw = [parse_int(b) for b in val]
        count = sum(raw[i] << (i*8) for i in range(min(4, len(raw))))
    else:
        count = parse_int(val)

if count == 0:
    print('No protected paths configured.')
    sys.exit(0)

print(f'Protected paths ({count}):')
print(f'{\"PATH\":<24} {\"BLOCKED OPERATIONS\":<40}')
print('-' * 64)

# Read paths and ops
paths_data = json.loads(subprocess.check_output(
    ['$BPFTOOL', 'map', 'dump', 'id', '$PATHS_ID', '--json'],
    stderr=subprocess.DEVNULL
).decode())

ops_data = json.loads(subprocess.check_output(
    ['$BPFTOOL', 'map', 'dump', 'id', '$PATH_OPS_ID', '--json'],
    stderr=subprocess.DEVNULL
).decode())

paths = {}
for entry in paths_data:
    key_bytes = entry.get('key', [])
    if isinstance(key_bytes, list):
        slot = 0
        for i, b in enumerate(key_bytes[:4]):
            slot |= parse_int(b) << (i * 8)
    else:
        slot = parse_int(key_bytes)

    val = entry.get('value', [])
    if isinstance(val, list):
        path_bytes = bytes([parse_int(b) for b in val])
        path = path_bytes.split(b'\x00')[0].decode('utf-8', errors='replace')
        if path:
            paths[slot] = path

ops = {}
for entry in ops_data:
    key_bytes = entry.get('key', [])
    if isinstance(key_bytes, list):
        slot = 0
        for i, b in enumerate(key_bytes[:4]):
            slot |= parse_int(b) << (i * 8)
    else:
        slot = parse_int(key_bytes)

    val = entry.get('value', [])
    if isinstance(val, list):
        raw = [parse_int(b) for b in val]
        mask = sum(raw[i] << (i*8) for i in range(min(4, len(raw))))
    else:
        mask = parse_int(val)
    ops[slot] = mask

for slot in range(count):
    path = paths.get(slot, '???')
    mask = ops.get(slot, 0)
    op_names = [OP_NAMES[i] for i in range(14) if mask & (1 << i)]
    print(f'{path:<24} {\" \".join(op_names):<40}')
"
fi
