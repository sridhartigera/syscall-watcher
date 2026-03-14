#!/bin/bash
# Print cumulative syscall stats every N seconds.
# Reads the per-CPU "stats" BPF hash map and sums across CPUs.
#
# Usage: sudo ./summary.sh [interval_seconds]

set -e

INTERVAL="${1:-5}"
BPFTOOL="${BPFTOOL:-bpftool}"

# Find maps
STATS_ID=$($BPFTOOL map show --json 2>/dev/null | \
    python3 -c "import sys,json; ms=json.load(sys.stdin); print(next((m['id'] for m in ms if m.get('name')=='stats'),''))" 2>/dev/null)

NAMES_ID=$($BPFTOOL map show --json 2>/dev/null | \
    python3 -c "import sys,json; ms=json.load(sys.stdin); print(next((m['id'] for m in ms if m.get('name')=='syscall_names'),''))" 2>/dev/null)

if [ -z "$STATS_ID" ]; then
    echo "ERROR: Could not find stats map. Is the watcher loaded?"
    exit 1
fi

# Build syscall name table once from ausyscall or headers
build_name_table() {
    python3 -c "
import subprocess, sys

names = {}
try:
    out = subprocess.check_output(['ausyscall', '--dump'], stderr=subprocess.DEVNULL).decode()
    for line in out.strip().split('\n')[1:]:
        parts = line.split()
        if len(parts) >= 2:
            names[int(parts[1])] = parts[0]
except:
    import re
    for hdr in ['/usr/include/asm/unistd_64.h', '/usr/include/x86_64-linux-gnu/asm/unistd_64.h']:
        try:
            with open(hdr) as f:
                for line in f:
                    m = re.match(r'#define __NR_(\w+)\s+(\d+)', line)
                    if m:
                        names[int(m.group(2))] = m.group(1)
            break
        except FileNotFoundError:
            continue

for nr, name in sorted(names.items()):
    print(f'{nr} {name}')
"
}

# Cache name table
NAME_TABLE=$(build_name_table)

while true; do
    clear
    echo "=== Syscall Watcher — Cumulative Stats (every ${INTERVAL}s) ==="
    echo ""

    # Dump raw and parse
    $BPFTOOL map dump id "$STATS_ID" --json 2>/dev/null | python3 -c "
import sys, json

name_table = {}
for line in '''${NAME_TABLE}'''.strip().split('\n'):
    parts = line.split(None, 1)
    if len(parts) == 2:
        name_table[int(parts[0])] = parts[1]

def parse_int(x):
    if isinstance(x, str):
        return int(x, 0)
    return int(x) if x else 0

def get_name(nr):
    return name_table.get(nr, f'sys_{nr}')

try:
    data = json.load(sys.stdin)
except:
    data = []

agg = {}
for entry in data:
    # Parse key: 4-byte LE syscall number
    key_bytes = entry.get('key', [])
    if isinstance(key_bytes, list):
        nr = 0
        for i, b in enumerate(key_bytes[:4]):
            nr |= parse_int(b) << (i * 8)
    else:
        nr = parse_int(key_bytes)

    # Per-CPU map: 'values' is a list with one entry per CPU
    # Each CPU entry may look like:
    #   {\"cpu\": 0, \"value\": {\"count\": N, \"bytes_in\": N, \"bytes_out\": N}}
    # or the per-CPU values might be raw lists
    values = entry.get('values', [])
    if not isinstance(values, list):
        values = [values]

    total_count = 0
    total_in = 0
    total_out = 0

    for v in values:
        val = v
        # Unwrap {\"cpu\": N, \"value\": {...}}
        if isinstance(v, dict) and 'value' in v:
            val = v['value']
        if isinstance(val, dict):
            total_count += parse_int(val.get('count', 0))
            total_in += parse_int(val.get('bytes_in', 0))
            total_out += parse_int(val.get('bytes_out', 0))
        elif isinstance(val, list):
            # Raw bytes — struct is 3x u64 = 24 bytes LE
            raw = [parse_int(b) for b in val]
            if len(raw) >= 24:
                c = sum(raw[i] << (i*8) for i in range(8))
                bi = sum(raw[8+i] << (i*8) for i in range(8))
                bo = sum(raw[16+i] << (i*8) for i in range(8))
                total_count += c
                total_in += bi
                total_out += bo

    if nr not in agg:
        agg[nr] = [0, 0, 0]
    agg[nr][0] += total_count
    agg[nr][1] += total_in
    agg[nr][2] += total_out

def fmt_bytes(b):
    if b == 0:
        return '-'
    if b < 1024:
        return f'{b} B'
    if b < 1024*1024:
        return f'{b/1024:.1f} KB'
    if b < 1024*1024*1024:
        return f'{b/(1024*1024):.1f} MB'
    return f'{b/(1024*1024*1024):.1f} GB'

print(f'{\"SYSCALL\":<20} {\"COUNT\":>10} {\"BYTES IN\":>12} {\"BYTES OUT\":>12}')
print('-' * 56)

for nr, (count, bi, bo) in sorted(agg.items(), key=lambda x: x[1][0], reverse=True):
    name = get_name(nr)
    print(f'{name:<20} {count:>10,} {fmt_bytes(bi):>12} {fmt_bytes(bo):>12}')

tc = sum(v[0] for v in agg.values())
ti = sum(v[1] for v in agg.values())
to_ = sum(v[2] for v in agg.values())
print('-' * 56)
print(f'{\"TOTAL\":<20} {tc:>10,} {fmt_bytes(ti):>12} {fmt_bytes(to_):>12}')
"
    sleep "$INTERVAL"
done
