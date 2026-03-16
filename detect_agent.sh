#!/bin/bash
# Detect whether the traced workload is an AI agent by analyzing syscall patterns.
# Takes differential snapshots of the stats BPF map, computes rate-based and
# ratio-based signals, and outputs a 0-100 score with breakdown.
#
# Usage: sudo ./detect_agent.sh [--samples N] [--interval S] [--json] [--watch]

set -e

SAMPLES=10
INTERVAL=3
JSON_OUTPUT=0
WATCH_MODE=0
BPFTOOL="${BPFTOOL:-bpftool}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --samples)  SAMPLES="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --json)     JSON_OUTPUT=1; shift ;;
        --watch)    WATCH_MODE=1; shift ;;
        -h|--help)
            echo "Usage: sudo ./detect_agent.sh [--samples N] [--interval S] [--json] [--watch]"
            echo ""
            echo "Options:"
            echo "  --samples N    Number of samples to take (default: 10)"
            echo "  --interval S   Seconds between samples (default: 3)"
            echo "  --json         Output results as JSON"
            echo "  --watch        Continuous re-scoring mode"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

STATS_ID=$($BPFTOOL map show --json 2>/dev/null | \
    python3 -c "import sys,json; ms=json.load(sys.stdin); print(next((m['id'] for m in ms if m.get('name')=='stats'),''))" 2>/dev/null)

if [ -z "$STATS_ID" ]; then
    echo "ERROR: Could not find stats map. Is the watcher loaded?" >&2
    exit 1
fi

# Build syscall name table once from ausyscall or headers
NAME_TABLE=$(python3 -c "
import subprocess, re

names = {}
try:
    out = subprocess.check_output(['ausyscall', '--dump'], stderr=subprocess.DEVNULL).decode()
    for line in out.strip().split('\n')[1:]:
        parts = line.split()
        if len(parts) >= 2:
            names[int(parts[1])] = parts[0]
except Exception:
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
")

# Snapshot the stats map once — outputs JSON blob of {syscall_name: count}
snapshot_stats() {
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

try:
    data = json.load(sys.stdin)
except Exception:
    data = []

agg = {}
for entry in data:
    key_bytes = entry.get('key', [])
    if isinstance(key_bytes, list):
        nr = 0
        for i, b in enumerate(key_bytes[:4]):
            nr |= parse_int(b) << (i * 8)
    else:
        nr = parse_int(key_bytes)

    values = entry.get('values', [])
    if not isinstance(values, list):
        values = [values]

    total_count = 0
    for v in values:
        val = v
        if isinstance(v, dict) and 'value' in v:
            val = v['value']
        if isinstance(val, dict):
            total_count += parse_int(val.get('count', 0))
        elif isinstance(val, list):
            raw = [parse_int(b) for b in val]
            if len(raw) >= 24:
                c = sum(raw[i] << (i*8) for i in range(8))
                total_count += c

    name = name_table.get(nr, f'sys_{nr}')
    agg[name] = agg.get(name, 0) + total_count

print(json.dumps(agg))
"
}

# Collect N+1 snapshots, compute deltas, then score
run_detection() {
    local window=$((SAMPLES * INTERVAL))

    if [ "$JSON_OUTPUT" = "0" ]; then
        echo "=== AI Agent Detection (${window}s observation window) ==="
        echo ""
        echo "Collecting $SAMPLES samples at ${INTERVAL}s intervals..."
    fi

    # Collect snapshots
    local snapshots=()
    for i in $(seq 0 "$SAMPLES"); do
        snapshots+=("$(snapshot_stats)")
        if [ "$i" -lt "$SAMPLES" ]; then
            sleep "$INTERVAL"
        fi
    done

    # Feed all snapshots into Python for scoring
    local snapshot_json="["
    for i in "${!snapshots[@]}"; do
        if [ "$i" -gt 0 ]; then
            snapshot_json+=","
        fi
        snapshot_json+="${snapshots[$i]}"
    done
    snapshot_json+="]"

    echo "$snapshot_json" | python3 -c "
import sys, json, math

snapshots = json.load(sys.stdin)
interval = $INTERVAL
samples = $SAMPLES
json_output = $JSON_OUTPUT
window = samples * interval

# Compute deltas between consecutive snapshots
deltas = []
for i in range(1, len(snapshots)):
    prev, curr = snapshots[i-1], snapshots[i]
    delta = {}
    all_keys = set(list(prev.keys()) + list(curr.keys()))
    for k in all_keys:
        d = curr.get(k, 0) - prev.get(k, 0)
        if d > 0:
            delta[k] = d
    deltas.append(delta)

if not deltas:
    if json_output:
        print(json.dumps({'score': 0, 'verdict': 'NO DATA', 'signals': {}}))
    else:
        print('No data collected.')
    sys.exit(0)

# Helper: get total count for a syscall across all deltas
def total_for(name):
    return sum(d.get(name, 0) for d in deltas)

def total_for_any(*names):
    return sum(total_for(n) for n in names)

# Helper: per-interval counts for a syscall
def per_interval(name):
    return [d.get(name, 0) for d in deltas]

def per_interval_any(*names):
    return [sum(d.get(n, 0) for n in names) for d in deltas]

# --- Signal 1: Execve Rate (max 25) ---
# Sigmoid curve, saturates at ~5/s
execve_total = total_for_any('execve', 'execveat')
execve_rate = execve_total / window if window > 0 else 0

def sigmoid(x, midpoint, steepness):
    return 1.0 / (1.0 + math.exp(-steepness * (x - midpoint)))

execve_score = round(25 * sigmoid(execve_rate, 1.5, 2.0))

# --- Signal 2: Connect:Execve Ratio (max 25) ---
# Gaussian centered at 1.0 — ratio near 1.0 means LLM-call-then-tool cycle
connect_total = total_for_any('connect')
if execve_total > 0 and connect_total > 0:
    ratio = connect_total / execve_total
    # Gaussian: peak at 1.0, sigma=0.5
    gauss = math.exp(-((ratio - 1.0) ** 2) / (2 * 0.5 ** 2))
    # Scale by activity level — need meaningful counts
    activity_factor = min(1.0, execve_total / 5.0)
    connect_execve_score = round(25 * gauss * activity_factor)
else:
    ratio = 0.0
    connect_execve_score = 0

# --- Signal 3: Fork Fan-Out (max 20) ---
# (clone + fork + clone3) / s — many short-lived children
fork_total = total_for_any('clone', 'clone3', 'fork', 'vfork')
fork_rate = fork_total / window if window > 0 else 0
fork_score = round(20 * sigmoid(fork_rate, 1.5, 2.0))

# --- Signal 4: Read-Write Churn (max 15) ---
# Balanced high-volume R/W — both openat and write counts high
openat_total = total_for_any('openat', 'openat2', 'open')
write_total = total_for_any('write', 'pwrite64')
read_total = total_for_any('read', 'pread64')

rw_total = read_total + write_total
if rw_total > 0:
    # Balance: 1.0 when read==write, 0 when all one-sided
    balance = 1.0 - abs(read_total - write_total) / rw_total
    # Volume: how much file churn (openat is the key indicator)
    volume_factor = min(1.0, openat_total / (window * 2.0)) if window > 0 else 0
    churn_score = round(15 * balance * volume_factor)
    churn_value = balance * volume_factor
else:
    churn_score = 0
    churn_value = 0.0

# --- Signal 5: Burst Pattern (max 15) ---
# Coefficient of variation of total syscall rate across windows
totals_per_interval = []
for d in deltas:
    totals_per_interval.append(sum(d.values()))

if len(totals_per_interval) >= 2:
    mean_rate = sum(totals_per_interval) / len(totals_per_interval)
    if mean_rate > 0:
        variance = sum((x - mean_rate) ** 2 for x in totals_per_interval) / len(totals_per_interval)
        cv = math.sqrt(variance) / mean_rate
    else:
        cv = 0.0
else:
    cv = 0.0

# High CV = bursty. Sigmoid centered at 0.5
burst_score = round(15 * sigmoid(cv, 0.5, 4.0))

# --- Total ---
total_score = execve_score + connect_execve_score + fork_score + churn_score + burst_score

# Verdict
if total_score <= 20:
    verdict = 'NOT AN AGENT'
elif total_score <= 45:
    verdict = 'UNLIKELY'
elif total_score <= 65:
    verdict = 'POSSIBLE AI AGENT'
elif total_score <= 85:
    verdict = 'LIKELY AI AGENT'
else:
    verdict = 'ALMOST CERTAINLY AI AGENT'

if json_output:
    result = {
        'score': total_score,
        'verdict': verdict,
        'window_seconds': window,
        'signals': {
            'execve_rate': {
                'value': round(execve_rate, 2),
                'unit': '/s',
                'score': execve_score,
                'max': 25
            },
            'connect_execve_ratio': {
                'value': round(ratio, 2),
                'score': connect_execve_score,
                'max': 25
            },
            'fork_fanout': {
                'value': round(fork_rate, 2),
                'unit': '/s',
                'score': fork_score,
                'max': 20
            },
            'rw_churn': {
                'value': round(churn_value, 2),
                'score': churn_score,
                'max': 15
            },
            'burst_pattern': {
                'value': round(cv, 2),
                'unit': 'cv',
                'score': burst_score,
                'max': 15
            }
        }
    }
    print(json.dumps(result, indent=2))
else:
    def bar(score, max_score, width=25):
        filled = round(width * score / max_score) if max_score > 0 else 0
        return '\u2588' * filled + '\u2591' * (width - filled)

    print()
    print(f'Score: {total_score}/100 \u2014 {verdict}')
    print()
    print('Signal Breakdown:')
    print(f'  Execve Rate ({execve_rate:.1f}/s)          [{execve_score:>2}/{25}]  {bar(execve_score, 25)}')
    print(f'  Connect:Execve Ratio ({ratio:.1f})   [{connect_execve_score:>2}/{25}]  {bar(connect_execve_score, 25)}')
    print(f'  Fork Fan-Out ({fork_rate:.1f}/s)         [{fork_score:>2}/{20}]  {bar(fork_score, 20, 20)}')
    print(f'  Read-Write Churn ({churn_value:.1f})       [{churn_score:>2}/{15}]  {bar(churn_score, 15, 15)}')
    print(f'  Burst Pattern (CV={cv:.1f})       [{burst_score:>2}/{15}]  {bar(burst_score, 15, 15)}')
    print()
"
}

if [ "$WATCH_MODE" = "1" ]; then
    while true; do
        clear
        run_detection
        echo ""
        echo "(Ctrl-C to stop, re-scoring in ${INTERVAL}s...)"
        sleep "$INTERVAL"
    done
else
    run_detection
fi
