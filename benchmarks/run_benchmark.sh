#!/usr/bin/env bash
# run_benchmark.sh -- Run AgentAuditKit against bundled sample configs
# Usage: bash benchmarks/run_benchmark.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SAMPLE_DIR="$SCRIPT_DIR/sample_configs"

# Ensure agent-audit-kit is available
if ! python3 -c "import agent_audit_kit" 2>/dev/null; then
    echo "ERROR: agent_audit_kit is not installed."
    echo "       Run: pip install -e '$PROJECT_ROOT'"
    exit 1
fi

echo "============================================================"
echo "  AgentAuditKit Sample Benchmark"
echo "============================================================"
echo ""

declare -a NAMES=()
declare -a TOTALS=()
declare -a CRITS=()
declare -a HIGHS=()
declare -a MEDS=()
declare -a LOWS=()
declare -a INFOS=()

for config in "$SAMPLE_DIR"/sample_*.json; do
    filename="$(basename "$config")"
    tmpdir="$(mktemp -d)"

    # Place config as .mcp.json so the scanner discovers it
    cp "$config" "$tmpdir/.mcp.json"

    # Run scan in JSON mode, capture output
    output="$(python3 -m agent_audit_kit.cli scan "$tmpdir" --format json 2>/dev/null || true)"
    rm -rf "$tmpdir"

    if [ -z "$output" ]; then
        NAMES+=("$filename")
        TOTALS+=(0)
        CRITS+=(0)
        HIGHS+=(0)
        MEDS+=(0)
        LOWS+=(0)
        INFOS+=(0)
        continue
    fi

    total="$(echo "$output"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['summary']['total'])" 2>/dev/null || echo 0)"
    crit="$(echo "$output"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['summary']['critical'])" 2>/dev/null || echo 0)"
    high="$(echo "$output"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['summary']['high'])" 2>/dev/null || echo 0)"
    medium="$(echo "$output" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['summary']['medium'])" 2>/dev/null || echo 0)"
    low="$(echo "$output"    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['summary']['low'])" 2>/dev/null || echo 0)"
    info="$(echo "$output"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['summary']['info'])" 2>/dev/null || echo 0)"

    NAMES+=("$filename")
    TOTALS+=("$total")
    CRITS+=("$crit")
    HIGHS+=("$high")
    MEDS+=("$medium")
    LOWS+=("$low")
    INFOS+=("$info")
done

# Print summary table
printf "%-35s %6s %6s %6s %6s %6s %6s\n" "Config" "Total" "Crit" "High" "Med" "Low" "Info"
printf "%-35s %6s %6s %6s %6s %6s %6s\n" "-----------------------------------" "------" "------" "------" "------" "------" "------"

grand_total=0
for i in "${!NAMES[@]}"; do
    printf "%-35s %6d %6d %6d %6d %6d %6d\n" \
        "${NAMES[$i]}" "${TOTALS[$i]}" "${CRITS[$i]}" "${HIGHS[$i]}" "${MEDS[$i]}" "${LOWS[$i]}" "${INFOS[$i]}"
    grand_total=$((grand_total + TOTALS[i]))
done

echo ""
echo "------------------------------------------------------------"
printf "%-35s %6d\n" "GRAND TOTAL" "$grand_total"
echo "============================================================"
echo ""
echo "Done. Scanned ${#NAMES[@]} sample configs with $grand_total total findings."
