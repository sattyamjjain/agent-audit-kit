#!/usr/bin/env bash
# Validate all vulnerable config examples produce expected findings.
# Usage: bash examples/run-all-examples.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXAMPLES_DIR="$SCRIPT_DIR/vulnerable-configs"
PASS=0
FAIL=0

for dir in "$EXAMPLES_DIR"/*/; do
    name=$(basename "$dir")
    expected_file="$dir/expected-findings.json"

    if [ ! -f "$expected_file" ]; then
        echo "SKIP  $name (no expected-findings.json)"
        continue
    fi

    # Run scanner
    output=$(agent-audit-kit scan "$dir" --format json 2>/dev/null) || true

    # Extract actual rule IDs
    actual_rules=$(echo "$output" | python3 -c "
import sys, json
d = json.load(sys.stdin)
rules = sorted(set(f['ruleId'] for f in d['findings']))
print(' '.join(rules))
" 2>/dev/null) || actual_rules=""

    # Extract expected rule IDs
    expected_rules=$(python3 -c "
import json
d = json.load(open('$expected_file'))
print(' '.join(sorted(d['expectedRules'])))
" 2>/dev/null) || expected_rules=""

    # Compare: check that all expected rules are present in actual
    missing=""
    for rule in $expected_rules; do
        if ! echo "$actual_rules" | grep -qw "$rule"; then
            missing="$missing $rule"
        fi
    done

    if [ -z "$missing" ]; then
        echo "PASS  $name  [$actual_rules]"
        PASS=$((PASS + 1))
    else
        echo "FAIL  $name  missing:$missing  actual: [$actual_rules]"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
