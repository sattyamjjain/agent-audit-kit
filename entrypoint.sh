#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# entrypoint.sh - Bridge GitHub Action inputs to the AgentAuditKit CLI
#
# Positional arguments (from action.yml):
#   $1  = path              (default: ".")
#   $2  = severity          (default: "low")
#   $3  = fail-on           (default: "high")
#   $4  = format            (default: "sarif")
#   $5  = upload-sarif      (default: "true")
#   $6  = include-user-config (default: "false")
#   $7  = rules             (default: "")
#   $8  = exclude-rules     (default: "")
#   $9  = ignore-paths      (default: "")
#   $10 = config            (default: "")
# ---------------------------------------------------------------------------

INPUT_PATH="${1:-.}"
INPUT_SEVERITY="${2:-low}"
INPUT_FAIL_ON="${3:-high}"
INPUT_FORMAT="${4:-sarif}"
INPUT_UPLOAD_SARIF="${5:-true}"
INPUT_INCLUDE_USER_CONFIG="${6:-false}"
INPUT_RULES="${7:-}"
INPUT_EXCLUDE_RULES="${8:-}"
INPUT_IGNORE_PATHS="${9:-}"
INPUT_CONFIG="${10:-}"

SARIF_FILE="agent-audit-results.sarif"

# ---------------------------------------------------------------------------
# Build CLI command
# ---------------------------------------------------------------------------
CMD=(agent-audit-kit scan "${INPUT_PATH}")
CMD+=(--format "${INPUT_FORMAT}")
CMD+=(--severity "${INPUT_SEVERITY}")
CMD+=(--fail-on "${INPUT_FAIL_ON}")
CMD+=(-o "${SARIF_FILE}")

if [ "${INPUT_INCLUDE_USER_CONFIG}" = "true" ]; then
    CMD+=(--include-user-config)
fi

if [ -n "${INPUT_RULES}" ]; then
    CMD+=(--rules "${INPUT_RULES}")
fi

if [ -n "${INPUT_EXCLUDE_RULES}" ]; then
    CMD+=(--exclude-rules "${INPUT_EXCLUDE_RULES}")
fi

if [ -n "${INPUT_IGNORE_PATHS}" ]; then
    CMD+=(--ignore-paths "${INPUT_IGNORE_PATHS}")
fi

if [ -n "${INPUT_CONFIG}" ]; then
    CMD+=(--config "${INPUT_CONFIG}")
fi

# ---------------------------------------------------------------------------
# Run scan and capture exit code
# ---------------------------------------------------------------------------
echo "::group::AgentAuditKit Scan"
echo "Running: ${CMD[*]}"

SCAN_EXIT=0
"${CMD[@]}" || SCAN_EXIT=$?

echo "::endgroup::"

# ---------------------------------------------------------------------------
# Parse SARIF for counts
# ---------------------------------------------------------------------------
FINDINGS_COUNT=0
CRITICAL_COUNT=0
HIGH_COUNT=0

if [ -f "${SARIF_FILE}" ]; then
    FINDINGS_COUNT=$(python3 -c "
import json, sys
try:
    with open('${SARIF_FILE}') as f:
        sarif = json.load(f)
    print(len(sarif.get('runs', [{}])[0].get('results', [])))
except Exception:
    print(0)
")

    CRITICAL_COUNT=$(python3 -c "
import json, sys
try:
    with open('${SARIF_FILE}') as f:
        sarif = json.load(f)
    results = sarif.get('runs', [{}])[0].get('results', [])
    rules = {r['id']: r for r in sarif.get('runs', [{}])[0].get('tool', {}).get('driver', {}).get('rules', [])}
    count = 0
    for r in results:
        rule = rules.get(r.get('ruleId', ''), {})
        score = float(rule.get('properties', {}).get('security-severity', '0'))
        if score >= 9.0:
            count += 1
    print(count)
except Exception:
    print(0)
")

    HIGH_COUNT=$(python3 -c "
import json, sys
try:
    with open('${SARIF_FILE}') as f:
        sarif = json.load(f)
    results = sarif.get('runs', [{}])[0].get('results', [])
    rules = {r['id']: r for r in sarif.get('runs', [{}])[0].get('tool', {}).get('driver', {}).get('rules', [])}
    count = 0
    for r in results:
        rule = rules.get(r.get('ruleId', ''), {})
        score = float(rule.get('properties', {}).get('security-severity', '0'))
        if 7.0 <= score < 9.0:
            count += 1
    print(count)
except Exception:
    print(0)
")
fi

# ---------------------------------------------------------------------------
# Set GitHub Action outputs
# ---------------------------------------------------------------------------
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
        echo "findings-count=${FINDINGS_COUNT}"
        echo "critical-count=${CRITICAL_COUNT}"
        echo "high-count=${HIGH_COUNT}"
        echo "sarif-file=${SARIF_FILE}"
        echo "exit-code=${SCAN_EXIT}"
    } >> "${GITHUB_OUTPUT}"
fi

# ---------------------------------------------------------------------------
# Copy SARIF to GITHUB_WORKSPACE for upload step
# ---------------------------------------------------------------------------
if [ -f "${SARIF_FILE}" ] && [ -n "${GITHUB_WORKSPACE:-}" ]; then
    cp "${SARIF_FILE}" "${GITHUB_WORKSPACE}/${SARIF_FILE}" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================="
echo "  AgentAuditKit Scan Summary"
echo "========================================="
echo "  Findings:  ${FINDINGS_COUNT}"
echo "  Critical:  ${CRITICAL_COUNT}"
echo "  High:      ${HIGH_COUNT}"
echo "  SARIF:     ${SARIF_FILE}"
echo "  Exit code: ${SCAN_EXIT}"
echo "========================================="

if [ "${SCAN_EXIT}" -eq 0 ]; then
    echo "  Result: PASSED"
elif [ "${SCAN_EXIT}" -eq 1 ]; then
    echo "  Result: FAILED (findings exceed --fail-on ${INPUT_FAIL_ON} threshold)"
else
    echo "  Result: ERROR (exit code ${SCAN_EXIT})"
fi
echo "========================================="
echo ""

# ---------------------------------------------------------------------------
# Write GitHub Actions job summary
# ---------------------------------------------------------------------------
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "## AgentAuditKit Scan Results"
        echo ""
        echo "| Metric | Count |"
        echo "|--------|-------|"
        echo "| Total findings | ${FINDINGS_COUNT} |"
        echo "| Critical | ${CRITICAL_COUNT} |"
        echo "| High | ${HIGH_COUNT} |"
        echo ""
        if [ "${SCAN_EXIT}" -eq 0 ]; then
            echo "**Result: PASSED**"
        elif [ "${SCAN_EXIT}" -eq 1 ]; then
            echo "**Result: FAILED** -- findings exceed \`--fail-on ${INPUT_FAIL_ON}\` threshold"
        else
            echo "**Result: ERROR** (exit code ${SCAN_EXIT})"
        fi
    } >> "${GITHUB_STEP_SUMMARY}"
fi

exit "${SCAN_EXIT}"
