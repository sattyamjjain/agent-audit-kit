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
INPUT_COMMENT_ON_PR="${11:-true}"
INPUT_FINGERPRINT_STRATEGY="${12:-auto}"

SARIF_FILE="agent-audit-results.sarif"
PR_SUMMARY_FILE="agent-audit-pr-summary.md"

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

# v0.3.1: always write the PR-summary markdown so the comment step below can use it.
CMD+=(--pr-summary-out "${PR_SUMMARY_FILE}")

# v0.3.2: thread through the SARIF fingerprint strategy.
CMD+=(--fingerprint-strategy "${INPUT_FINGERPRINT_STRATEGY}")

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

# ---------------------------------------------------------------------------
# v0.3.1: Sticky PR comment.
#
# When comment-on-pr=true AND this is a pull_request event AND we have a
# token, post/update a single sticky comment using the hidden marker
# `<!-- agent-audit-kit:pr-summary -->` that the renderer embeds. Any
# failure here is logged but does NOT change the scan exit code — the
# scan is the source of truth.
# ---------------------------------------------------------------------------
if [ "${INPUT_COMMENT_ON_PR}" = "true" ] \
    && [ -f "${PR_SUMMARY_FILE}" ] \
    && [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] \
    && [ -n "${GITHUB_TOKEN:-}" ]; then
    REPO="${GITHUB_REPOSITORY:-}"
    PR_NUMBER=""
    if [ -f "${GITHUB_EVENT_PATH:-}" ]; then
        PR_NUMBER=$(python3 -c 'import json,sys,os; d=json.load(open(os.environ["GITHUB_EVENT_PATH"])); print(d.get("pull_request",{}).get("number",""))' || echo "")
    fi

    if [ -n "${REPO}" ] && [ -n "${PR_NUMBER}" ]; then
        MARKER="<!-- agent-audit-kit:pr-summary -->"
        API="https://api.github.com/repos/${REPO}/issues/${PR_NUMBER}/comments"
        # Find an existing sticky comment.
        EXISTING=$(curl -fsSL \
            -H "Authorization: Bearer ${GITHUB_TOKEN}" \
            -H "Accept: application/vnd.github+json" \
            "${API}?per_page=100" | python3 -c \
            'import json,sys; rows=json.load(sys.stdin); m="<!-- agent-audit-kit:pr-summary -->"
for r in rows:
    if isinstance(r,dict) and m in (r.get("body") or ""):
        print(r["id"]); break' || true)
        BODY_JSON=$(python3 -c 'import json,sys; print(json.dumps({"body": open(sys.argv[1]).read()}))' "${PR_SUMMARY_FILE}")
        if [ -n "${EXISTING}" ]; then
            curl -fsSL -X PATCH \
                -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                -H "Accept: application/vnd.github+json" \
                -d "${BODY_JSON}" \
                "https://api.github.com/repos/${REPO}/issues/comments/${EXISTING}" >/dev/null \
                || echo "comment-on-pr: PATCH failed (non-fatal)"
        else
            curl -fsSL -X POST \
                -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                -H "Accept: application/vnd.github+json" \
                -d "${BODY_JSON}" \
                "${API}" >/dev/null \
                || echo "comment-on-pr: POST failed (non-fatal)"
        fi
        echo "comment-on-pr: sticky comment updated for PR #${PR_NUMBER}"
    fi
fi

exit "${SCAN_EXIT}"
