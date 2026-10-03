"""The VS Code extension reads keys that `scan --format json` actually writes.

`vscode-extension/src/extension.ts` runs `agent-audit-kit scan <folder> --format
json --severity <sev>` and reads stdout through its `AuditFinding` and
`AuditReport` interfaces. The extension has no test suite and no workflow builds
it, so renaming a camelCase key in `output/json_report.py` would leave every
editor diagnostic `undefined` with nothing failing anywhere. This pins the two
sides together from the Python side.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_audit_kit.models import ScanResult, Severity
from agent_audit_kit.output.json_report import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners._helpers import make_finding

EXTENSION_TS = Path(__file__).resolve().parent.parent / "vscode-extension" / "src" / "extension.ts"


def _block(text: str, opener: str) -> str:
    """The body of the `{...}` that starts at `opener`, nested braces included."""
    start = text.index(opener) + len(opener)
    depth = 1
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i]
    raise AssertionError(f"unbalanced braces after {opener!r}")


def _fields(body: str) -> dict[str, bool]:
    """Top-level `name: type` / `name?: type` members of a TS object type -> optional?"""
    fields: dict[str, bool] = {}
    depth = 0
    for line in body.splitlines():
        if depth == 0:
            match = re.match(r"\s*(\w+)(\?)?:", line)
            if match:
                fields[match.group(1)] = bool(match.group(2))
        depth += line.count("{") - line.count("}")
    return fields


def _ts() -> str:
    return EXTENSION_TS.read_text(encoding="utf-8")


def _report() -> dict:
    rule_id = next(rid for rid, rule in RULES.items() if rule.severity is Severity.HIGH)
    finding = make_finding(rule_id, ".mcp.json", "evidence", 3)
    result = ScanResult(findings=[finding], files_scanned=1, rules_evaluated=len(RULES))
    return json.loads(format_results(result))


def test_every_finding_key_the_extension_reads_is_written() -> None:
    wanted = _fields(_block(_ts(), "interface AuditFinding {"))
    assert len(wanted) > 5, f"parsed suspiciously few AuditFinding fields: {wanted}"
    written = _report()["findings"][0]
    missing = sorted(k for k, optional in wanted.items() if not optional and k not in written)
    assert not missing, f"extension.ts AuditFinding reads keys json_report.py no longer writes: {missing}"


def test_every_report_key_the_extension_reads_is_written() -> None:
    ts = _ts()
    report = _report()
    wanted = _fields(_block(ts, "interface AuditReport {"))
    missing = sorted(k for k, optional in wanted.items() if not optional and k not in report)
    assert not missing, f"extension.ts AuditReport reads keys json_report.py no longer writes: {missing}"

    summary_wanted = _fields(_block(_block(ts, "interface AuditReport {"), "summary: {"))
    summary_missing = sorted(k for k in summary_wanted if k not in report["summary"])
    assert not summary_missing, f"extension.ts reads summary keys json_report.py no longer writes: {summary_missing}"


def test_the_severity_union_matches_the_enum() -> None:
    match = re.search(r"severity:\s*((?:\"\w+\"\s*\|?\s*)+);", _block(_ts(), "interface AuditFinding {"))
    assert match, "AuditFinding.severity is no longer a string-literal union"
    union = set(re.findall(r"\"(\w+)\"", match.group(1)))
    assert union == {s.value for s in Severity}, (
        f"extension.ts severity union {sorted(union)} != Severity values {sorted(s.value for s in Severity)}"
    )
