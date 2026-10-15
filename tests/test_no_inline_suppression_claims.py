"""AAK reads no per-line suppression comment, so nothing may promise one.

Three rule pages told readers to silence a finding with
`# aak: ignore[RULE-ID]`, and one remediation with `# noqa: RULE-ID`. No
scanner reads either comment, so a reader who followed the advice kept the
finding. The ways to silence a finding are `exclude-rules` / `--exclude-rules`
for a rule and `ignore-paths` / `--ignore-paths` for a file. This test fails
if a doc page or a rule's text promises a comment again before a scanner
actually honours one.
"""
from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.rules.builtin import RULES

REPO = Path(__file__).resolve().parents[1]
_CLAIM = re.compile(r"aak:\s*ignore|noqa:\s*AAK-", re.IGNORECASE)


def _doc_files() -> list[Path]:
    return sorted((REPO / "docs").rglob("*.md"))


def test_no_doc_page_promises_a_suppression_comment() -> None:
    hits = [
        f"{path.relative_to(REPO)}:{number}"
        for path in _doc_files()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _CLAIM.search(line)
    ]
    assert not hits, f"these pages promise a suppression comment AAK never reads: {hits}"


def test_no_rule_text_promises_a_suppression_comment() -> None:
    hits = [
        rule_id
        for rule_id, rule in RULES.items()
        if _CLAIM.search(" ".join(filter(None, (rule.description, rule.remediation, rule.limitations))))
    ]
    assert not hits, f"these rules promise a suppression comment AAK never reads: {hits}"


def test_the_check_catches_both_spellings() -> None:
    assert _CLAIM.search("silence it with `# aak: ignore[AAK-SSRF-TOCTOU-001]`")
    assert _CLAIM.search("add a `# noqa: AAK-AGENT-HARNESS-SHARED-STATE-001` comment")
    assert not _CLAIM.search("list the file under `ignore-paths` in `.agent-audit-kit.yml`")
