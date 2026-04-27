"""SARIF → Markdown remediation hints.

`aak suggest <sarif> --pr` consumes a SARIF run and emits a Markdown
body suitable for `gh pr create --body-file -`. Per-finding sections
include the rule's primary description, severity, evidence, and the
`## Remediation` block from the corresponding `docs/rules/<id>.md` file.

Codemod application (`--apply-trivial`) is scaffolded for v0.3.9 —
the v0.3.8 ship lays out the file/test surface so the only remaining
work is writing libcst codemods.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path


_DOCS_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "docs" / "rules"
_REMEDIATION_RE = re.compile(
    r"##\s*Remediation\s*\n+(.+?)(?=\n##\s|\Z)",
    re.DOTALL,
)


def _remediation_snippet(rule_id: str) -> str | None:
    doc = _DOCS_RULES_DIR / f"{rule_id}.md"
    if not doc.is_file():
        return None
    text = doc.read_text(encoding="utf-8")
    m = _REMEDIATION_RE.search(text)
    return m.group(1).strip() if m else None


def sarif_to_markdown(sarif_text: str, pr_mode: bool = False) -> str:
    sarif = json.loads(sarif_text)
    runs = sarif.get("runs") or []
    by_rule: dict[str, list[dict]] = defaultdict(list)
    for run in runs:
        for result in run.get("results", []) or []:
            by_rule[result.get("ruleId", "<unknown>")].append(result)

    if not by_rule:
        return "AAK scan returned no findings.\n"

    lines: list[str] = []
    if pr_mode:
        lines.append("## AgentAuditKit findings\n")
    else:
        lines.append("# AgentAuditKit suggested remediations\n")

    for rule_id in sorted(by_rule):
        results = by_rule[rule_id]
        lines.append(f"### {rule_id} ({len(results)} finding{'s' if len(results) != 1 else ''})")
        for result in results[:5]:
            loc = (result.get("locations") or [{}])[0]
            phys = loc.get("physicalLocation") or {}
            artifact = phys.get("artifactLocation") or {}
            region = phys.get("region") or {}
            file_path = artifact.get("uri", "<unknown>")
            line = region.get("startLine", 0)
            msg = (result.get("message") or {}).get("text", "")
            lines.append(f"- `{file_path}:{line}` — {msg}")
        if len(results) > 5:
            lines.append(f"- ... and {len(results) - 5} more")

        snippet = _remediation_snippet(rule_id)
        if snippet:
            lines.append("")
            lines.append("**Remediation:**")
            lines.append("")
            lines.append(snippet)
        else:
            lines.append("")
            lines.append("_(No `docs/rules/" + rule_id + ".md` page yet — file an issue if this rule fired.)_")
        lines.append("")

    if pr_mode:
        lines.append("---")
        lines.append("")
        lines.append("Run `aak suggest <sarif> --apply-trivial` (v0.3.9+) to apply mechanically-safe fixes.")
    return "\n".join(lines) + "\n"
