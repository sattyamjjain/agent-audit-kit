#!/usr/bin/env python3
"""Generate the public OWASP coverage leaderboard (issue #67).

Emits two Markdown tables from the **live rule registry** so they cannot drift:

  docs/coverage/owasp-agentic-top10.md   (ASI01–ASI10)
  docs/coverage/owasp-mcp-top10.md       (MCP01:2025–MCP10:2025)

Each OWASP category maps to the AAK rule IDs that reference it, plus a
transparent coverage label — Full / Partial / None — defined by a *published*
threshold (below), not by self-assessment. Run ``--check`` in CI to fail if the
committed tables are stale.

Deterministic + offline: pure functions of ``agent_audit_kit.rules.builtin.RULES``
plus the canonical taxonomy titles already shipped in the codebase
(``ASI_TITLES`` from ``gen_owasp_coverage.py``; ``OWASP_MCP`` from
``agent_audit_kit.output.owasp_report``) — no network, no invented titles.
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

# Reuse the canonical taxonomy titles — do not duplicate.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_owasp_coverage import ASI_TITLES  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_audit_kit.output.owasp_report import OWASP_MCP  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
COVERAGE_DIR = REPO_ROOT / "docs" / "coverage"

AGENTIC_PAGE = COVERAGE_DIR / "owasp-agentic-top10.md"
MCP_PAGE = COVERAGE_DIR / "owasp-mcp-top10.md"

# Transparent coverage thresholds (published in the methodology header so the
# label is reproducible and cannot be inflated): Full = >= 3 mapped rules,
# Partial = 1–2, None = 0.
FULL_THRESHOLD = 3

OWASP_AGENTIC_URL = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
OWASP_MCP_URL = "https://github.com/OWASP/www-project-mcp-top-10"
# Microsoft Agent Governance Toolkit (open-sourced 2026-04-02, MIT) — states
# 10/10 OWASP Agentic coverage. We report AAK's honest per-category rule counts
# next to it. Sources: the launch blog + the toolkit repo.
MS_TOOLKIT_URL = "https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/"
MS_TOOLKIT_REPO = "https://github.com/microsoft/agent-governance-toolkit"


def _coverage_by(field: str) -> dict[str, list[str]]:
    """Map each OWASP code -> sorted rule IDs that reference it (live registry)."""
    from agent_audit_kit.rules.builtin import RULES

    cov: dict[str, list[str]] = defaultdict(list)
    for rid, rule in sorted(RULES.items()):
        for code in getattr(rule, field) or []:
            cov[code].append(rid)
    return dict(cov)


def _label(n: int) -> str:
    if n == 0:
        return "None"
    if n < FULL_THRESHOLD:
        return "Partial"
    return "Full"


def _methodology(kind: str, project_url: str, total: int, covered: int) -> list[str]:
    return [
        f"# OWASP {kind} — AgentAuditKit coverage leaderboard",
        "",
        "> **Generated file — do not edit by hand.** Run "
        "`python scripts/gen_coverage.py` to regenerate; CI fails if it drifts "
        "(`scripts/gen_coverage.py --check`).",
        "",
        "## Methodology",
        "",
        "Every row is derived from the live AAK rule registry "
        "(`agent_audit_kit/rules/builtin.py`): a rule lands in a category iff it "
        "declares that category in its OWASP references. Coverage labels are "
        f"**reproducible thresholds, not self-assessment** — **Full** = ≥ "
        f"{FULL_THRESHOLD} mapped rules, **Partial** = 1–2, **None** = 0. "
        "Deterministic and offline: same registry → same table, byte-for-byte.",
        "",
        f"**AAK covers {covered}/{total} categories** with ≥ 1 deterministic "
        "rule. Rule IDs are listed so the claim is auditable — click through to "
        f"`docs/rules/`. Source taxonomy: <{project_url}>.",
        "",
    ]


def render_agentic() -> str:
    cov = _coverage_by("owasp_agentic_references")
    covered = sum(1 for a in ASI_TITLES if cov.get(a))
    lines = _methodology(
        "Top 10 for Agentic Applications (2026)", OWASP_AGENTIC_URL, len(ASI_TITLES), covered
    )
    lines += ["| OWASP | Title | Coverage | # rules | Rule IDs |",
              "| --- | --- | :---: | :---: | --- |"]
    for asi in sorted(ASI_TITLES):
        rules = cov.get(asi, [])
        rule_text = ", ".join(f"`{r}`" for r in rules) or "—"
        lines.append(f"| **{asi}** | {ASI_TITLES[asi]} | {_label(len(rules))} | {len(rules)} | {rule_text} |")
    lines += ["", _toolkit_note(covered, len(ASI_TITLES)), ""]
    return "\n".join(lines)


def render_mcp() -> str:
    cov = _coverage_by("owasp_mcp_references")
    covered = sum(1 for c in OWASP_MCP if cov.get(c))
    lines = _methodology(
        "MCP Top 10 (2025)", OWASP_MCP_URL, len(OWASP_MCP), covered
    )
    lines += ["| OWASP | Title | Coverage | # rules | Rule IDs |",
              "| --- | --- | :---: | :---: | --- |"]
    for code in sorted(OWASP_MCP):
        rules = cov.get(code, [])
        rule_text = ", ".join(f"`{r}`" for r in rules) or "—"
        lines.append(f"| **{code}** | {OWASP_MCP[code]} | {_label(len(rules))} | {len(rules)} | {rule_text} |")
    lines += [""]
    return "\n".join(lines)


def _toolkit_note(covered: int, total: int) -> str:
    return "\n".join([
        "## Coverage vs. named toolkits",
        "",
        f"The Microsoft Agent Governance Toolkit "
        f"([blog]({MS_TOOLKIT_URL}) · [repo]({MS_TOOLKIT_REPO}), open-sourced "
        "2026-04-02, MIT) states 10/10 OWASP Agentic coverage. AgentAuditKit "
        "does not claim a headline number here — it reports the per-category rule "
        f"counts above, which are **reproducible from the registry** ({covered}/"
        f"{total} categories carry ≥ 1 rule, each with named, clickable rule "
        "IDs). No account, no cloud call, no self-scored grade: the table is the "
        "evidence. Note the two are different layers — the Microsoft toolkit is "
        "**runtime** policy enforcement; AAK is a **static, offline** scanner "
        "that flags the same risk classes before deploy — so this is a coverage "
        "cross-reference, not a head-to-head benchmark. Source OWASP projects: "
        f"[Agentic Top 10]({OWASP_AGENTIC_URL}) · [MCP Top 10]({OWASP_MCP_URL}).",
    ])


def _targets() -> list[tuple[Path, str]]:
    return [(AGENTIC_PAGE, render_agentic()), (MCP_PAGE, render_mcp())]


def write() -> None:
    COVERAGE_DIR.mkdir(parents=True, exist_ok=True)
    for path, content in _targets():
        path.write_text(content.rstrip() + "\n", encoding="utf-8")
        print(f"wrote {path.relative_to(REPO_ROOT)}")


def check() -> int:
    stale: list[str] = []
    for path, content in _targets():
        want = content.rstrip() + "\n"
        have = path.read_text(encoding="utf-8") if path.is_file() else ""
        if have != want:
            stale.append(str(path.relative_to(REPO_ROOT)))
    if stale:
        sys.stderr.write(
            "Stale OWASP coverage tables: " + ", ".join(stale)
            + "\nRun `python scripts/gen_coverage.py` and commit.\n"
        )
        return 1
    print("OWASP coverage tables are up to date.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="Fail if committed tables are stale.")
    args = ap.parse_args()
    if args.check:
        return check()
    write()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
