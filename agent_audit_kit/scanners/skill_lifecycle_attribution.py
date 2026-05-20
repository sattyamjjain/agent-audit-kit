"""Skill lifecycle outcome-attribution detector.

Anchored to *SkillsVote: Lifecycle Governance of Agent Skills from
Collection, Recommendation to Evolution* (Liu et al., arXiv:2605.18401,
2026-05-18). The paper's central claim (verified via WebFetch on
2026-05-20):

  "After execution, it decomposes trajectories into skill-linked
   subtasks, attributes outcomes to skill use, agent exploration,
   environment, and result signals."

The defensive code shape: a Skill `execute()` function that mutates
persistent state (writes to disk, makes side-effecting HTTP/DB calls)
without emitting a structured outcome-attribution record. Without
attribution, the SkillsVote evidence-gated update loop cannot
operate — repeat invocations of a buggy skill silently degrade
agent behavior.

**Research-grade** (MEDIUM severity). The SkillsVote paper does not
prescribe a specific Python decorator or attribution-record schema;
this rule catches the most concrete shape (skill execute mutating
state + missing attribution call). YAML frontmatter checks the
prompt suggested (`requires_search`, `depends_on`) are intentionally
NOT shipped — the paper does not define those fields.

Detector contract:
    scan(project_root) -> (list[Finding], set[str])
"""
from __future__ import annotations

import ast
from pathlib import Path

from agent_audit_kit.models import Category, Finding, Severity


# Heuristic: a function is treated as a Skill execute() if it is
# decorated with @skill / @Skill / @skill_fn / @register_skill /
# @skills_vote_skill, OR if its name is exactly `execute` /
# `run_skill` / `invoke_skill` and lives in a file whose path
# segment contains "skill" / "skills" (case-insensitive).
_SKILL_DECORATORS: frozenset[str] = frozenset({
    "skill", "skill_fn", "register_skill", "skills_vote_skill",
})
_SKILL_FUNCTION_NAMES: frozenset[str] = frozenset({
    "execute", "run_skill", "invoke_skill", "skill_main",
})

# Sinks that imply persistent-state mutation.
_PERSISTENT_MUTATION_NAMES: frozenset[str] = frozenset({
    # File / DB writes
    "write_text", "write_bytes", "save", "dump", "persist",
    "commit", "execute_insert", "execute_update",
    # HTTP side-effecting verbs (best-effort heuristic)
    "post", "put", "patch", "delete",
    # Common ORM patterns
    "session_add", "session_commit", "session_merge",
})

# Calls that count as outcome attribution. The presence of any of
# these in the function body short-circuits the rule.
_ATTRIBUTION_CALL_NAMES: frozenset[str] = frozenset({
    "record_outcome", "log_outcome", "attribute_outcome",
    "skill_attribution", "report_outcome", "emit_attribution",
    "track_outcome", "outcome_signal", "skill_outcome",
})


def _is_skill_decorator(decorator: ast.expr) -> bool:
    if isinstance(decorator, ast.Name) and decorator.id in _SKILL_DECORATORS:
        return True
    if isinstance(decorator, ast.Attribute) and decorator.attr in _SKILL_DECORATORS:
        return True
    if isinstance(decorator, ast.Call):
        return _is_skill_decorator(decorator.func)
    return False


def _is_skill_path(path: Path) -> bool:
    # Match an exact directory segment named `skill` / `skills` /
    # `agent-skills` / `.skills` rather than any-substring "skill",
    # so pytest tmp_path directories with test-name segments
    # (e.g. `test_skill_*`) don't false-positive.
    parts_lower = [p.lower() for p in path.parts]
    skill_segs = {"skill", "skills", "agent-skills", ".skills", "skill-pack"}
    return any(p in skill_segs for p in parts_lower)


def _call_name(expr: ast.expr) -> str | None:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return expr.attr
    return None


def _function_qualifies_as_skill(fn: ast.FunctionDef | ast.AsyncFunctionDef, path: Path) -> bool:
    if any(_is_skill_decorator(d) for d in fn.decorator_list):
        return True
    if fn.name in _SKILL_FUNCTION_NAMES and _is_skill_path(path):
        return True
    return False


def _scan_function(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[int, str] | None:
    """Return (lineno, evidence) if the function mutates persistent
    state without emitting an attribution call. Otherwise None."""
    mutates_line: int | None = None
    mutates_evidence = ""
    has_attribution = False

    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name is None:
                continue
            if name in _ATTRIBUTION_CALL_NAMES:
                has_attribution = True
            elif name in _PERSISTENT_MUTATION_NAMES and mutates_line is None:
                mutates_line = node.lineno
                mutates_evidence = f"`{name}(...)` mutates persistent state"

    if mutates_line is not None and not has_attribution:
        return mutates_line, mutates_evidence
    return None


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    skip_dirs = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__"}

    for path in project_root.rglob("*.py"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        try:
            src = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Cheap pre-filter: if the file has no skill hints AND no path
        # match, skip parsing entirely.
        src_lower = src.lower()
        if "skill" not in src_lower and not _is_skill_path(path):
            continue
        try:
            tree = ast.parse(src, filename=str(path))
        except SyntaxError:
            continue
        rel = str(path.relative_to(project_root))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _function_qualifies_as_skill(node, path):
                continue
            hit = _scan_function(node)
            if hit is None:
                continue
            line, evidence = hit
            scanned.add(rel)
            findings.append(Finding(
                rule_id="AAK-SKILL-LIFECYCLE-ATTRIBUTION-001",
                title="Skill execute mutates persistent state without emitting an outcome-attribution record",
                description=(
                    "A Skill execute / run function mutates persistent "
                    "state (file write, DB commit, side-effecting HTTP "
                    "verb) without emitting an outcome-attribution call "
                    "(`record_outcome` / `log_outcome` / `attribute_*` / "
                    "etc.) in the same function body. Per SkillsVote "
                    "(arXiv:2605.18401), the evidence-gated update loop "
                    "depends on per-execution attribution; missing "
                    "attribution silently degrades repeat invocations."
                ),
                severity=Severity.MEDIUM,
                category=Category.TOOL_POISONING,
                file_path=rel,
                line_number=line,
                evidence=f"function `{node.name}`: {evidence}, but no attribution call emitted",
                remediation=(
                    "Emit a structured outcome record at the end of the "
                    "skill's execute function: e.g., `record_outcome("
                    "skill_id=..., outcome='success'|'failure', "
                    "signals={...})`. The schema can be project-local — "
                    "SkillsVote does not prescribe a specific format — "
                    "but the call must be present in the same function "
                    "body so the evidence-gated update loop can consume it."
                ),
                owasp_agentic_references=["ASI04", "ASI09"],
                incident_references=["ARXIV-2605.18401"],
            ))
    return findings, scanned


__all__ = ["scan"]
