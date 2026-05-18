"""Metis POMDP closed-loop reasoning defense detectors.

Anchored to *Metis: Learning to Jailbreak LLMs via Self-Evolving
Metacognitive Policy Optimization* (arXiv:2605.10067, ICML 2026).
The paper describes an **offensive** technique — it reformulates
jailbreaking as inference-time policy optimization within an
adversarial POMDP and shows that "current defenses remain vulnerable
to internally-steered, closed-loop reasoning trajectories" because
the adversary "leverages structured feedback as a semantic gradient
to refine its policy."

The paper does NOT prescribe defensive SAST shapes; what it DOES is
demonstrate that closed-loop feedback (refusal text → next prompt,
scoring strings → next prompt mutation) is exploitable. This module
catches two of the most concrete code shapes that enable that
exploit class. Both rules are **research-grade** — they flag
code patterns the paper shows are exploitable, but they don't
prove RCE on any specific tool call.

Rule shapes shipped today (2 of the 5 in the original Suggestion 1):
  - AAK-METIS-REFUSAL-REFEED-001: a function that consumes an LLM
    refusal text and returns/echoes it into a subsequent prompt
    without a policy-mediated transformation.
  - AAK-METIS-SCORING-SINK-001: a function in a tool-call loop that
    routes a numeric or string scoring value into the next prompt
    template.

Deferred to v0.3.21 (need more concrete code shape from a defensive
follow-up paper before shipping non-FP-heavy detectors):
  - self-evolving prompt mutation without rate-limit
  - structured-feedback echoing into system prompt
  - closed-loop reasoning chain without circuit-breaker

Detector contract:
    scan(project_root) -> (list[Finding], set[str])
"""
from __future__ import annotations

import ast
from pathlib import Path

from agent_audit_kit.models import Category, Finding, Severity


# Heuristic name patterns — function name, parameter name, or string
# literal inside the function body that indicates the function operates
# on a refusal / scoring signal.
_REFUSAL_HINTS: frozenset[str] = frozenset({
    "refusal",
    "rejected",
    "denied",
    "denial",
    "decline",
    "decline_text",
    "handle_refusal",
})
_SCORE_HINTS: frozenset[str] = frozenset({
    "score",
    "scoring",
    "judge",
    "judgment",
    "reward",
    "rating",
    "critique",
})
# Sinks: function/method names that mean "this value gets fed into the
# next prompt or tool-call." If a refusal/score-named variable reaches
# any of these, the rule fires.
_PROMPT_SINK_NAMES: frozenset[str] = frozenset({
    "format",
    "format_map",
    "append",
    "extend",
    "set_user_message",
    "add_message",
    "messages",
    "build_prompt",
    "next_prompt",
    "render_prompt",
    "set_system_prompt",
})


def _name_matches_any(name: str, hints: frozenset[str]) -> bool:
    lower = name.lower()
    return any(h in lower for h in hints)


def _is_prompt_sink_call(call: ast.Call) -> bool:
    """True if the call shape looks like 'pump value into next prompt'."""
    func = call.func
    if isinstance(func, ast.Attribute):
        if func.attr.lower() in _PROMPT_SINK_NAMES:
            return True
    if isinstance(func, ast.Name):
        if func.id.lower() in _PROMPT_SINK_NAMES:
            return True
    return False


def _function_param_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: set[str] = set()
    args = fn.args
    for a in args.posonlyargs + args.args + args.kwonlyargs:
        names.add(a.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _collect_tainted_vars(fn: ast.FunctionDef | ast.AsyncFunctionDef, hints: frozenset[str]) -> set[str]:
    """Find variable names inside `fn` whose identifier matches a hint,
    whose value is read from a hint-named parameter, OR whose value
    propagates transitively from a tainted name (single-pass walk)."""
    # Seed from parameters whose names match a hint.
    tainted = {p for p in _function_param_names(fn) if _name_matches_any(p, hints)}
    # Always walk for assigns — the param-match is the seed, not an
    # early-exit. Run multiple passes so taint propagates through
    # chained assignments (`critique = score; bad = critique`).
    for _ in range(3):  # fixed-point iteration capped at 3 passes
        before = len(tainted)
        for node in ast.walk(fn):
            if not isinstance(node, ast.Assign):
                continue
            # Any assignment target whose own name matches a hint is tainted.
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and _name_matches_any(tgt.id, hints):
                    tainted.add(tgt.id)
            # Any assignment whose RHS is a tainted Name spreads taint
            # to all LHS targets.
            if isinstance(node.value, ast.Name) and node.value.id in tainted:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        tainted.add(tgt.id)
        if len(tainted) == before:
            break
    return tainted


def _scan_python_file(path: Path, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    src_lower = src.lower()
    has_refusal_token = any(h in src_lower for h in _REFUSAL_HINTS)
    has_score_token = any(h in src_lower for h in _SCORE_HINTS)
    if not (has_refusal_token or has_score_token):
        return findings
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        fn_name = node.name

        # ---- AAK-METIS-REFUSAL-REFEED-001 ----
        if _name_matches_any(fn_name, _REFUSAL_HINTS) or any(
            _name_matches_any(p, _REFUSAL_HINTS) for p in _function_param_names(node)
        ):
            tainted = _collect_tainted_vars(node, _REFUSAL_HINTS)
            if tainted:
                for sub in ast.walk(node):
                    # Pattern A: function returns a refusal-tainted value
                    if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Name) \
                            and sub.value.id in tainted:
                        findings.append(_metis_finding(
                            "AAK-METIS-REFUSAL-REFEED-001",
                            "Refusal text returned from handler — risk of re-feed into next prompt",
                            rel, sub.lineno,
                            f"function `{fn_name}` returns `{sub.value.id}` derived from a refusal signal",
                            "Wrap the refusal in a policy-mediated transformation (categorize / "
                            "log / rate-limit / strip free-text) before any callsite re-uses it. "
                            "Per Metis (arXiv:2605.10067), structured feedback used as a semantic "
                            "gradient is the exploited surface.",
                        ))
                    # Pattern B: refusal-tainted value flows into a prompt sink
                    if isinstance(sub, ast.Call) and _is_prompt_sink_call(sub):
                        for a in sub.args:
                            if isinstance(a, ast.Name) and a.id in tainted:
                                findings.append(_metis_finding(
                                    "AAK-METIS-REFUSAL-REFEED-001",
                                    "Refusal value flows into prompt-sink call",
                                    rel, sub.lineno,
                                    f"prompt-sink call in `{fn_name}` receives refusal-tainted `{a.id}`",
                                    "Categorize and replace refusal text with a non-echoing token "
                                    "before injecting into the next prompt. See arXiv:2605.10067.",
                                ))

        # ---- AAK-METIS-SCORING-SINK-001 ----
        if _name_matches_any(fn_name, _SCORE_HINTS) or any(
            _name_matches_any(p, _SCORE_HINTS) for p in _function_param_names(node)
        ):
            tainted = _collect_tainted_vars(node, _SCORE_HINTS)
            if tainted:
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call) and _is_prompt_sink_call(sub):
                        for a in sub.args:
                            if isinstance(a, ast.Name) and a.id in tainted:
                                findings.append(_metis_finding(
                                    "AAK-METIS-SCORING-SINK-001",
                                    "Scoring/judge value flows into prompt-sink call",
                                    rel, sub.lineno,
                                    f"prompt-sink call in `{fn_name}` receives score-tainted `{a.id}`",
                                    "Discretize scoring signal into an opaque bucket (PASS / FAIL / "
                                    "PARTIAL) before re-injecting. Per Metis (arXiv:2605.10067), "
                                    "numeric / verbose scoring strings are the semantic-gradient "
                                    "the adversary uses to refine its policy.",
                                ))
    return findings


def _metis_finding(
    rule_id: str,
    title: str,
    rel: str,
    line: int,
    evidence: str,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        description=title,
        severity=Severity.MEDIUM,  # research-grade — high-FP risk warrants MEDIUM
        category=Category.TOOL_POISONING,
        file_path=rel,
        line_number=line,
        evidence=evidence,
        remediation=remediation,
        owasp_agentic_references=["ASI01", "ASI02"],
        incident_references=["ARXIV-2605.10067"],
    )


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    skip_dirs = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__"}
    for path in project_root.rglob("*.py"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        rel = str(path.relative_to(project_root))
        fires = _scan_python_file(path, rel)
        if fires:
            scanned.add(rel)
            findings.extend(fires)
    return findings, scanned


__all__ = ["scan"]
