"""Multi-agent shared-state lock detector.

Anchored to *Code as Agent Harness* (Ning et al., arXiv:2605.18747,
2026-05-18). The paper's survey (110+ papers, 23 systems) names
"consistent shared state across multiple agents" as an explicit
open challenge for harness engineering.

The defensive code shape: a Python class whose name matches an
Agent pattern (`*Agent`, `*Worker`, `*Harness`) accesses a
module-level or class-level mutable shared object (dict / list /
set) without using a lock primitive (`threading.Lock` /
`asyncio.Lock` / `multiprocessing.Lock` / contextmanager named
`*lock*`). The detector fires when at least 2 distinct Agent
classes write to the same shared symbol with no lock acquisition
visible in either function scope.

**Research-grade** (MEDIUM severity). The Code-as-Harness paper is
a survey, not a code prescription — it identifies the open
challenge but does not specify a canonical fix shape. This rule
catches the most concrete shape (>=2 agent classes mutating the
same shared dict / list / set without a Lock acquisition in scope).
False positives are expected when agents legitimately serialize
writes via an external coordinator (e.g., a database transaction
or a queue) that the AST scanner can't see. Severity reflects that.

Detector contract:
    scan(project_root) -> (list[Finding], set[str])
"""
from __future__ import annotations

import ast
from pathlib import Path

from agent_audit_kit.models import Category, Finding, Severity


_AGENT_CLASS_SUFFIXES: tuple[str, ...] = ("Agent", "Worker", "Harness")
_MUTATING_METHODS: frozenset[str] = frozenset({
    "append", "extend", "insert", "add", "update", "pop",
    "remove", "clear", "setdefault", "popitem",
})
# Heuristic "lock acquired in scope" — checks if any of these is
# referenced within the function body.
_LOCK_HINTS: tuple[str, ...] = (
    "Lock", "RLock", "Semaphore", "BoundedSemaphore", "Mutex",
    "lock", "_lock", "acquire",
)


def _is_agent_class(node: ast.ClassDef) -> bool:
    return any(node.name.endswith(suf) for suf in _AGENT_CLASS_SUFFIXES)


def _module_level_mutable_names(tree: ast.Module) -> set[str]:
    """Collect names assigned to a mutable container literal at module
    level. Handles both bare `_SHARED = {}` (ast.Assign) and the
    annotated form `_SHARED: dict = {}` (ast.AnnAssign) — the latter
    is the typed style seen in modern Python code."""
    out: set[str] = set()
    for node in tree.body:
        # Pull out (target_name, value) pairs from both forms.
        target_name: str | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                target_name = node.targets[0].id
                value = node.value
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.value is not None:
                target_name = node.target.id
                value = node.value
        if target_name is None or value is None:
            continue
        if isinstance(value, (ast.Dict, ast.List, ast.Set, ast.DictComp, ast.ListComp, ast.SetComp)):
            out.add(target_name)
        elif isinstance(value, ast.Call):
            cn = _call_name(value.func)
            if cn in {"dict", "list", "set", "defaultdict", "OrderedDict"}:
                out.add(target_name)
    return out


def _call_name(expr: ast.expr) -> str | None:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return expr.attr
    return None


def _function_has_lock_hint(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Walk a function body for any name that looks like a Lock
    primitive being acquired. Case-insensitive — the variable
    `_LOCK` should match the `_lock` hint."""
    hints_lower = {h.lower() for h in _LOCK_HINTS}
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and node.id.lower() in hints_lower:
            return True
        if isinstance(node, ast.Attribute) and node.attr.lower() in hints_lower:
            return True
    return False


def _function_mutations_against(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    shared_names: set[str],
) -> list[tuple[int, str, str]]:
    """Return (lineno, target_name, evidence) for each call site that
    mutates one of the shared module-level names."""
    hits: list[tuple[int, str, str]] = []
    for node in ast.walk(fn):
        # x.method(...) where x is shared and method is mutating
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in _MUTATING_METHODS \
                    and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id in shared_names:
                hits.append((
                    node.lineno,
                    node.func.value.id,
                    f"`{node.func.value.id}.{node.func.attr}(...)`",
                ))
        # x[key] = ... assignment where x is a shared module-level name
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript) \
                        and isinstance(target.value, ast.Name) \
                        and target.value.id in shared_names:
                    hits.append((
                        node.lineno,
                        target.value.id,
                        f"`{target.value.id}[...]=...` subscript assign",
                    ))
    return hits


def _scan_python_file(path: Path, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    # Pre-filter: file must contain at least one *Agent / *Worker / *Harness class.
    if not any(suf in src for suf in _AGENT_CLASS_SUFFIXES):
        return findings
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return findings

    shared_names = _module_level_mutable_names(tree)
    if not shared_names:
        return findings

    # Pass 1: collect every (agent_class, shared_target, line) tuple.
    agent_writes: dict[str, list[tuple[str, int, str]]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        if not _is_agent_class(node):
            continue
        for fn in ast.walk(node):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if _function_has_lock_hint(fn):
                continue  # explicit-lock short-circuit
            for line, target, evidence in _function_mutations_against(fn, shared_names):
                agent_writes.setdefault(target, []).append((node.name, line, evidence))

    # Pass 2: a shared symbol fires the rule iff >=2 DISTINCT agent
    # classes mutate it without a lock-hint.
    for target, writes in agent_writes.items():
        agent_names = {w[0] for w in writes}
        if len(agent_names) < 2:
            continue
        primary_line = writes[0][1]
        agent_list = ", ".join(sorted(agent_names))
        findings.append(Finding(
            rule_id="AAK-AGENT-HARNESS-SHARED-STATE-001",
            title="Multi-agent shared state mutated by >=2 agents without a lock primitive",
            description=(
                "A module-level mutable object (`dict` / `list` / `set` "
                "/ comprehension result) is mutated by methods of >=2 "
                "distinct Agent / Worker / Harness classes without a "
                "lock primitive (`threading.Lock` / `asyncio.Lock` / "
                "etc.) visible in any of the mutating functions. Per "
                "*Code as Agent Harness* (arXiv:2605.18747, EASE 2026 "
                "survey), 'consistent shared state across multiple "
                "agents' is an explicit open challenge."
            ),
            severity=Severity.MEDIUM,
            category=Category.A2A_PROTOCOL,
            file_path=rel,
            line_number=primary_line,
            evidence=(
                f"shared module-level `{target}` mutated by "
                f"{{{agent_list}}} without a lock acquisition in any "
                "of the mutating function bodies"
            ),
            remediation=(
                "Guard every mutation against the shared symbol with a "
                "lock primitive (`threading.Lock` / `asyncio.Lock` / "
                "`multiprocessing.Lock`). If serialization is enforced "
                "by an external coordinator (database transaction, "
                "message queue), this rule's false-positive rate is "
                "expected — add a `# noqa: AAK-AGENT-HARNESS-SHARED-STATE-001` "
                "comment with the coordinator name to suppress."
            ),
            owasp_agentic_references=["ASI04", "ASI06"],
            incident_references=["ARXIV-2605.18747"],
        ))
    return findings


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
