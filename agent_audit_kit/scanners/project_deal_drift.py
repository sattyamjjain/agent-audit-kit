"""AAK-PROJECT-DEAL-DRIFT-001 — economic-quality drift in commerce agents.

Anthropic's 2026-04-26 Project Deal experiment showed Opus sellers
earned $2.68/item more than Haiku sellers for items rated identically
(4.06 vs 4.05). LLM09 / OWASP-Agentic class: economic-tier drift
across model deployments without parity checks.

Fires when an LLM client call (`anthropic.messages.create`,
`openai.chat.completions.create`, `litellm.completion`) lives inside
a pricing function (`set_price`, `quote`, `bid`, `list_price`,
`negotiate`) whose `model=` argument is templated from a variable
(cross-tier deployment likely) AND no `@parity.check` decorator is
present.

Scope-gated to commerce contexts: the enclosing module must import a
known commerce library (`stripe`, `shopify`, `medusa`,
`commercetools`) OR live under a `pricing/` / `commerce/` path. This
gate keeps the rule from firing on every LLM call in a non-commerce
codebase.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding


_PRICING_FUNC_RE = re.compile(
    r"^(set_price|quote|bid|list_price|negotiate|price_item|compute_price)$"
)
_LLM_SINK_RE = re.compile(
    r"""
    (?:
        anthropic(?:\.[A-Za-z_]+)*\.\s*(?:messages|completions)\.create
      | openai(?:\.[A-Za-z_]+)*\.\s*(?:chat\.completions|ChatCompletion|completions)\.create
      | litellm\.completion
      | client\.messages\.create
      | client\.chat\.completions\.create
    )
    """,
    re.VERBOSE,
)
_COMMERCE_HINT_RE = re.compile(
    r"""
    \b(?:
        import\s+(?:stripe|shopify|medusa|commercetools)
      | from\s+(?:stripe|shopify|medusa|commercetools)\s+import
    )\b
    """,
    re.VERBOSE,
)
_PARITY_DECORATOR_RE = re.compile(
    r"""
    (?:^|\W)
    (?:
        (?:[\w.]+\.)?parity\s*\.\s*check
      | parity_check
      | aak\.parity\.check
      | parity\b
    )
    """,
    re.VERBOSE,
)


def _has_templated_model_kwarg(call: ast.Call) -> bool:
    """Return True iff call has model=<Name|Attribute|Subscript> (i.e. variable, not literal)."""
    for kw in call.keywords:
        if kw.arg == "model":
            if isinstance(kw.value, ast.Constant):
                return False
            return True
    return False


def _is_in_commerce_context(text: str, project_root: Path, path: Path) -> bool:
    if _COMMERCE_HINT_RE.search(text):
        return True
    rel = str(path.relative_to(project_root)).lower()
    return any(part in rel for part in ("/pricing/", "/commerce/", "pricing/", "commerce/"))


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    if not _is_in_commerce_context(text, project_root, path):
        return []
    try:
        tree = ast.parse(text, str(path))
    except SyntaxError:
        return []
    findings: list[Finding] = []

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._scan(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._scan(node)
            self.generic_visit(node)

        def _scan(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            if not _PRICING_FUNC_RE.match(func.name):
                return
            # Decorator suppresses.
            for dec in func.decorator_list:
                src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                if _PARITY_DECORATOR_RE.search(src):
                    return
            for child in ast.walk(func):
                if not isinstance(child, ast.Call):
                    continue
                callee_src = ast.unparse(child.func) if hasattr(ast, "unparse") else ""
                if not _LLM_SINK_RE.search(callee_src):
                    continue
                if not _has_templated_model_kwarg(child):
                    continue
                rel = str(path.relative_to(project_root))
                scanned.add(rel)
                findings.append(make_finding(
                    "AAK-PROJECT-DEAL-DRIFT-001",
                    rel,
                    f"Pricing function `{func.name}` calls an LLM with a "
                    "templated `model=` and no @parity.check decorator. "
                    "Project-Deal-class economic drift: same LLM-quality "
                    "score across tiers can produce $/item differences. "
                    "Tag with @aak.parity.check or assert per-tier parity "
                    "in CI.",
                    line_number=child.lineno,
                ))
                return

    V().visit(tree)
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    for path in project_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_walk_python(text, path, project_root, scanned))
    return findings, scanned
