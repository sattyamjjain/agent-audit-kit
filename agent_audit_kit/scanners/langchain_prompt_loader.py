"""AAK-LANGCHAIN-PROMPT-LOADER-PATH-001 — LangChain load_prompt path traversal.

CVE-2026-34070 (CVSS 7.5): `langchain.prompts.load_prompt(path)` and
`PromptTemplate.from_file(path)` accept the `lc://` URI scheme + raw
file paths and resolve them without anchoring. A crafted prompt path
reads arbitrary files. Patched in `langchain-core>=0.3.74`.

The scanner fires when the path argument is non-constant AND there is
a taint source in the same function (request body / CLI args / env
read). It suppresses on a call into
`agent_audit_kit.checks.path_under_root`.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import (
    SOURCE_MAX_BYTES,
    in_skip_dir,
    make_finding,
    parse_python,
    read_text_capped,
    refusing_overflow,
    source_lines,
    walk_tree,
)


# The imported names stop at the next `from langchain... import` on the line,
# which reads on itself: with `[^\n]*` alone a line of such imports and no
# matching name was read to its end once per import.
_LANGCHAIN_FROM = r"from\s+langchain(?:\.[\w.]+)?\s+import"
_LANGCHAIN_IMPORT_RE = re.compile(
    r"""
    (?:
        """ + _LANGCHAIN_FROM + r"""(?:(?!""" + _LANGCHAIN_FROM + r""")[^\n])*\b(?:load_prompt|PromptTemplate)\b
      | from\s+langchain_core\.prompts\s+import\b
      | import\s+langchain_core\.prompts
      | import\s+langchain\.prompts
    )
    """,
    re.VERBOSE,
)
_TAINT_RE = re.compile(
    r"""
    (?:
        \brequest\.(?:json|body|args|form|data|values|files)\b
      | \brequest\s*\.\s*get_json
      | \bawait\s+request\.json\(\)
      | \bsys\.argv\b
      | \bos\.environ\b
      | \bos\.getenv
      | \bargparse\.\w+\.parse_args
    )
    """,
    re.VERBOSE,
)
_GUARD_RE = re.compile(
    r"""
    (?:
        \bpath_under_root\s*\(
      | \bagent_audit_kit\.checks\.path_under_root
      | \bos\.path\.realpath\s*\(
    )
    """,
    re.VERBOSE,
)
# Exempt: legitimate object-store backends.
_EXEMPT_RE = re.compile(
    r"""
    (?:
        langchain_community\.storage\.s3
      | langchain_community\.document_loaders\.S3FileLoader
      | requests\.get\([^)]+\)\.text
    )
    """,
    re.VERBOSE,
)


def _func_body(text: str, node: ast.AST) -> str:
    """The function's source lines, cut from lines split once per file
    (`source_lines`). Splitting the whole file again for each function made
    20,000 one-line functions take 6.9 s."""
    lines = source_lines(text)
    start = max(0, getattr(node, "lineno", 1) - 1)
    end_lineno = getattr(node, "end_lineno", node.lineno) or node.lineno  # type: ignore[attr-defined]
    end = min(len(lines), end_lineno)
    return "\n".join(lines[start:end])


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    if not _LANGCHAIN_IMPORT_RE.search(text):
        return []
    try:
        tree = parse_python(text, path)
    except SyntaxError:
        return []
    findings: list[Finding] = []
    rel = str(path.relative_to(project_root))

    def _body_has(searched: dict[str, bool], pattern: re.Pattern[str], body: str) -> bool:
        """`pattern.search(body)`, once per pattern for one function's body.
        Searching it again for every `load_prompt` call in the function made
        one function of 10,000 such calls take 34 s."""
        found = searched.get(pattern.pattern)
        if found is None:
            found = searched[pattern.pattern] = pattern.search(body) is not None
        return found

    def _scan_call(call: ast.Call, parent_body: str, searched: dict[str, bool]) -> None:
        callee = ""
        if isinstance(call.func, ast.Attribute):
            callee = call.func.attr
        elif isinstance(call.func, ast.Name):
            callee = call.func.id
        if callee not in {"load_prompt", "from_file"}:
            return
        # First positional or `path=` / `template_file=` kwarg.
        path_node: ast.AST | None = None
        if call.args:
            path_node = call.args[0]
        for kw in call.keywords:
            if kw.arg in {"path", "template_file", "file_path"}:
                path_node = kw.value
                break
        if path_node is None or isinstance(path_node, ast.Constant):
            return
        if _body_has(searched, _GUARD_RE, parent_body):
            return
        if _body_has(searched, _EXEMPT_RE, parent_body):
            return
        if not _body_has(searched, _TAINT_RE, parent_body):
            return
        findings.append(make_finding(
            "AAK-LANGCHAIN-PROMPT-LOADER-PATH-001",
            rel,
            f"{callee}(...) called with a non-constant path inside a "
            "function that reads from request / argv / env. CVE-2026-"
            "34070 path traversal — anchor the path with "
            "agent_audit_kit.checks.path_under_root or bump "
            "langchain-core to >= 0.3.74.",
            line_number=call.lineno,
        ))

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            body = _func_body(text, node)
            searched: dict[str, bool] = {}
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    _scan_call(child, body, searched)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            body = _func_body(text, node)
            searched: dict[str, bool] = {}
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    _scan_call(child, body, searched)
            self.generic_visit(node)

    walk_tree(V().visit, tree)
    if findings:
        scanned.add(rel)
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    for path in project_root.rglob("*.py"):
        if in_skip_dir(path, project_root):
            continue
        try:
            text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
        except OSError:
            continue
        with refusing_overflow(path):
            findings.extend(_walk_python(text, path, project_root, scanned))
    return findings, scanned
