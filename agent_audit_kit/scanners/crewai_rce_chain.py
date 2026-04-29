"""AAK-CREWAI-CHAIN-2026-04-001 — CrewAI four-CVE exploit-chain scanner.

ThaiCERT (2026-04-02) + CERT/CC VU#221883 disclosed a chain through
CrewAI 0.x that turns an untrusted prompt into host RCE:

    CVE-2026-2275  CodeInterpreterTool(unsafe_mode=True) -> ctypes
    CVE-2026-2285  JSONSearchTool / JSONLoader path traversal
    CVE-2026-2286  RagTool / WebsiteSearchTool SSRF
    CVE-2026-2287  Sandbox fallback without Docker liveness check

This scanner emits one finding per CVE-shape AND a meta-finding when
all four shapes are present in the same project. Each finding is
suppressed by a call into `agent_audit_kit.sanitizers.crewai`
(`assert_codeinterp_safe_mode`, `validate_jsonloader_path`,
`validate_rag_url`, `require_docker_liveness`).

Restricted by import gate: at least one of `from crewai import ...`
or `import crewai` must be present in the file (avoids matches in
unrelated codebases).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding


_CREWAI_IMPORT_RE = re.compile(
    r"""
    (?:
        from\s+crewai(?:\.\w+)*\s+import\b
      | import\s+crewai\b
      | from\s+crewai_tools\s+import\b
    )
    """,
    re.VERBOSE,
)

# Per-CVE sanitiser detectors. Presence in the same function body
# suppresses the corresponding finding.
_GUARD_CODEINTERP_RE = re.compile(r"\bassert_codeinterp_safe_mode\s*\(")
_GUARD_JSON_RE = re.compile(r"\bvalidate_jsonloader_path\s*\(")
_GUARD_RAG_RE = re.compile(r"\bvalidate_rag_url\s*\(")
_GUARD_DOCKER_RE = re.compile(r"\brequire_docker_liveness\s*\(")

# Source-of-taint hints (function body must reference one of these
# for the finding to be reachability-credible).
_TAINT_HINTS_RE = re.compile(
    r"""
    (?:
        \brequest\.(?:json|body|args|form|data|values|files)\b
      | \bawait\s+request\.json\(\)
      | \bevent\b
      | \bllm_input\b
      | \buser_input\b
      | \bagent\.kickoff\s*\(
      | \btask\.execute\s*\(
      | \binputs\s*=
    )
    """,
    re.VERBOSE,
)


def _func_body(text: str, node: ast.AST) -> str:
    lines = text.splitlines()
    start = max(0, getattr(node, "lineno", 1) - 1)
    end_lineno = getattr(node, "end_lineno", node.lineno) or node.lineno  # type: ignore[attr-defined]
    end = min(len(lines), end_lineno)
    return "\n".join(lines[start:end])


def _kw_value_constant(call: ast.Call, name: str) -> ast.Constant | None:
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant):
            return kw.value
    return None


def _kw_value(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    if not _CREWAI_IMPORT_RE.search(text):
        return []
    try:
        tree = ast.parse(text, str(path))
    except SyntaxError:
        return []

    rel = str(path.relative_to(project_root))
    findings: list[Finding] = []
    fired: set[str] = set()  # which CVE-shapes fired in this file

    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            self._inspect(node)
            self.generic_visit(node)

        def _callee_attr(self, call: ast.Call) -> str:
            if isinstance(call.func, ast.Attribute):
                return call.func.attr
            if isinstance(call.func, ast.Name):
                return call.func.id
            return ""

        def _enclosing_function_body(self, call: ast.Call) -> str:
            # Walk up to find the nearest FunctionDef / AsyncFunctionDef.
            for parent in ast.walk(tree):
                if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if any(
                        c is call
                        for c in ast.walk(parent)
                        if isinstance(c, ast.Call)
                    ):
                        return _func_body(text, parent)
            return text

        def _inspect(self, call: ast.Call) -> None:
            callee = self._callee_attr(call)
            body = self._enclosing_function_body(call)

            # ---- CVE-2026-2275 — CodeInterpreterTool(unsafe_mode=True)
            if callee == "CodeInterpreterTool":
                unsafe = _kw_value_constant(call, "unsafe_mode")
                if unsafe is not None and unsafe.value is True:
                    if not _GUARD_CODEINTERP_RE.search(body):
                        findings.append(make_finding(
                            "AAK-CREWAI-CVE-2026-2275-001",
                            rel,
                            "CodeInterpreterTool(unsafe_mode=True) drops "
                            "into a host Python sandbox; ctypes + "
                            "os.system are reachable. Wrap with "
                            "agent_audit_kit.sanitizers.crewai."
                            "assert_codeinterp_safe_mode(False) or set "
                            "unsafe_mode=False (CVE-2026-2275).",
                            line_number=call.lineno,
                        ))
                        fired.add("2275")

            # ---- CVE-2026-2285 — JSON loader / search path traversal
            if callee in {"JSONSearchTool", "JSONLoader"}:
                path_arg = _kw_value(call, "file_path") or _kw_value(call, "path")
                if path_arg is not None and not isinstance(path_arg, ast.Constant):
                    if not _GUARD_JSON_RE.search(body):
                        if _TAINT_HINTS_RE.search(body):
                            findings.append(make_finding(
                                "AAK-CREWAI-CVE-2026-2285-001",
                                rel,
                                f"{callee}(...) takes a non-constant "
                                "path argument and reaches the function "
                                "from an untrusted source. Pipe through "
                                "validate_jsonloader_path(path, root=...) "
                                "(CVE-2026-2285).",
                                line_number=call.lineno,
                            ))
                            fired.add("2285")

            # ---- CVE-2026-2286 — RAG / WebsiteSearch SSRF
            if callee in {"RagTool", "WebsiteSearchTool"}:
                url_arg = _kw_value(call, "url") or _kw_value(call, "website")
                if url_arg is not None and not isinstance(url_arg, ast.Constant):
                    if not _GUARD_RAG_RE.search(body):
                        if _TAINT_HINTS_RE.search(body):
                            findings.append(make_finding(
                                "AAK-CREWAI-CVE-2026-2286-001",
                                rel,
                                f"{callee}(...) accepts a non-constant URL "
                                "reachable from an untrusted source "
                                "without validate_rag_url(url, "
                                "allowlist=[...]). Cloud-metadata / "
                                "loopback SSRF (CVE-2026-2286).",
                                line_number=call.lineno,
                            ))
                            fired.add("2286")

            # ---- CVE-2026-2287 — sandbox fallback without docker check
            if callee == "CodeInterpreterTool":
                if not _GUARD_DOCKER_RE.search(body):
                    docker_required = _kw_value_constant(call, "docker_required")
                    if docker_required is None or not bool(docker_required.value):
                        findings.append(make_finding(
                            "AAK-CREWAI-CVE-2026-2287-001",
                            rel,
                            "CodeInterpreterTool(...) does not gate on "
                            "Docker liveness — a dead Docker daemon "
                            "silently falls back to the host Python "
                            "sandbox. Call require_docker_liveness("
                            "client) before tool exec or set "
                            "docker_required=True (CVE-2026-2287).",
                            line_number=call.lineno,
                        ))
                        fired.add("2287")

    V().visit(tree)

    # Meta-rule: meta-finding only when all 4 sub-shapes fired in the file.
    if fired >= {"2275", "2285", "2286", "2287"}:
        findings.append(make_finding(
            "AAK-CREWAI-CHAIN-2026-04-001",
            rel,
            "Full CrewAI four-CVE exploit chain (CVE-2026-2275 + 2285 + "
            "2286 + 2287) reachable in the same module. ThaiCERT + "
            "CERT/CC VU#221883 chain a single prompt into host RCE.",
            line_number=1,
        ))

    if findings:
        scanned.add(rel)
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
