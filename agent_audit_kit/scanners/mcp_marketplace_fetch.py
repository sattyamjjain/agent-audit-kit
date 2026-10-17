"""AAK-MCP-MARKETPLACE-CONFIG-FETCH-001 — marketplace-fetch → spawn.

Cloudflare's MCP-defender reframe (2026-04-25) called this out as the
highest-risk single-line bug in the wild:

    config = requests.get("https://marketplace.example/manifest").json()
    StdioServerParameters(command=config["cmd"], args=config["args"])

A marketplace compromise becomes client-side RCE on every consumer at
the next refresh. AAK-MCP-STDIO-CMD-INJ-001/002 catch the broader
config-from-network → spawn class; this rule narrows in on the
*marketplace* shape specifically so it can ship a denominator of
"how many AAK consumers are running that exact pattern" and a
suppression file (`.aak-mcp-marketplace-trust.yml`) for trusted
internal artifact registries.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml

from agent_audit_kit.models import Finding

from ._helpers import (
    CONFIG_MAX_BYTES,
    SOURCE_MAX_BYTES,
    chain_ends,
    in_skip_dir,
    load_yaml,
    make_finding,
    parse_python,
    read_text_capped,
    refusing_overflow,
    walk_tree,
)


_PY_FETCH_NAMES = frozenset({"get", "post", "request", "urlopen"})
_PY_STDIO_TARGETS = frozenset({"StdioServerParameters", "StdioClientTransport"})

_TS_FETCH_RE = re.compile(r"await\s+fetch\s*\(")
_TS_STDIO_NEW_RE = re.compile(r"new\s+Stdio(?:ClientTransport|ServerTransport)")


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    cur: ast.AST | None = node
    while True:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Name):
            parts.append(cur.id)
            break
        elif isinstance(cur, ast.Call):
            cur = cur.func
        else:
            break
    return ".".join(reversed(parts))


def _is_fetch_call(call: ast.Call) -> bool:
    count, first, last = chain_ends(call.func)
    if not count or last not in _PY_FETCH_NAMES:
        return False
    head = first if count > 1 else ""
    return head in {"requests", "httpx", "urllib"} or (count, first) == (1, "urlopen")


def _is_stdio_call(call: ast.Call) -> bool:
    count, _, last = chain_ends(call.func)
    return count > 0 and last in _PY_STDIO_TARGETS


def _trusted_urls(project_root: Path) -> set[str]:
    cfg = project_root / ".aak-mcp-marketplace-trust.yml"
    if not cfg.is_file():
        return set()
    try:
        data = load_yaml(read_text_capped(cfg, CONFIG_MAX_BYTES), cfg) or {}
    except (yaml.YAMLError, OSError):
        return set()
    out: set[str] = set()
    for entry in data.get("trust", []) or []:
        if isinstance(entry, dict):
            url = entry.get("url")
            justification = entry.get("justification", "")
            if isinstance(url, str) and isinstance(justification, str) and justification.strip():
                out.add(url)
    return out


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str], trusted: set[str]) -> list[Finding]:
    try:
        tree = parse_python(text, path)
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

        def _scan(self, func: ast.AST) -> None:
            calls = sorted(
                (n for n in ast.walk(func) if isinstance(n, ast.Call)),
                key=lambda c: (c.lineno, c.col_offset),
            )
            fetch_seen = False
            fetch_url: str | None = None
            fetch_line = 0
            for call in calls:
                if not fetch_seen and _is_fetch_call(call):
                    fetch_seen = True
                    fetch_line = call.lineno
                    if call.args and isinstance(call.args[0], ast.Constant):
                        fetch_url = str(call.args[0].value)
                    continue
                if fetch_seen and _is_stdio_call(call):
                    if fetch_url and fetch_url in trusted:
                        return
                    rel = str(path.relative_to(project_root))
                    scanned.add(rel)
                    findings.append(make_finding(
                        "AAK-MCP-MARKETPLACE-CONFIG-FETCH-001",
                        rel,
                        f"Network fetch at line {fetch_line} feeds "
                        f"{_attr_chain(call.func).split('.')[-1]}(...) "
                        "in the same function — marketplace-compromise "
                        "becomes client-side RCE on next refresh "
                        "(OX/Cloudflare 2026-04-25). Add the manifest "
                        "URL to .aak-mcp-marketplace-trust.yml to "
                        "suppress.",
                        line_number=call.lineno,
                    ))
                    return

    walk_tree(V().visit, tree)
    return findings


def _walk_ts(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for fetch_m in _TS_FETCH_RE.finditer(text):
        # Look forward 2KB for a `new Stdio*Transport`.
        window = text[fetch_m.end() : fetch_m.end() + 2048]
        if not _TS_STDIO_NEW_RE.search(window):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        line = text.count("\n", 0, fetch_m.start()) + 1
        findings.append(make_finding(
            "AAK-MCP-MARKETPLACE-CONFIG-FETCH-001",
            rel,
            "await fetch(...) followed by new Stdio*Transport in the "
            "same scope — marketplace-fetch RCE shape (OX/Cloudflare "
            "2026-04-25).",
            line_number=line,
        ))
        return findings
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    trusted = _trusted_urls(project_root)
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if in_skip_dir(path, project_root):
            continue
        suffix = path.suffix
        try:
            text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
        except OSError:
            continue
        if suffix == ".py":
            with refusing_overflow(path):
                findings.extend(_walk_python(text, path, project_root, scanned, trusted))
        elif suffix in (".ts", ".tsx", ".js", ".mjs", ".cjs"):
            findings.extend(_walk_ts(text, path, project_root, scanned))
    return findings, scanned
