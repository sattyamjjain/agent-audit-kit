"""AAK-MCP-FHI-001 — Function-Hijacking adversarial tool descriptions.

arXiv 2604.20994 (2026-04-23) showed 70-100% ASR on BFCL via universal
adversarial suffixes appended to MCP tool names/descriptions. Once a
malicious tool is registered (via marketplace, supply-chain, or a
poisoned tool-catalogue), the LLM is steered into picking it
preferentially because the embedded suffix exploits the planner's
ranking heuristics.

Detection: parse tool registrations across Python (`@mcp.tool`,
`@server.tool`, `@tool`), TS (`server.tool`, `mcp.tool`), Java
(`@Tool`), Rust (`#[mcp_tool]`) and inspect the `name` /
`description` strings for:

- Imperative override language ("ignore previous", "always call",
  "this tool must be invoked first", "supersedes all other tools")
- Universal-suffix tokens from `agent_audit_kit/data/fhi_universal_suffixes.txt`
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding


_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_SUFFIX_FILE = _DATA_DIR / "fhi_universal_suffixes.txt"


def _load_suffixes() -> list[str]:
    if not _SUFFIX_FILE.is_file():
        return []
    out: list[str] = []
    for line in _SUFFIX_FILE.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


_IMPERATIVE_RE = re.compile(
    r"""
    (?:
        ignore[\s_-]+(?:previous|prior|all)\s+(?:instructions|tools|prompts)
      | always\s+(?:call|invoke|use|prefer)\s+(?:this|me)
      | (?:this|the)\s+tool\s+must\s+be\s+(?:invoked|called)\s+first
      | supersedes?\s+all\s+other\s+tools?
      | top[\s-]*priority[\s-]*tool
      | call\s+only\s+this\s+tool
      | disregard\s+(?:other|previous)\s+(?:tools?|instructions?)
      | system\s*[:\-]\s*always
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Tool registration shapes by language.
_PY_TOOL_RE = re.compile(
    r"""
    @(?:mcp|server|app)\s*\.\s*tool\s*\(
    (?P<args>[^)]*)
    \)
    """,
    re.VERBOSE,
)
# Catches `@tool(name="x", description="y")` and the bare `@tool`.
_PY_TOOL_BARE_RE = re.compile(r"@(?:mcp\.tool|server\.tool|tool)\b")

_TS_TOOL_RE = re.compile(
    r"""
    (?:server|mcp|app)\s*\.\s*tool\s*\(
    \s*['"](?P<name>[^'"]*)['"]
    \s*,\s*['"](?P<description>[^'"]*)['"]
    """,
    re.VERBOSE,
)
_JAVA_TOOL_RE = re.compile(
    r"""
    @Tool\s*\(\s*(?:name\s*=\s*['"][^'"]*['"][\s,]*)?
    description\s*=\s*['"](?P<description>[^'"]*)['"]
    """,
    re.VERBOSE,
)
_RUST_TOOL_RE = re.compile(
    r"""
    \#\[\s*mcp_tool\s*\(
    [^)]*?
    description\s*=\s*['"](?P<description>[^'"]*)['"]
    """,
    re.VERBOSE | re.DOTALL,
)


def _check_text(text: str, suffixes: list[str]) -> tuple[bool, str | None]:
    """Return (is_adversarial, matched_token)."""
    if _IMPERATIVE_RE.search(text):
        m = _IMPERATIVE_RE.search(text)
        return True, m.group(0) if m else None
    lower = text.lower()
    for suffix in suffixes:
        if not suffix:
            continue
        if suffix.lower() in lower:
            return True, suffix
    return False, None


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    suffixes = _load_suffixes()
    scanned: set[str] = set()
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        suffix = path.suffix
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = str(path.relative_to(project_root))
        matches: list[tuple[int, str]] = []  # (line, snippet)

        if suffix == ".py":
            # Python: docstring of the decorated function OR description= kwarg.
            for m in _PY_TOOL_RE.finditer(text):
                args = m.group("args") or ""
                desc_m = re.search(r"description\s*=\s*['\"]([^'\"]*)['\"]", args)
                if desc_m:
                    is_adv, token = _check_text(desc_m.group(1), suffixes)
                    if is_adv:
                        line = text.count("\n", 0, m.start()) + 1
                        matches.append((line, token or "<imperative>"))
            # Also catch `@mcp.tool` followed by a docstring.
            for m in _PY_TOOL_BARE_RE.finditer(text):
                tail = text[m.end() : m.end() + 2048]
                doc_m = re.search(r'"""([^"]+)"""', tail)
                if doc_m:
                    is_adv, token = _check_text(doc_m.group(1), suffixes)
                    if is_adv:
                        line = text.count("\n", 0, m.start()) + 1
                        matches.append((line, token or "<imperative>"))
        elif suffix in (".ts", ".tsx", ".js", ".mjs", ".cjs"):
            for m in _TS_TOOL_RE.finditer(text):
                desc = m.group("description") or ""
                is_adv, token = _check_text(desc, suffixes)
                if is_adv:
                    line = text.count("\n", 0, m.start()) + 1
                    matches.append((line, token or "<imperative>"))
        elif suffix == ".java":
            for m in _JAVA_TOOL_RE.finditer(text):
                desc = m.group("description") or ""
                is_adv, token = _check_text(desc, suffixes)
                if is_adv:
                    line = text.count("\n", 0, m.start()) + 1
                    matches.append((line, token or "<imperative>"))
        elif suffix == ".rs":
            for m in _RUST_TOOL_RE.finditer(text):
                desc = m.group("description") or ""
                is_adv, token = _check_text(desc, suffixes)
                if is_adv:
                    line = text.count("\n", 0, m.start()) + 1
                    matches.append((line, token or "<imperative>"))
        else:
            continue

        if matches:
            scanned.add(rel)
            for line, token in matches[:3]:  # cap to 3 per file to keep noise down
                findings.append(make_finding(
                    "AAK-MCP-FHI-001",
                    rel,
                    f"MCP tool description carries adversarial-suffix "
                    f"shape: {token!r}. Function-Hijacking class — "
                    "arXiv 2604.20994 reports 70-100% ASR on BFCL with "
                    "this pattern.",
                    line_number=line,
                ))
    return findings, scanned
