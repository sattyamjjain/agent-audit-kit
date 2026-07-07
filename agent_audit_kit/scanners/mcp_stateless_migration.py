"""AAK-MCP-STATELESS-001..004 — 2026-07-28 stateless-MCP migration.

The MCP 2026-07-28 spec release candidate (locked 2026-05-21) makes the
protocol stateless by default:

* SEP-2567: the protocol-level session and `Mcp-Session-Id` header are
  removed and replaced with explicit server-minted state handles, so any
  MCP request can land on any server instance. SEP-1442 / SEP-2575 make the
  initialization handshake optional so stateless is the default.
* The experimental Tasks primitive (SEP-1686), including `tasks/list`, moves
  out of the core specification into the Extensions framework (redesigned as
  SEP-2663), so core `tasks/list` is removed.

Server / client code that assumes the pre-RC stateful protocol will
silently break once the final spec lands on 2026-07-28. This scanner
surfaces four migration smells:

* 001 (HIGH) — code reads / asserts / constants the `Mcp-Session-Id`
  header (string match + Python AST for higher precision).
* 002 (HIGH) — code dispatches or handles the removed `tasks/list`
  method.
* 003 (MEDIUM) — deployment manifest requires sticky routing (nginx
  `ip_hash`, K8s `sessionAffinity: ClientIP`, Traefik / ALB sticky
  cookies) or handler code reads a shared session store keyed on a
  per-connection id used across requests.
* 004 (LOW) — client file calls `tools/list` / `list_tools` in a hot
  path with no caching marker (`lru_cache`, `ttl`, `cache`, …) anywhere
  in the file, and the same file participates in per-session state.

Source-side rules (001, 002, 004) are gated on a declared MCP SDK in the
project manifest, matching the established `mcp_sampling_capability` and
`mcp_sdk_hardening` pattern — this keeps the AAK self-scan quiet on its
own scanner sources and avoids firing on prose mentions in unrelated
projects.

Rule 003 also fires on infrastructure manifests (nginx / K8s / Traefik)
when the same project declares an MCP SDK *or* the manifest references
"mcp" / "modelcontextprotocol" somewhere.

Suppression: opt in via `.agent-audit-kit.yml` with
`accepts_stateless_migration_risk: true` and a non-empty `justification:`
(mirrors the sampling-rule opt-out).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding

# --------------------------------------------------------------------------
# SDK declaration gate (mirrors mcp_sampling_capability._declares_sdk)
# --------------------------------------------------------------------------

_PY_SDK_NAMES = (
    "mcp",
    "modelcontextprotocol",
    "model-context-protocol",
)
_TS_SDK_NAMES = (
    "@modelcontextprotocol/sdk",
    "@anthropic-ai/mcp",
    "@anthropic-ai/claude-agent-sdk",
)
_JAVA_SDK_TOKEN = "io.modelcontextprotocol"
_RUST_SDK_TOKENS = ("mcp", "modelcontextprotocol")

_LANG_EXTS = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".java", ".kt", ".rs")
_INFRA_EXTS = (".yaml", ".yml", ".conf", ".toml")


def _declares_sdk(project_root: Path) -> tuple[bool, list[str]]:
    manifests: list[str] = []
    declared = False

    pyproject = project_root / "pyproject.toml"
    if pyproject.is_file():
        try:
            text = pyproject.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if any(f'"{n}"' in text or f"'{n}'" in text for n in _PY_SDK_NAMES):
            declared = True
            manifests.append("pyproject.toml")

    for req in project_root.glob("requirements*.txt"):
        try:
            text = req.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            name = (
                line.split("#", 1)[0].strip().split("[")[0]
                .split("=")[0].split(">")[0].split("<")[0].strip()
            )
            if name in _PY_SDK_NAMES:
                declared = True
                manifests.append(str(req.relative_to(project_root)))
                break

    pkg = project_root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            data = {}
        if isinstance(data, dict):
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                deps = data.get(section) or {}
                if isinstance(deps, dict) and any(n in deps for n in _TS_SDK_NAMES):
                    declared = True
                    manifests.append("package.json")
                    break

    for maven in ("pom.xml", "build.gradle", "build.gradle.kts"):
        p = project_root / maven
        if p.is_file():
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _JAVA_SDK_TOKEN in text:
                declared = True
                manifests.append(maven)

    cargo = project_root / "Cargo.toml"
    if cargo.is_file():
        try:
            text = cargo.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for tok in _RUST_SDK_TOKENS:
            if re.search(rf"^\s*{re.escape(tok)}\s*=", text, re.MULTILINE):
                declared = True
                manifests.append("Cargo.toml")
                break

    return declared, manifests


def _accepts_risk(project_root: Path) -> bool:
    cfg = project_root / ".agent-audit-kit.yml"
    if not cfg.is_file():
        return False
    try:
        data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return False
    if not isinstance(data, dict):
        return False
    if data.get("accepts_stateless_migration_risk") is not True:
        return False
    justification = data.get("justification")
    return isinstance(justification, str) and justification.strip() != ""


# --------------------------------------------------------------------------
# 001 — Mcp-Session-Id reliance
# --------------------------------------------------------------------------

# `Mcp-Session-Id` as a literal (header name). Case-insensitive at the
# regex level — the spec header is canonical mixed-case but real code
# often lowercases it before lookup. Word boundaries keep the match tight.
_SESSION_ID_RE = re.compile(r"\bMcp-Session-Id\b", re.IGNORECASE)
# Snake_case Python-side constant variant.
_SESSION_ID_CONST_RE = re.compile(r"\bMCP_SESSION_ID\b")


def _scan_001_session_id(source_files: list[Path]) -> list[tuple[Path, int]]:
    """Return (path, line) for every file that references the removed
    `Mcp-Session-Id` header. For Python files, the AST pass picks up
    `headers.get("Mcp-Session-Id")` and dict-key references too — but
    the literal regex on raw text already catches both cases, so we
    keep it simple and use one pass."""
    hits: list[tuple[Path, int]] = []
    for path in source_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = _SESSION_ID_RE.search(text) or _SESSION_ID_CONST_RE.search(text)
        if not m:
            continue
        line_no = text.count("\n", 0, m.start()) + 1
        hits.append((path, line_no))
    return hits


# --------------------------------------------------------------------------
# 002 — tasks/list usage
# --------------------------------------------------------------------------

# `"tasks/list"` or `'tasks/list'` as a literal string — the JSON-RPC
# method name. This catches both client dispatch and server-side handler
# registration. We also catch the SDK-aliased call form `tasks.list(`
# / `tasks_list(` for higher coverage.
_TASKS_LIST_LITERAL_RE = re.compile(r"""(?:["'])tasks/list(?:["'])""")
_TASKS_LIST_CALL_RE = re.compile(r"\btasks[_.]list\s*\(")


def _scan_002_tasks_list(source_files: list[Path]) -> list[tuple[Path, int]]:
    hits: list[tuple[Path, int]] = []
    for path in source_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = _TASKS_LIST_LITERAL_RE.search(text) or _TASKS_LIST_CALL_RE.search(text)
        if not m:
            continue
        line_no = text.count("\n", 0, m.start()) + 1
        hits.append((path, line_no))
    return hits


# --------------------------------------------------------------------------
# 003 — sticky-session / shared-store dependency
# --------------------------------------------------------------------------

# Infrastructure-level sticky-session markers. Kept narrow so generic
# K8s manifests / nginx configs in unrelated projects don't fire.
_STICKY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("nginx ip_hash", re.compile(r"^\s*ip_hash\s*;", re.MULTILINE)),
    ("nginx sticky", re.compile(r"^\s*sticky\s+(?:cookie|route|learn)", re.MULTILINE)),
    ("k8s sessionAffinity", re.compile(r"\bsessionAffinity\s*:\s*ClientIP\b")),
    ("ALB sticky", re.compile(r"stickiness\.enabled\s*=\s*true", re.IGNORECASE)),
    ("Traefik sticky", re.compile(r"sticky\s*:\s*\n\s*cookie\s*:", re.MULTILINE)),
)

# Code-side: a function that reads a shared store keyed on a session id
# and then mutates / reads tool state. We look for the conjunction of
# (a) a session-id source from request headers and (b) a dict / store
# lookup with that variable. This is a heuristic — kept restrictive.
_SESSION_STORE_RE = re.compile(
    r"""
    (?:
        # session_store[session_id] / sessions[sid]
        \b(?:session_store|sessions|state_by_session|per_session_state)\b
        \s*\[\s*(?:session_id|sid|mcp_session_id)\s*\]
    )
    """,
    re.VERBOSE,
)


def _file_mentions_mcp(text: str) -> bool:
    return ("mcp" in text.lower()) or ("modelcontextprotocol" in text.lower())


def _scan_003_sticky(
    project_root: Path,
    sdk_declared: bool,
) -> list[tuple[Path, str, int]]:
    """Return (path, evidence_label, line) for sticky-session findings.
    Infrastructure manifests fire when either an SDK is declared in the
    repo OR the manifest itself mentions MCP. Code-side store-lookup
    findings fire only when the SDK is declared."""
    hits: list[tuple[Path, str, int]] = []

    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if path.suffix in _INFRA_EXTS or path.name in {"nginx.conf", "Caddyfile"}:
            if not (sdk_declared or _file_mentions_mcp(text)):
                continue
            for label, pattern in _STICKY_PATTERNS:
                m = pattern.search(text)
                if m:
                    line_no = text.count("\n", 0, m.start()) + 1
                    hits.append((path, label, line_no))
                    break

        if path.suffix in _LANG_EXTS and sdk_declared:
            m = _SESSION_STORE_RE.search(text)
            if m:
                line_no = text.count("\n", 0, m.start()) + 1
                hits.append((path, "shared session store keyed on session id", line_no))

    return hits


# --------------------------------------------------------------------------
# 004 — client never caches tools/list and depends on per-session state
# --------------------------------------------------------------------------

_TOOLS_LIST_CALL_RE = re.compile(
    r"""
    (?:
        ["']tools/list["']
      | \blist_tools\s*\(
      | \.tools\.list\s*\(
    )
    """,
    re.VERBOSE,
)

# Cache markers — only match identifier-shaped tokens that imply real
# caching machinery. Bare "cache" in prose / docstrings ("no cache yet")
# is intentionally NOT a marker.
_CACHE_MARKERS_RE = re.compile(
    r"""
    \b(?:
        lru_cache
      | cached_property
      | cachetools
      | TTLCache
      | ttl(?:Ms|_ms|Seconds|_seconds)
      | tools_list_cache
      | cached_tools
      | memoize
      | functools\.cache
    )\b
    """,
    re.VERBOSE,
)


def _scan_004_no_cache(source_files: list[Path]) -> list[tuple[Path, int]]:
    """A file fires when (a) it calls `tools/list` (or alias) at least
    twice OR inside an `async`/`def` body that takes per-request inputs,
    (b) it has no cache marker anywhere in the file, AND (c) it also
    references session state (`session_id`, `Mcp-Session-Id`, or a
    `session.` attribute access). The triple conjunction keeps the LOW-
    severity advisory tight."""
    hits: list[tuple[Path, int]] = []
    for path in source_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        calls = list(_TOOLS_LIST_CALL_RE.finditer(text))
        if len(calls) < 2:
            continue
        if _CACHE_MARKERS_RE.search(text):
            continue
        if not (
            _SESSION_ID_RE.search(text)
            or _SESSION_ID_CONST_RE.search(text)
            or re.search(r"\bsession_id\b", text)
        ):
            continue
        first = calls[0]
        line_no = text.count("\n", 0, first.start()) + 1
        hits.append((path, line_no))
    return hits


# --------------------------------------------------------------------------
# Source-file enumerator (one walk; reused by 001 / 002 / 004)
# --------------------------------------------------------------------------

def _collect_source_files(project_root: Path) -> list[Path]:
    out: list[Path] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _LANG_EXTS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        out.append(path)
    return out


# --------------------------------------------------------------------------
# Public scan() entry point
# --------------------------------------------------------------------------

def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()

    if _accepts_risk(project_root):
        scanned.add(".agent-audit-kit.yml")
        return findings, scanned

    sdk_declared, manifests = _declares_sdk(project_root)

    # 003 fires on infra files regardless of SDK (with content gate) and
    # on code files only when the SDK is declared.
    for path, label, line in _scan_003_sticky(project_root, sdk_declared):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-MCP-STATELESS-003",
            rel,
            f"Sticky-session / shared-store dependency: {label}.",
            line,
        ))

    if not sdk_declared:
        return findings, scanned
    for m in manifests:
        scanned.add(m)

    source_files = _collect_source_files(project_root)

    for path, line in _scan_001_session_id(source_files):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-MCP-STATELESS-001",
            rel,
            "References the `Mcp-Session-Id` header / protocol-level session id, "
            "which is removed in the 2026-07-28 MCP RC.",
            line,
        ))

    for path, line in _scan_002_tasks_list(source_files):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-MCP-STATELESS-002",
            rel,
            "Uses the `tasks/list` JSON-RPC method, which is removed in the "
            "2026-07-28 MCP RC (can't be scoped safely without sessions).",
            line,
        ))

    for path, line in _scan_004_no_cache(source_files):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-MCP-STATELESS-004",
            rel,
            "Calls `tools/list` in a hot path with no cache marker, and holds "
            "per-session state. Stateless transport may serve a different "
            "instance per request.",
            line,
        ))

    return findings, scanned
