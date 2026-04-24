"""AAK-SPLUNK-TOKLOG-001 — token-shaped values in log sinks.

CVE-2026-20205 (splunk-mcp-server < 1.0.3) logged session tokens into
the Splunk `_internal` index in cleartext. The pattern generalises:
any `logger.info|warn|error` or `print` whose interpolated argument
matches a Bearer / JWT / `splunkd_session` / `st-*` shape is a token
leak into whatever the log sink is wired to.

Two detections:

1. Pattern: log-sink call (Python / TS / JS) whose argument contains a
   token-shaped literal or a variable named `token`, `auth`, `bearer`,
   etc., interpolated into a format string.
2. Pin check: `splunk-mcp-server < 1.0.3` in Python / npm manifests.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, find_line_number, make_finding

_SPLUNK_PATCHED = (1, 0, 3)
_SEMVER_RE = re.compile(r"[^\d]*(\d+)\.(\d+)(?:\.(\d+))?")

_LOG_SINK_RE = re.compile(
    r"""
    (?:
        \b(?:logger|logging|LOGGER|log)\s*\.\s*(?:info|warning|warn|error|critical|exception|debug|severe|fine)\s*\(
      | \bprint\s*\(
      | \bconsole\s*\.\s*(?:log|info|warn|error|debug)\s*\(
      | \bSystem\s*\.\s*out\s*\.\s*print(?:ln)?\s*\(
    )
    """,
    re.VERBOSE,
)

_TOKEN_SHAPE_RE = re.compile(
    r"""
    (?:
        Bearer\s+[A-Za-z0-9._\-]{20,}                    # "Bearer eyJ..."
      | eyJ[A-Za-z0-9._\-]{20,}                          # raw JWT
      | splunkd_session=[A-Za-z0-9._\-]{10,}             # Splunk cookie
      | \bst-[A-Za-z0-9]{40,}\b                          # Splunk session token
      | sk-ant-[A-Za-z0-9_\-]{20,}                       # Anthropic API key
      | \bghp_[A-Za-z0-9]{20,}\b                         # GitHub PAT
    )
    """,
    re.VERBOSE,
)

_TOKEN_VAR_RE = re.compile(
    r"""
    \b(?:
        session_?token | splunkd_session | access_?token | id_?token
      | auth_?token | bearer | api_?key | refresh_?token
    )\b
    """,
    re.VERBOSE | re.IGNORECASE,
)

_REDACT_HINTS_RE = re.compile(
    r"""
    (?:
        redact\b | mask\b | anonymi[sz]e\b | \*{3,} | <redacted> | \[redacted\]
      | \.replace\s*\([^)]*(?:token|auth|bearer|key)[^)]*,\s*['"](\*{3,}|[\[\]<>]*redacted[\[\]<>]*)
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_PY_EXTS = (".py",)
_JS_EXTS = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_JAVA_EXTS = (".java", ".kt")


def _parse_semver(spec: str | None) -> tuple[int, int, int] | None:
    if not spec:
        return None
    m = _SEMVER_RE.match(str(spec))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def _collect_log_call_args(text: str) -> list[tuple[str, int]]:
    """Return a list of (arg_substring, line) pairs for each log-sink call.

    Not a real parser — we walk the opening paren until matched. Good
    enough for scanner heuristics; AST would be nice but per-language.
    """
    out: list[tuple[str, int]] = []
    for match in _LOG_SINK_RE.finditer(text):
        open_idx = match.end() - 1  # position of '('
        depth = 0
        i = open_idx
        while i < len(text):
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if depth != 0:
            continue
        arg_str = text[open_idx + 1 : i]
        line = text.count("\n", 0, match.start()) + 1
        out.append((arg_str, line))
    return out


def _contains_token_leak(arg_str: str) -> bool:
    if _REDACT_HINTS_RE.search(arg_str):
        return False
    if _TOKEN_SHAPE_RE.search(arg_str):
        return True
    # Format-string interpolation of a token-named variable.
    # `f"session={token}"`, `logger.info("bearer %s", bearer_token)`, etc.
    if _TOKEN_VAR_RE.search(arg_str):
        return True
    return False


def _check_pattern(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _PY_EXTS + _JS_EXTS + _JAVA_EXTS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for arg_str, line in _collect_log_call_args(text):
            if _contains_token_leak(arg_str):
                rel = str(path.relative_to(project_root))
                scanned.add(rel)
                findings.append(make_finding(
                    "AAK-SPLUNK-TOKLOG-001",
                    rel,
                    "Log sink call contains a token-shaped value or "
                    "unredacted token variable — CVE-2026-20205 shape.",
                    line_number=line,
                ))
                break  # One finding per file is plenty.
    return findings


def _check_splunk_pin(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    for req in project_root.glob("requirements*.txt"):
        try:
            text = req.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(req.relative_to(project_root))
        scanned.add(rel)
        for lineno, line in enumerate(text.splitlines(), 1):
            raw = line.split("#", 1)[0].strip()
            if not raw:
                continue
            m = re.match(
                r"^(splunk[_-]mcp[_-]server)\s*(==|<=|<|~=)\s*([0-9][0-9A-Za-z.\-+]*)\s*$",
                raw,
                re.IGNORECASE,
            )
            if not m:
                continue
            parsed = _parse_semver(m.group(3))
            if parsed and parsed < _SPLUNK_PATCHED:
                findings.append(make_finding(
                    "AAK-SPLUNK-TOKLOG-001",
                    rel,
                    f"splunk-mcp-server pinned at {m.group(2)}{m.group(3)} — "
                    "CVE-2026-20205 fixed in 1.0.3.",
                    line_number=lineno,
                ))

    pyproject = project_root / "pyproject.toml"
    if pyproject.is_file():
        try:
            text = pyproject.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for m in re.finditer(
            r"""['"]splunk[-_]mcp[-_]server['"]?\s*[=<>~]=?\s*['"]?([0-9][0-9A-Za-z.\-+]*)['"]?""",
            text,
            re.IGNORECASE,
        ):
            parsed = _parse_semver(m.group(1))
            if parsed and parsed < _SPLUNK_PATCHED:
                findings.append(make_finding(
                    "AAK-SPLUNK-TOKLOG-001",
                    "pyproject.toml",
                    f"splunk-mcp-server pinned at {m.group(1)} in pyproject.toml — "
                    "CVE-2026-20205 fixed in 1.0.3.",
                    line_number=find_line_number(text, m.group(0)),
                ))
                scanned.add("pyproject.toml")

    pkg = project_root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            data = {}
        if isinstance(data, dict):
            for section in ("dependencies", "devDependencies"):
                deps = data.get(section) or {}
                if not isinstance(deps, dict):
                    continue
                spec = deps.get("splunk-mcp-server")
                if not spec:
                    continue
                parsed = _parse_semver(str(spec))
                if parsed and parsed < _SPLUNK_PATCHED:
                    findings.append(make_finding(
                        "AAK-SPLUNK-TOKLOG-001",
                        "package.json",
                        f"splunk-mcp-server pinned at {spec!r} in {section} — "
                        "CVE-2026-20205 fixed in 1.0.3.",
                    ))
                    scanned.add("package.json")

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    findings.extend(_check_pattern(project_root, scanned))
    findings.extend(_check_splunk_pin(project_root, scanned))
    return findings, scanned
