"""SSRF guard that tests a hostname it never unwrapped — CVE-2026-80347.

The guard is present. That is the whole problem, and it is why the existing SSRF
rules cannot see this: ``AAK-MCP-SSRF-001`` keys on a tool handler fetching a
caller URL with *no* allow-list, and ``AAK-LANGCHAIN-SSRF-REDIR-001`` keys on
following a 3xx past one. mcp-fetch has an allow-list and does not follow a
redirect. It simply asks the wrong question of the right value::

    const host = new URL(raw).hostname;   // "[::1]" — brackets kept
    if (net.isIP(host)) {                 // returns 0 for a bracketed literal
      if (host === "::1") return false;   // never reached
      return true;
    }
    return true;                          // falls through to allow

``URL.hostname`` in WHATWG (Node, browsers) keeps the brackets on an IPv6
literal. ``net.isIP`` does not accept them, so it returns 0, the entire
private-address branch is skipped, and the guard's default-allow tail runs. A
caller asking for ``http://[::1]/`` reaches loopback through a guard written to
stop exactly that.

**JS/TS only, deliberately.** Python's ``urlsplit().hostname`` strips the
brackets before you see it, so the same code shape in Python is not vulnerable
and flagging it would be inventing a finding. This is a WHATWG-URL semantic, not
a universal one, and the rule says so rather than generalising a language detail.

The detector wants the whole conjunction: a hostname read off a parsed URL, an
IP-classification call applied to that value, an outbound fetch in the same file
(so it is a guard for something), and no bracket normalisation anywhere. Strip
the brackets and it goes quiet, which is what the benign fixture asserts.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import SKIP_DIRS, find_line_number, make_finding

_RULE_ID = "AAK-SSRF-BRACKETED-HOST-001"

_JS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")

_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")

# A hostname taken off a parsed URL. `.host` is included: it keeps the brackets
# too (and adds the port), so it is no safer than `.hostname` here.
_URL_HOSTNAME_RE = re.compile(
    r"new\s+URL\s*\([^)]{0,200}\)\s*\.\s*hostname"
    r"|\b(?:parsed|url|u|target|dest)\w*\s*\.\s*hostname\b"
    r"|\.\s*hostname\s*(?:;|,|\)|$)",
    re.MULTILINE,
)

# The classification call that silently rejects a bracketed literal.
_IP_CLASSIFY_RE = re.compile(
    r"\bnet\s*\.\s*isIP\s*\("
    r"|\bisIPv?6?\s*\("
    r"|\bipaddress\s*\.\s*ip_address\s*\(",
)

# Any normalisation that makes the classification call correct again.
_BRACKET_STRIP_RE = re.compile(
    r"replace\s*\(\s*/\^?\\?\[.{0,40}?/[gimsuy]*\s*,"   # replace(/^\[|\]$/g, "")
    r"|replaceAll\s*\(\s*['\"]\[['\"]"
    r"|\.replace\s*\(\s*['\"]\[['\"]"
    r"|slice\s*\(\s*1\s*,\s*-\s*1\s*\)"
    r"|startsWith\s*\(\s*['\"]\[['\"]"
    r"|strip\s*\(\s*['\"]\[\]['\"]\s*\)"
    r"|\bunbracket\w*\s*\("
    r"|\bstripBrackets\b",
)

# The sink the guard exists to protect.
_FETCH_RE = re.compile(
    r"\bfetch\s*\(|\baxios\s*\.|\bgot\s*\(|\brequest\s*\(|https?\s*\.\s*get\s*\(",
)

# Enough context that this is a guard rather than incidental URL parsing.
_GUARD_RE = re.compile(
    r"\bis\w*Safe\w*\s*\(|\bisAllowed\w*\s*\(|\bvalidate\w*Url\w*\s*\("
    r"|\bssrf\b|\bblock(?:ed|list)\b|\ballow(?:ed)?list\b|\bguard\b|private[-_ ]?address",
    re.IGNORECASE,
)


def _strip_comments(text: str) -> str:
    return _TS_LINE_COMMENT_RE.sub(" ", _TS_BLOCK_COMMENT_RE.sub(" ", text))


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for SSRF guards that classify a bracketed IPv6 hostname.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for path in project_root.rglob("*"):
        if path.suffix not in _JS_SUFFIXES:
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
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        text = _strip_comments(raw)
        if not (
            _URL_HOSTNAME_RE.search(text)
            and _IP_CLASSIFY_RE.search(text)
            and _FETCH_RE.search(text)
            and _GUARD_RE.search(text)
        ):
            continue
        if _BRACKET_STRIP_RE.search(text):
            continue

        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.append(make_finding(
            _RULE_ID,
            rel_path,
            (
                "SSRF guard reads `.hostname` from a parsed URL and hands it to an "
                "IP-classification call without removing the brackets WHATWG keeps "
                "on an IPv6 literal. `net.isIP('[::1]')` returns 0, so the "
                "private-address branch is skipped and the guard falls through to "
                "allow — `http://[::1]/` reaches loopback through a check written "
                "to stop it (CVE-2026-80347 class). Strip the brackets before "
                "classifying, and default to deny rather than allow."
            ),
            find_line_number(raw, "isIP") or find_line_number(raw, "hostname"),
        ))

    return findings, scanned_files
