"""Deny-policy evaluated on a truncated string the executor never truncates.

`AAK-POLICY-TRUNCATION-001`.

A hook bridge, gateway or guard reads a candidate command / URL / path, cuts it
to a fixed length "for matching", and evaluates its deny patterns against the cut
copy — while the thing that actually runs receives the full, untruncated value.
Anything an attacker positions past the cut point is invisible to the policy and
visible to the executor.

CVE-2026-73614 (Network-AI ClaudeHookBridge < 5.15.1, CVSS 8.8) is the disclosed
instance: the target string is truncated to 500 characters before `denyPatterns`
are evaluated, while Claude Code executes the full Bash command field, so
dangerous content placed past byte 500 bypasses the operator's hard-deny list.

That CVE is **not** pinnable — the package resolves on neither npm nor PyPI and
its GitHub repository 404s (see `CHANGELOG.cves.md`, 2026-08-14) — so this rule
is deliberately vendor-independent. It keys on the *shape*, which is a general
bug in policy code, not on the vendor.

Detection is intentionally narrow. All three must hold in one file:

  1. a truncation with a fixed bound assigned to a variable
     (`x = cmd.slice(0, 500)`, `x = cmd[:500]`, ...);
  2. that variable is then tested against a deny / block / forbid construct;
  3. the untruncated source is still referenced elsewhere — otherwise the whole
     program only ever sees the short string, and there is no asymmetry.

Requiring (3) is what keeps this off legitimate display truncation, where the
short copy is the only copy anyone uses.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, find_line_number, make_finding

_RULE_ID = "AAK-POLICY-TRUNCATION-001"
_MAX_FILE_BYTES = 1_000_000

# `const short = cmd.slice(0, 500)` / `.substring(0, 500)` / `.substr(0, 500)`
_JS_TRUNC_RE = re.compile(
    r"""(?:const|let|var)?\s*(?P<var>[A-Za-z_$][\w$]*)\s*=\s*
        (?P<src>[A-Za-z_$][\w$.\[\]]*)\s*\.\s*
        (?:slice|substring|substr)\s*\(\s*0\s*,\s*(?P<n>\d{2,})\s*\)""",
    re.VERBOSE,
)
# `short = cmd[:500]`
_PY_TRUNC_RE = re.compile(
    r"""(?P<var>[A-Za-z_]\w*)\s*=\s*
        (?P<src>[A-Za-z_][\w.\[\]]*)\s*\[\s*:\s*(?P<n>\d{2,})\s*\]""",
    re.VERBOSE,
)

# A deny / block decision being made. Deliberately broad on naming, because the
# vendor names vary, but it must look like a *policy* decision, not any regex.
_DENY_CONTEXT_RE = re.compile(
    r"deny[_A-Za-z]*(?:Pattern|List|Rule|Match|Regex|s)\b"
    r"|block(?:ed)?[_A-Za-z]*(?:Pattern|List|Rule|Match|Regex|s)\b"
    r"|forbidden[_A-Za-z]*\b"
    r"|disallow(?:ed)?[_A-Za-z]*\b"
    r"|blacklist\w*"
    r"|hard[_-]?deny\w*",
    re.IGNORECASE,
)

# The test operation itself, applied to the truncated variable. Covers both
# argument positions, because the idiom differs by language: JS tends to put the
# subject first (`target.match(p)`, `p.test(target)`) while Python's `re` module
# puts it last (`re.search(pattern, target)`).
_TEST_TEMPLATE = (
    r"(?:{var}\s*\.\s*(?:match|search|test|includes|startsWith|indexOf)\s*\()"
    r"|(?:\.\s*(?:test|exec|search|match|fullmatch)\s*\(\s*{var}\s*\))"
    r"|(?:\b(?:search|match|fullmatch|findall|test|exec)\s*\([^)]*,\s*{var}\s*\))"
    r"|(?:\bin\s+{var}\b)"
    r"|(?:{var}\s+in\b)"
    r"|(?:\(\s*{var}\s*\))"
)

_JS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_PY_SUFFIXES = (".py",)

_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_PY_DOCSTRING_RE = re.compile(r'""".*?"""|\'\'\'.*?\'\'\'', re.DOTALL)
_PY_COMMENT_RE = re.compile(r"#[^\n]*")


def _strip_prose(text: str, is_python: bool) -> str:
    """Comments must not create or clear a finding."""
    if is_python:
        return _PY_COMMENT_RE.sub(" ", _PY_DOCSTRING_RE.sub(" ", text))
    return _TS_LINE_COMMENT_RE.sub(" ", _TS_BLOCK_COMMENT_RE.sub(" ", text))


def _source_used_untruncated(code: str, src: str, var: str) -> bool:
    """Is the original still referenced somewhere other than the truncation?

    Without this, a file that truncates once and only ever uses the short copy
    is legitimate — there is no policy/executor asymmetry to exploit.
    """
    base = re.escape(src)
    # Occurrences of the source identifier that are not the truncation itself.
    hits = len(re.findall(rf"(?<![\w$.]){base}(?![\w$])", code))
    # One hit is the truncation's own right-hand side.
    return hits >= 2 and src != var


def _policy_tests_the_truncated_value(code: str, var: str) -> bool:
    pattern = _TEST_TEMPLATE.format(var=re.escape(var))
    for m in re.finditer(pattern, code):
        # The deny context must be near the test, not merely somewhere in file.
        window = code[max(0, m.start() - 400):m.end() + 400]
        if _DENY_CONTEXT_RE.search(window):
            return True
    return False


def _scan_text(code: str, is_python: bool) -> tuple[str, str, str] | None:
    """Return (var, src, bound) for the first genuine truncation-before-deny."""
    if not _DENY_CONTEXT_RE.search(code):
        return None
    trunc_re = _PY_TRUNC_RE if is_python else _JS_TRUNC_RE
    for m in trunc_re.finditer(code):
        var, src, bound = m.group("var"), m.group("src"), m.group("n")
        if not _policy_tests_the_truncated_value(code, var):
            continue
        if not _source_used_untruncated(code, src, var):
            continue
        return var, src, bound
    return None


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for deny policies evaluated against a truncated copy of their input.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of evaluated rule IDs).
    """
    findings: list[Finding] = []
    evaluated = {_RULE_ID}

    for path in sorted(project_root.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        is_python = suffix in _PY_SUFFIXES
        if not (is_python or suffix in _JS_SUFFIXES):
            continue
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        hit = _scan_text(_strip_prose(raw, is_python), is_python)
        if hit is None:
            continue
        var, src, bound = hit

        rel = path.relative_to(project_root).as_posix()
        findings.append(make_finding(
            _RULE_ID,
            rel,
            (
                f"Deny policy is evaluated against `{var}`, a copy of `{src}` cut "
                f"to {bound} characters, while `{src}` is still used untruncated "
                f"elsewhere in the file. Whatever sits past character {bound} is "
                f"invisible to the deny patterns and visible to whatever consumes "
                f"`{src}` — so a caller places the dangerous part after the cut and "
                f"the hard-deny list never sees it. This is the ClaudeHookBridge "
                f"shape (CVE-2026-73614, CVSS 8.8: truncation to 500 characters "
                f"before `denyPatterns`, while Claude Code executed the full "
                f"command). Evaluate the policy on exactly the value the executor "
                f"receives; if a bound is needed for cost, reject over-long input "
                f"rather than matching a prefix of it."
            ),
            find_line_number(raw, f"{bound}") or find_line_number(raw, var),
        ))

    return findings, evaluated
