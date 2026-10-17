"""Transport-layer resource-limit checks.

Home of AAK-MCPFRAME-001 — mcp-framework < 0.2.22 HTTP body-size DoS
(CVE-2026-39313). Two detections:

1. Pin-check on `package.json` for `mcp-framework` at any version below
   0.2.22 (and `next-ai-draw-io` below 0.4.15, AAK-NEXT-AI-DRAW-001). It took
   the first number of the range, so `"<0.2.22"`, which admits only affected
   releases, read as the fix and was silent; it is now read as the CVE pin
   table reads it (`_dependency_pins`).
2. Pattern-check on `.ts` / `.js` / `.mjs` / `.tsx` files where a
   readRequestBody-style chunk-concat accumulates body bytes into a
   string without consulting a `Content-Length` guard or a
   `maxMessageSize`-style cap. Separate pass so custom transports
   written on top of upstream SDKs still get flagged.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._dependency_pins import DependencyPin, pinned_dependency, read_manifest
from ._helpers import blank_js_comments, in_skip_dir, find_line_number, make_finding, sub_comments

_MCPFRAME_PATCHED = (0, 2, 22)
_NEXT_AI_DRAW_PATCHED = (0, 4, 15)

# An unreadable spec (`latest`, `*`, a local directory, a git reference to a
# commit or a branch) is reported, as the first-number reader always reported one.
_MCPFRAME_PIN = DependencyPin(("mcp-framework",), _MCPFRAME_PATCHED, ecosystem="js", report_unversioned=True)
_NEXT_AI_DRAW_PIN = DependencyPin(("next-ai-draw-io",), _NEXT_AI_DRAW_PATCHED, ecosystem="js",
                                  report_unversioned=True)

_JS_EXTS = (".ts", ".tsx", ".js", ".mjs", ".cjs")

# Readable loosely: any `.on('data', ...)` or `for await (... of req)`
# block that concatenates into a string or an array without a running
# size guard. Deliberately literal so false positives don't explode.
#
# The handler arm read `[^)]*` up to the next `)` from every `req.on('data',`,
# so a file of them with no `)` read the rest of the file once per occurrence
# and stalled the scan. It now looks for that `)` within a fixed window. In a
# real handler it comes within a few characters (`(chunk) =>`, `function
# (chunk)`, `onData)`): at most 36 on 88,502 TS/JS files, so 1,024 changes no
# answer there and keeps the read per occurrence fixed.
_BODY_CONCAT_RE = re.compile(
    r"""
    (?:
        req\.on\(\s*['"]data['"]\s*,[^)]{0,1024}\)\s*  # req.on('data', handler)
      | for\s+await\s*\(\s*const\s+\w+\s+of\s+req(?:\.body)?\s*\)  # for await
    )
    """,
    re.VERBOSE,
)

# The `+=` arm used to end in `\s*;`, so a reader written without semicolons
# (StandardJS, or `{ body += chunk.toString() }`) was silent while
# `chunks.push(chunk)` in the same style was reported. It now ends at whatever
# ends the statement there: a `;`, a line break, or the `}` or `)` that closes
# the handler. The `.toString(...)` arguments are one character class rather
# than `[^)]*`, which read on to the next `)` from every `.toString(` and made a
# file of them quadratic. It is matched against the code with comments blanked
# (a comment after the statement hid its line break, and a commented-out one
# counted), and each name stands on its own, a leading underscore allowed
# (`this._body`), so `metadata += chunk` is not `data += chunk`.
_STR_ACCUMULATE_RE = re.compile(
    r"""
    (?:
        (?<![\w$])_?(?:body|data|buf|chunks)\s*\+=\s*\w+(?:\.toString\([\w'".,\s-]*\))?[ \t]*(?:[;})\r\n]|$)  # body += chunk
      | (?<![\w$])_?(?:body|data|buf|chunks)\.push\s*\(\s*\w+\s*\)                    # chunks.push(chunk)
    )
    """,
    re.VERBOSE,
)

_SIZE_GUARD_RE = re.compile(
    r"""
    (?:
        headers\s*\[\s*['"]content-length['"]    # req.headers['content-length']
      | maxMessageSize                           # upstream config
      | maxBodySize                              # express/fastify idiom
      | bodyLimit                                # fastify
      | limits?\s*:\s*\{\s*fileSize              # multer-style
      | \b(total|length|size)\s*[><]=?\s*\d+     # if (total > N)
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_LINE_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.MULTILINE | re.DOTALL)
_LINE_ONLY_COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE | re.DOTALL)


def _strip_comments(text: str) -> str:
    return sub_comments(_LINE_COMMENT_RE, _LINE_ONLY_COMMENT_RE, text)


def _check_package_json(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    pkg = project_root / "package.json"
    if not pkg.is_file():
        return findings
    rel = str(pkg.relative_to(project_root))
    scanned.add(rel)
    manifest = read_manifest(pkg)
    if manifest is None:
        return findings
    for rule_id, pin, name, tail in (
        ("AAK-MCPFRAME-001", _MCPFRAME_PIN, "mcp-framework",
         "CVE-2026-39313 HTTP-body DoS is patched in 0.2.22."),
        ("AAK-NEXT-AI-DRAW-001", _NEXT_AI_DRAW_PIN, "next-ai-draw-io",
         "CVE-2026-40608 body-accumulation DoS is patched in 0.4.15."),
    ):
        hit = pinned_dependency(manifest, pin)
        if hit is not None:
            # No line, as before: giving package.json findings one re-keys
            # their code-scanning alerts.
            findings.append(make_finding(
                rule_id, rel, f"{name} referenced as {hit.quote(f' in {hit.declaration.section}')} — {tail}",
            ))
    return findings


def _check_body_accumulation(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _JS_EXTS:
            continue
        if in_skip_dir(path, project_root):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "readRequestBody" not in text and not _BODY_CONCAT_RE.search(text):
            continue
        if not _STR_ACCUMULATE_RE.search(blank_js_comments(text)):
            continue
        # Check for size guard in code (not comments) — the documented
        # safe pattern. Strip // and /* */ comments so "no Content-Length
        # guard" in a fixture comment doesn't spuriously suppress.
        stripped = _strip_comments(text)
        if _SIZE_GUARD_RE.search(stripped):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-MCPFRAME-001",
            rel,
            "HTTP body chunks accumulated without a Content-Length or "
            "maxMessageSize guard — CVE-2026-39313 shape.",
            line_number=find_line_number(text, "data")
            or find_line_number(text, "req"),
        ))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    findings.extend(_check_package_json(project_root, scanned))
    findings.extend(_check_body_accumulation(project_root, scanned))
    return findings, scanned
