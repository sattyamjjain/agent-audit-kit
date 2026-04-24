"""Transport-layer resource-limit checks.

Home of AAK-MCPFRAME-001 — mcp-framework < 0.2.22 HTTP body-size DoS
(CVE-2026-39313). Two detections:

1. Pin-check on `package.json` (dependencies / devDependencies /
   peerDependencies) for `mcp-framework` at any version below 0.2.22.
2. Pattern-check on `.ts` / `.js` / `.mjs` / `.tsx` files where a
   readRequestBody-style chunk-concat accumulates body bytes into a
   string without consulting a `Content-Length` guard or a
   `maxMessageSize`-style cap. Separate pass so custom transports
   written on top of upstream SDKs still get flagged.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, find_line_number, make_finding

_MCPFRAME_PATCHED = (0, 2, 22)
_NEXT_AI_DRAW_PATCHED = (0, 4, 15)

_SEMVER_RE = re.compile(r"[^\d]*(\d+)\.(\d+)(?:\.(\d+))?")

_JS_EXTS = (".ts", ".tsx", ".js", ".mjs", ".cjs")

# Readable loosely: any `.on('data', ...)` or `for await (... of req)`
# block that concatenates into a string or an array without a running
# size guard. Deliberately literal so false positives don't explode.
_BODY_CONCAT_RE = re.compile(
    r"""
    (?:
        req\.on\(\s*['"]data['"]\s*,[^)]*\)\s*  # req.on('data', handler)
      | for\s+await\s*\(\s*const\s+\w+\s+of\s+req(?:\.body)?\s*\)  # for await
    )
    """,
    re.VERBOSE,
)

_STR_ACCUMULATE_RE = re.compile(
    r"""
    (?:
        (?:body|data|buf|chunks)\s*\+=\s*\w+(?:\.toString\([^)]*\))?\s*;  # body += chunk
      | (?:body|data|buf|chunks)\.push\s*\(\s*\w+\s*\)                    # chunks.push(chunk)
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


def _strip_comments(text: str) -> str:
    return _LINE_COMMENT_RE.sub("", text)


def _parse_semver(spec: str) -> tuple[int, int, int] | None:
    m = _SEMVER_RE.match(str(spec))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def _check_package_json(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    pkg = project_root / "package.json"
    if not pkg.is_file():
        return findings
    rel = str(pkg.relative_to(project_root))
    scanned.add(rel)
    try:
        data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return findings
    if not isinstance(data, dict):
        return findings
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        spec = deps.get("mcp-framework")
        if spec:
            parsed = _parse_semver(str(spec))
            if parsed is None or parsed < _MCPFRAME_PATCHED:
                findings.append(make_finding(
                    "AAK-MCPFRAME-001",
                    rel,
                    f"mcp-framework pinned at {spec!r} in {section} — "
                    "CVE-2026-39313 HTTP-body DoS is patched in 0.2.22.",
                ))
        draw_spec = deps.get("next-ai-draw-io")
        if draw_spec:
            parsed = _parse_semver(str(draw_spec))
            if parsed is None or parsed < _NEXT_AI_DRAW_PATCHED:
                findings.append(make_finding(
                    "AAK-NEXT-AI-DRAW-001",
                    rel,
                    f"next-ai-draw-io pinned at {draw_spec!r} in {section} — "
                    "CVE-2026-40608 body-accumulation DoS is patched in 0.4.15.",
                ))
    return findings


def _check_body_accumulation(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _JS_EXTS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "readRequestBody" not in text and not _BODY_CONCAT_RE.search(text):
            continue
        if not _STR_ACCUMULATE_RE.search(text):
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
