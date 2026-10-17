"""AAK-MCP-INSPECTOR-CVE-2026-23744-001 — vendored MCPJam fork RCE.

CVSS 9.8 in `@mcpjam/inspector` ≤ 1.4.2 (GHSA-232v-j27c-5pp6): the server
listens on 0.0.0.0, and a crafted request makes it install and run an MCP
server. 1.4.3 binds 127.0.0.1. Closes the gap between the config-only
AAK-MCP-INSPECTOR preset entry and forks/vendored copies that ship the
vulnerable code unpatched.

Detection:
1. A copy of the package: a `node_modules/@mcpjam/inspector/` directory, or
   any directory whose name contains `mcpjam-inspector` (`vendor/mcpjam-
   inspector/`), holding code. One finding per copy, judged by the copy's
   own package.json: a copy that names `@mcpjam/inspector` at 1.4.3 or later
   is patched and quiet. A copy that states no such version (no package.json,
   one that does not parse, or a fork renamed to its own numbering) is
   reported, because nothing says which release it carries.
2. Call-shape: `inspectorServer.handle(<arg>, <arg>)` regardless of
   import path, per file — catches forks where the vendor moved files but kept
   the call shape. Outside a copy nothing else is read: a file named after
   the inspector is not a copy.

Why a copy is read as a whole, not file by file: the published package keeps
its server in `dist/server/index.js` and only a `bin/` shim outside `dist/`
(1.4.2, 1.4.3 and 3.16.1 alike). The shared skip list drops `dist/`, `build/`
and `out/`, so the rule read the shim alone, decided on the path, and reported
every install at CRITICAL, a patched 3.x included. Reading `dist/` the same way
would have reported every file of every install. Inside a copy nothing is
skipped, and a dated copy needs none of its code read: the path places the copy
and package.json dates it. An undated one is reported on its first
`inspectorServer.handle(` call, where it makes one. Above the copy the usual
skip list applies, minus `vendor/` and `node_modules/`, so a copy inside a
`dist/` bundle stays out.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import (
    MANIFEST_MAX_BYTES,
    SKIP_DIRS,
    SOURCE_MAX_BYTES,
    in_skip_dir,
    loads_json,
    make_finding,
    read_text_capped,
)


# Override SKIP_DIRS for this scanner: detecting vendored copies in
# vendor/ + node_modules/ is the whole point.
_INSPECTOR_SKIP_DIRS = SKIP_DIRS - {"vendor", "node_modules"}

_PACKAGE = "@mcpjam/inspector"
_FIXED_IN: tuple[int, int, int] = (1, 4, 3)
_FORK_DIR_HINT = "mcpjam-inspector"
_INSPECTOR_CALL_RE = re.compile(
    r"\binspectorServer\s*\.\s*handle\s*\(",
)
_TARGET_EXTS = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_VERSION_KEY_RE = re.compile(r'"version"\s*:')


def _copy_root(parts: tuple[str, ...]) -> int | None:
    """How many leading parts of a relative file path name the copy it sits in.

    `node_modules/@mcpjam/inspector/...` is the npm package itself; another
    `@mcpjam/*` package such as `@mcpjam/inspector-v1` is not. A directory
    whose name contains `mcpjam-inspector` is a vendored copy. A file name that
    contains it is not a directory, so it is no copy.
    """
    dirs = [p.lower() for p in parts[:-1]]
    for i, part in enumerate(dirs):
        if part == "@mcpjam" and i + 1 < len(dirs) and dirs[i + 1] == "inspector":
            return i + 2
        if _FORK_DIR_HINT in part:
            return i + 1
    return None


def _stated_version(root: Path) -> tuple[tuple[int, int, int], str, int] | None:
    """(version, as written, line) from a copy's package.json when it names
    `@mcpjam/inspector`, or None when nothing says which release the copy is."""
    manifest = root / "package.json"
    try:
        text = read_text_capped(manifest, MANIFEST_MAX_BYTES, encoding="utf-8-sig")
        data = loads_json(text, manifest)
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or str(data.get("name", "")).lower() != _PACKAGE:
        return None
    written = data.get("version")
    m = _VERSION_RE.match(written.strip()) if isinstance(written, str) else None
    if m is None:
        return None
    key = _VERSION_KEY_RE.search(text)
    line = text.count("\n", 0, key.start()) + 1 if key else 1
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))), str(written), line


def _call_site(project_root: Path, files: list[str]) -> tuple[str, int]:
    """The first of a copy's files that makes the `inspectorServer.handle(` call,
    and its line, else the first file and line 1."""
    for rel in files:
        try:
            text = (project_root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = _INSPECTOR_CALL_RE.search(text)
        if m:
            return rel, text.count("\n", 0, m.start()) + 1
    return files[0], 1


def _copy_findings(
    project_root: Path, copies: dict[Path, list[str]], scanned: set[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for root, files in sorted(copies.items()):
        stated = _stated_version(root)
        root_rel = root.relative_to(project_root).as_posix()
        if stated is None:
            # Nothing dates the copy, so it is reported, on the call it makes if
            # it makes one: only an unversioned copy has its code read.
            rel, line = _call_site(project_root, sorted(files))
            scanned.add(rel)
            findings.append(make_finding(
                "AAK-MCP-INSPECTOR-CVE-2026-23744-001",
                rel,
                f"Vendored mcpjam-inspector fork at {root_rel}/, with no package.json "
                f"naming {_PACKAGE} at a version — CVE-2026-23744 (CVSS 9.8) "
                "affects 1.4.2 and earlier.",
                line_number=line,
            ))
            continue
        version, written, line = stated
        manifest_rel = f"{root_rel}/package.json"
        scanned.add(manifest_rel)
        if version >= _FIXED_IN:
            continue
        findings.append(make_finding(
            "AAK-MCP-INSPECTOR-CVE-2026-23744-001",
            manifest_rel,
            f"{_PACKAGE} {written} at {root_rel}/ — CVE-2026-23744 (CVSS 9.8) "
            "affects 1.4.2 and earlier; fixed in 1.4.3.",
            line_number=line,
        ))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    copies: dict[Path, list[str]] = {}   # copy root -> its code files
    skipped_roots: set[Path] = set()
    for path in project_root.rglob("*"):
        if path.suffix not in _TARGET_EXTS or not path.is_file():
            continue
        rel_path = path.relative_to(project_root)
        depth = _copy_root(rel_path.parts)
        if depth is not None:
            root = project_root.joinpath(*rel_path.parts[:depth])
            if root in skipped_roots:
                continue
            if root not in copies and in_skip_dir(root, project_root, _INSPECTOR_SKIP_DIRS):
                skipped_roots.add(root)
                continue
            copies.setdefault(root, []).append(rel_path.as_posix())
            continue
        if in_skip_dir(path, project_root, _INSPECTOR_SKIP_DIRS):
            continue
        rel = str(rel_path)
        try:
            text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
        except OSError:
            continue
        # Outside a copy only the call shape counts. A file whose own name holds
        # `mcpjam-inspector` was reported for the name alone, at CRITICAL.
        call_m = _INSPECTOR_CALL_RE.search(text)
        if not call_m:
            continue
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-MCP-INSPECTOR-CVE-2026-23744-001",
            rel,
            "inspectorServer.handle(...) call shape from MCPJam "
            "Inspector — CVE-2026-23744 vulnerable code path.",
            line_number=text.count("\n", 0, call_m.start()) + 1,
        ))
    findings.extend(_copy_findings(project_root, copies, scanned))
    return findings, scanned
