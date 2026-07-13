"""MCP/agent CVE version-pins — 2026-07 disclosure wave (table-driven).

Eight dependency version-pin rules for MCP/agent CVEs disclosed 2026-07-08..12
that have both a vendor-fixed version and a pinnable PyPI / npm artifact. Each
pin fires when a project references the affected package below its fix floor (or
unpinned) across dependency manifests, lockfiles, and MCP config files — the same
shape as the Kong / gateway-registry / Serena pins in `supply_chain`.

Packages + fix floors were verified against PyPI / npm before shipping:

  - litellm                        >= 1.84.0  (CVE-2026-59822, CVE-2026-59820)
  - cline                          >= 3.0.30  (CVE-2026-59723)
  - mcp-text-editor                >  1.0.2   (CVE-2026-15138; NVD "up to 1.0.2")
  - n8n                            >= 2.27.4  (CVE-2026-59207; also 2.28.1 line)
  - ruflo                          >= 3.16.3  (CVE-2026-59726)
  - @arikusi/deepseek-mcp-server   >= 1.8.0   (CVE-2026-55604, CVE-2026-55605)
  - mcp-server-kubernetes          >= 3.9.0   (CVE-2026-61459)
  - astrbot                        >  4.25.2  (CVE-2026-15501; NVD "up to 4.25.2")

CVEs without a pinnable PyPI/npm artifact (aerostack-mcp SSRF, MaxKB stdio
command-injection) or a tractable version scheme (langchain4j's four parallel
beta fix-lines) are handled outside this module — see CHANGELOG.cves.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS
from agent_audit_kit.scanners.supply_chain import _semver3

_Ver = tuple[int, int, int]


def _mk_re(name: str) -> re.Pattern[str]:
    """Match ``name`` optionally followed by a version, across requirements /
    pyproject / npm (``"name": "^1.2.3"``) / MCP-config forms."""
    return re.compile(
        re.escape(name)
        + r'\s*(?:==|>=|~=|<=|<|>|@|:|"\s*:\s*"[\^~><=v ]*|"?\s*version"?\s*[:=])?'
        r"\s*v?([0-9][\w.\-]*)?",
        re.IGNORECASE,
    )


@dataclass(frozen=True)
class _Pin:
    rule_id: str
    display: str
    names: tuple[str, ...]
    floor: _Ver | None          # None => presence-only (fire on any match)
    introduced: _Ver | None = None   # fire only if version >= introduced
    fix_label: str = ""
    regexes: tuple[re.Pattern[str], ...] = field(default=(), compare=False)

    def compiled(self) -> tuple[re.Pattern[str], ...]:
        return self.regexes or tuple(_mk_re(n) for n in self.names)


_PINS: tuple[_Pin, ...] = (
    _Pin("AAK-MCP-LITELLM-CVE-2026-59822-001", "litellm", ("litellm",), (1, 84, 0),
         fix_label="1.84.0"),
    _Pin("AAK-MCP-CLINE-CVE-2026-59723-001", "cline", ("cline",), (3, 0, 30),
         fix_label="3.0.30"),
    _Pin("AAK-MCP-TEXTEDITOR-CVE-2026-15138-001", "mcp-text-editor", ("mcp-text-editor",),
         (1, 0, 3), fix_label="1.0.3 (affected up to 1.0.2)"),
    _Pin("AAK-MCP-N8N-CVE-2026-59207-001", "n8n", ("n8n",), (2, 27, 4),
         fix_label="2.27.4 / 2.28.1"),
    _Pin("AAK-MCP-RUFLO-CVE-2026-59726-001", "ruflo", ("ruflo",), (3, 16, 3),
         fix_label="3.16.3"),
    _Pin("AAK-MCP-DEEPSEEK-CVE-2026-55604-001", "@arikusi/deepseek-mcp-server",
         ("@arikusi/deepseek-mcp-server",), (1, 8, 0), introduced=(1, 4, 2),
         fix_label="1.8.0"),
    _Pin("AAK-MCP-K8S-CVE-2026-61459-001", "mcp-server-kubernetes", ("mcp-server-kubernetes",),
         (3, 9, 0), fix_label="3.9.0"),
    _Pin("AAK-MCP-ASTRBOT-CVE-2026-15501-001", "astrbot", ("astrbot",), (4, 25, 3),
         fix_label="4.25.3 (affected up to 4.25.2)"),
)

_CANDIDATE_NAMES = (
    "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    ".mcp.json", "mcp.json", "claude_desktop_config.json",
)
_CANDIDATE_GLOBS = ("requirements*.txt", "*.mcp.yaml", "*.mcp.yml")
_MAX_FILE_BYTES = 2_000_000


def _fires(pin: _Pin, version: _Ver | None) -> bool:
    if pin.floor is None:
        return True
    if version is None:
        return True
    if version >= pin.floor:
        return False
    if pin.introduced is not None and version < pin.introduced:
        return False
    return True


def _candidate_files(project_root: Path) -> list[Path]:
    out: list[Path] = []
    seen: set[Path] = set()
    for name in _CANDIDATE_NAMES:
        p = project_root / name
        if p.is_file():
            out.append(p)
            seen.add(p)
    for pattern in _CANDIDATE_GLOBS:
        for p in project_root.rglob(pattern):
            if p.is_file() and p not in seen and not any(part in SKIP_DIRS for part in p.parts):
                out.append(p)
                seen.add(p)
    return out


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for the 2026-07 MCP/agent CVE dependency pins.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned: set[str] = set()

    for path in _candidate_files(project_root):
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(project_root))
        matched_here = False
        for pin in _PINS:
            for rx in pin.compiled():
                m = rx.search(text)
                if not m:
                    continue
                raw = m.group(1)
                version = _semver3(raw) if raw else None
                if _fires(pin, version):
                    shown = f"{raw!r}" if raw else "unpinned"
                    findings.append(make_finding(
                        pin.rule_id,
                        rel,
                        f"{pin.display} referenced at {shown} — fixed in "
                        f"{pin.fix_label}; pin the patched release.",
                    ))
                    matched_here = True
                break  # one finding per pin per file
        if matched_here:
            scanned.add(rel)

    return findings, scanned
