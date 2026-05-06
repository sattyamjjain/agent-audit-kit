"""GPT-Researcher MCP transport-flip resistance detector.

Mirrors `agent_audit_kit/scanners/docsgpt_transport_flip.py` (v0.3.14)
shape against `gpt-researcher` / `assafelovic/gpt-researcher` named
configs. Phase 2 of the OX MCP 2026-05-01 batch (issue #159).

The umbrella generalization to a vendor-agnostic
`AAK-MCP-TRANSPORT-FLIP-001` ships in v0.3.16 (issue #162); until
then per-vendor scanners stay parallel.

Detector contract:
    scan(project_root) -> (list[Finding], set[str])
"""
from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Category, Finding, Severity


_GPT_RESEARCHER_HINT_RE = re.compile(
    r"gpt[-_]researcher|assafelovic/gpt-researcher",
    re.IGNORECASE,
)
_TRANSPORT_SAFE_RE = re.compile(
    r'"transport"\s*:\s*"(?:sse|http|https|streamable-http)"',
    re.IGNORECASE,
)
_TRANSPORT_REJECTS_STDIO_RE = re.compile(
    r"""(?ix)
    (?:
        "allowed_transports"\s*:\s*\[[^]]*"sse"
      | "deny_stdio_transport"\s*:\s*true
      | "reject_transport_override"\s*:\s*true
      | assert_transport_locked
    )
    """,
)
_TRANSPORT_PERMITS_STDIO_RE = re.compile(
    r"""(?ix)
    (?:
        "transports"\s*:\s*\[[^]]*"stdio"
      | "stdio_fallback"\s*:\s*true
      | "transport_override"\s*:\s*true
      | "permit_transport_override"\s*:\s*true
    )
    """,
)


def _config_candidates(project_root: Path) -> list[Path]:
    """Find GPT-Researcher-named MCP config files."""
    out: list[Path] = []
    for name in (
        ".mcp.json",
        ".cursor/mcp.json",
        ".vscode/mcp.json",
        "mcp.json",
        "gpt-researcher.config.json",
        "gpt_researcher.config.json",
        "gpt-researcher-mcp.json",
        ".gpt-researcher/config.json",
        ".gpt-researcher/mcp.json",
    ):
        p = project_root / name
        if p.is_file():
            out.append(p)
    cfg_dir = project_root / "configs"
    if cfg_dir.is_dir():
        for entry in list(cfg_dir.glob("*.json"))[:50]:
            if entry.is_file():
                out.append(entry)
    return out


def _line_number(text: str, needle_re: re.Pattern[str]) -> int | None:
    m = needle_re.search(text)
    if not m:
        return None
    return text.count("\n", 0, m.start()) + 1


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Detect GPT-Researcher MCP configs that allow transport-flip MITM."""
    findings: list[Finding] = []
    scanned: set[str] = set()

    for path in _config_candidates(project_root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _GPT_RESEARCHER_HINT_RE.search(text):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)

        has_safe_transport = _TRANSPORT_SAFE_RE.search(text) is not None
        explicitly_rejects = _TRANSPORT_REJECTS_STDIO_RE.search(text) is not None
        permits_override = _TRANSPORT_PERMITS_STDIO_RE.search(text) is not None
        if not has_safe_transport:
            continue
        if explicitly_rejects:
            continue
        if not permits_override:
            continue

        findings.append(Finding(
            rule_id="AAK-GPTRESEARCHER-MCP-STDIO-MITM-001",
            title="GPT-Researcher MCP config permits transport-flip to stdio (OX 2026-05-01)",
            description=(
                "GPT-Researcher MCP server config declares an SSE/HTTP "
                "transport but also permits a post-handshake "
                "`transport=stdio` override. The OX/BackBox 2026-05-01 "
                "disclosure showed this enables a MITM to flip the "
                "transport mid-session and reach the architectural shape "
                "AAK-MCP-STDIO-CMD-INJ-001 covers. Add an explicit "
                "reject-stdio guard."
            ),
            severity=Severity.HIGH,
            category=Category.SUPPLY_CHAIN,
            file_path=rel,
            line_number=_line_number(text, _TRANSPORT_PERMITS_STDIO_RE),
            evidence=(
                "transports/stdio_fallback/transport_override flag enabled "
                "alongside sse/http/https transport — MITM can flip to stdio."
            ),
            remediation=(
                "Set `\"deny_stdio_transport\": true` (or "
                "`\"allowed_transports\": [\"sse\"]`) in the same config. "
                "Pin gpt-researcher away from pre-disclosure versions when "
                "vendor ships a fix (track upstream "
                "https://github.com/assafelovic/gpt-researcher). See "
                "AAK-MCP-STDIO-CMD-INJ-001 + AAK-STDIO-001 for the "
                "receiver-side architectural class."
            ),
            cve_references=["CVE-2025-65720"],
            owasp_mcp_references=["MCP01:2025", "MCP05:2025"],
            owasp_agentic_references=["ASI02", "ASI10"],
            incident_references=["OX-MCP-2026-05-01"],
        ))

    return findings, scanned


__all__ = ["scan"]
