"""DocsGPT MCP transport-flip resistance detector (closes A1 from
2026-05-05 daily prompt; OX MCP 2026-05-01 disclosure).

The OX/BackBox 2026-05-01 disclosure traced a class of MCP-server
exploits to a single shape: server configs that advertise a safe
transport (e.g. `transport: "sse"` or HTTPS-only) but accept a
post-handshake `transport=stdio` override from MITM-edited JSON
payloads. Once stdio is reached, the architectural class
`AAK-MCP-STDIO-CMD-INJ-001..004` + `AAK-STDIO-001` already fire on
the receiver shape — but only if the transport flip is allowed in
the first place.

This scanner detects the *config-side* gap: an MCP server config
file declaring an SSE/HTTP/HTTPS transport without an explicit
allow-list / reject-stdio guard. Fires for any DocsGPT-flavoured
config (the OX writeup names DocsGPT, GPT-Researcher, Agent-Zero,
LettaAI; this scanner only fires on DocsGPT-named configs today —
the other three are covered in v0.3.15+ per the
docs/roadmap/ox-mcp-2026-05-01-batch.md plan).

Detector contract:
    scan(project_root) -> (list[Finding], set[str])
matches the standard `agent_audit_kit.scanners.*.scan` shape.
"""
from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Category, Finding, Severity


_DOCSGPT_HINT_RE = re.compile(
    r"docsgpt|arc53/DocsGPT",
    re.IGNORECASE,
)
# Configs that advertise SSE / HTTP / HTTPS transport.
_TRANSPORT_SAFE_RE = re.compile(
    r'"transport"\s*:\s*"(?:sse|http|https|streamable-http)"',
    re.IGNORECASE,
)
# Explicit reject-stdio / allow-list pattern: the server-author has
# whitelisted transports or rejected stdio. Either of these short-
# circuits the finding.
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
# An override = the config explicitly enumerates `stdio` alongside SSE
# *or* the field is absent from a doc that doesn't lock it down.
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
    """Find DocsGPT-named MCP config files."""
    out: list[Path] = []
    for name in (
        ".mcp.json",
        ".cursor/mcp.json",
        ".vscode/mcp.json",
        "mcp.json",
        "docsgpt.config.json",
        "docsgpt-mcp.json",
        ".docsgpt/config.json",
        ".docsgpt/mcp.json",
    ):
        p = project_root / name
        if p.is_file():
            out.append(p)
    # Also walk a top-level configs/ dir if present, capped to 50 entries.
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
    """Detect DocsGPT MCP configs that allow transport-flip MITM.

    Returns (findings, scanned_files) per the standard scanner contract.
    """
    findings: list[Finding] = []
    scanned: set[str] = set()

    for path in _config_candidates(project_root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _DOCSGPT_HINT_RE.search(text):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)

        # Only fire when the config advertises a non-stdio transport but
        # also permits stdio override. Configs that explicitly reject
        # stdio override are silently passed.
        has_safe_transport = _TRANSPORT_SAFE_RE.search(text) is not None
        explicitly_rejects = _TRANSPORT_REJECTS_STDIO_RE.search(text) is not None
        permits_override = _TRANSPORT_PERMITS_STDIO_RE.search(text) is not None
        if not has_safe_transport:
            continue
        if explicitly_rejects:
            continue
        if not permits_override:
            # Safe transport declared and no override field — neutral.
            # We could fire on missing reject directive, but that would
            # generate false positives in well-formed minimal configs.
            continue

        findings.append(Finding(
            rule_id="AAK-DOCSGPT-MCP-STDIO-MITM-001",
            title="DocsGPT MCP config permits transport-flip to stdio (OX 2026-05-01)",
            description=(
                "DocsGPT MCP server config declares an SSE/HTTP transport "
                "but also permits a post-handshake `transport=stdio` "
                "override. The OX/BackBox 2026-05-01 disclosure showed "
                "this enables a MITM to flip the transport mid-session "
                "and reach the architectural shape AAK-MCP-STDIO-CMD-INJ-* "
                "covers. Add an explicit reject-stdio guard."
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
                "Pin DocsGPT >=0.6.4 (OX MCP 2026-05-01 batch fix). See "
                "AAK-MCP-STDIO-CMD-INJ-001..004 + AAK-STDIO-001 for the "
                "receiver-side architectural class."
            ),
            cve_references=["CVE-2026-26015"],
            owasp_mcp_references=["MCP01:2025", "MCP05:2025"],
            owasp_agentic_references=["ASI02", "ASI10"],
            incident_references=["OX-MCP-2026-05-01"],
        ))

    return findings, scanned


__all__ = ["scan"]
