"""AAK-MCP-SAMPLING-001 — MCP `sampling` capability without consent guard.

MCP servers can request LLM completions back through the connected client
via the `sampling/createMessage` request (MCP 2025-06-18 §6.3). That makes
the server a privileged caller of the host's LLM — and any output it
receives must be treated as untrusted tool input. The 2025-03-26 spec
revision added the `elicitation/create` consent flow specifically to gate
sampling requests.

This scanner fires when ALL hold:

1. A dependency manifest declares an MCP SDK (Python / TS / Rust / Java).
2. A repo file participates in the sampling capability — either declaring
   `capabilities.sampling`, calling `sampling/createMessage` /
   `create_message`, or implementing a CreateMessage request handler.
3. No consent / elicitation guard is found anywhere in the repo —
   `elicitation/create`, `elicit_*`, `ElicitRequestSchema`,
   `requires_consent`, `human_in_the_loop`, `confirmSampling`, etc.
4. `.agent-audit-kit.yml` does NOT carry
   `accepts_sampling_risk: true` plus a non-empty `justification:`.

Also fires when an MCP config file (`.mcp.json` family) explicitly lists
`"sampling"` in a per-server `capabilities` block without a sibling
consent / `requires_consent` flag — captures host-side allow-lists.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, find_line_number, make_finding

_PY_SDK_NAMES = (
    "mcp",
    "modelcontextprotocol",
    "model-context-protocol",
)
_TS_SDK_NAMES = (
    "@modelcontextprotocol/sdk",
    "@anthropic-ai/mcp",
    "@anthropic-ai/claude-agent-sdk",
)
_JAVA_SDK_TOKEN = "io.modelcontextprotocol"
_RUST_SDK_TOKENS = ("mcp", "modelcontextprotocol")

_LANG_EXTS = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".java", ".kt", ".rs")

# Markers that prove the repo participates in MCP sampling. Each pattern is
# scoped tightly enough that bare prose mentioning "sampling" won't fire.
_SAMPLING_MARKERS = (
    # Server / client capability declarations.
    re.compile(r"capabilities\s*[:=]\s*\{[^}]*sampling\s*[:=]"),
    re.compile(r"ServerCapabilities\s*\([^)]*sampling\s*="),
    re.compile(r"SamplingCapability\s*\("),
    # Request schemas — server-side handler installation.
    re.compile(r"CreateMessageRequestSchema"),
    re.compile(r"\bsampling/createMessage\b"),
    re.compile(r"\bcreate_message\s*\("),
    # SDK method aliases.
    re.compile(r"\.sampling\.create\s*\("),
    re.compile(r"\bRequestSampling\b"),
)

# Markers that prove a consent / elicitation gate is wired up somewhere in
# the same repo. Any one of these suppresses the finding — they cover the
# protocol-level `elicitation/create` flow, project-level wrappers, and
# the human-in-the-loop callbacks commonly used by hosts.
_CONSENT_MARKERS = (
    re.compile(r"\belicitation/create\b"),
    re.compile(r"\bElicitRequestSchema\b"),
    re.compile(r"\belicit(?:_create|_input|ation)?\s*\("),
    re.compile(r"\bElicitInput\b"),
    re.compile(r"\b(?:requires?_consent|require_consent|user_consent)\b"),
    re.compile(r"\bhuman[_-]?in[_-]?the[_-]?loop\b", re.IGNORECASE),
    re.compile(r"\b(?:confirm|approve)Sampling\b"),
    re.compile(r"\bsamplingConsent\b"),
    re.compile(r"\bhuman_approval\b"),
)

# Config-file location for explicit per-server sampling allow-listing.
_MCP_CONFIG_FILES = (
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".amazonq/mcp.json",
    ".windsurf/mcp.json",
    ".continue/config.json",
    ".roo/mcp.json",
    ".kiro/mcp.json",
    "mcp.json",
)


def _declares_sdk(project_root: Path) -> tuple[bool, list[str]]:
    """Returns (any_sdk_declared, list_of_manifest_relpaths). Mirrors the
    helper in `mcp_sdk_hardening.py`."""
    manifests: list[str] = []
    declared = False

    pyproject = project_root / "pyproject.toml"
    if pyproject.is_file():
        try:
            text = pyproject.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if any(f'"{n}"' in text or f"'{n}'" in text for n in _PY_SDK_NAMES):
            declared = True
            manifests.append("pyproject.toml")

    for req in project_root.glob("requirements*.txt"):
        try:
            text = req.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            name = (
                line.split("#", 1)[0].strip().split("[")[0]
                .split("=")[0].split(">")[0].split("<")[0].strip()
            )
            if name in _PY_SDK_NAMES:
                declared = True
                manifests.append(str(req.relative_to(project_root)))
                break

    pkg = project_root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            data = {}
        if isinstance(data, dict):
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                deps = data.get(section) or {}
                if isinstance(deps, dict) and any(n in deps for n in _TS_SDK_NAMES):
                    declared = True
                    manifests.append("package.json")
                    break

    for maven in ("pom.xml", "build.gradle", "build.gradle.kts"):
        p = project_root / maven
        if p.is_file():
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _JAVA_SDK_TOKEN in text:
                declared = True
                manifests.append(maven)

    cargo = project_root / "Cargo.toml"
    if cargo.is_file():
        try:
            text = cargo.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for tok in _RUST_SDK_TOKENS:
            if re.search(rf"^\s*{re.escape(tok)}\s*=", text, re.MULTILINE):
                declared = True
                manifests.append("Cargo.toml")
                break

    return declared, manifests


def _sampling_hits(project_root: Path) -> list[tuple[Path, int]]:
    """Return (path, line_number) for every file/match that proves sampling
    participation. Tight regex set keeps prose mentions from firing."""
    hits: list[tuple[Path, int]] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _LANG_EXTS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pat in _SAMPLING_MARKERS:
            m = pat.search(text)
            if m:
                # Approximate line number from the match offset.
                line_no = text.count("\n", 0, m.start()) + 1
                hits.append((path, line_no))
                break
    return hits


def _has_consent_marker(project_root: Path) -> bool:
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _LANG_EXTS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(p.search(text) for p in _CONSENT_MARKERS):
            return True
    return False


def _accepts_risk(project_root: Path) -> bool:
    cfg = project_root / ".agent-audit-kit.yml"
    if not cfg.is_file():
        return False
    try:
        data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return False
    if not isinstance(data, dict):
        return False
    if data.get("accepts_sampling_risk") is not True:
        return False
    justification = data.get("justification")
    return isinstance(justification, str) and justification.strip() != ""


def _config_sampling_findings(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Detect explicit per-server `"sampling"` declarations in MCP config
    files without a sibling `requires_consent` / `consent` flag."""
    findings: list[Finding] = []
    scanned: set[str] = set()
    for name in _MCP_CONFIG_FILES:
        path = project_root / name
        if not path.is_file():
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        servers = data.get("mcpServers")
        if not isinstance(servers, dict):
            continue
        for server_name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            caps = cfg.get("capabilities")
            declares_sampling = False
            if isinstance(caps, list) and "sampling" in caps:
                declares_sampling = True
            elif isinstance(caps, dict) and "sampling" in caps:
                declares_sampling = True
            if not declares_sampling:
                continue
            requires_consent = (
                cfg.get("requires_consent") is True
                or cfg.get("requiresConsent") is True
                or cfg.get("consent") is True
                or cfg.get("human_in_the_loop") is True
            )
            if requires_consent:
                continue
            rel = str(path.relative_to(project_root))
            scanned.add(rel)
            findings.append(make_finding(
                "AAK-MCP-SAMPLING-001",
                rel,
                f"Server '{server_name}' declares the `sampling` capability "
                "with no `requires_consent` / `human_in_the_loop` flag.",
                find_line_number(raw, "sampling"),
            ))
    return findings, scanned


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []

    # 1) Per-server config-side allow-listing — independent of SDK use.
    cfg_findings, cfg_scanned = _config_sampling_findings(project_root)
    findings.extend(cfg_findings)
    scanned.update(cfg_scanned)

    # 2) Source-side participation: only fires when an SDK is declared.
    declared, manifests = _declares_sdk(project_root)
    if not declared:
        return findings, scanned
    for m in manifests:
        scanned.add(m)

    hits = _sampling_hits(project_root)
    if not hits:
        return findings, scanned

    if _accepts_risk(project_root):
        scanned.add(".agent-audit-kit.yml")
        return findings, scanned

    if _has_consent_marker(project_root):
        return findings, scanned

    for path, line_no in hits:
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-MCP-SAMPLING-001",
            rel,
            "MCP `sampling` capability is wired up but no elicitation / "
            "consent gate is present in the repo.",
            line_no,
        ))
    return findings, scanned
