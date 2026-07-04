from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from agent_audit_kit.models import Category, Finding, ScanResult, Severity
from agent_audit_kit.rules.builtin import all_rule_ids, get_rule


ScanFn = Callable[..., tuple[list[Finding], set[str]]]


class ScannerLoadError(RuntimeError):
    """Raised when strict_loading is enabled and a scanner fails to import."""


@dataclass
class ScannerRegistration:
    name: str
    scan_fn: ScanFn
    kwargs_keys: list[str] = field(default_factory=list)


_OPTIONAL_SCANNERS: list[tuple[str, str, list[str]]] = [
    ("agent_config", "Agent config", []),
    ("tool_poisoning", "Tool poisoning", []),
    ("taint_analysis", "Taint analysis", []),
    ("transport_security", "Transport security", []),
    ("a2a_protocol", "A2A protocol", []),
    ("legal_compliance", "Legal compliance", []),
    ("typescript_pattern_scan", "TypeScript pattern scan", []),
    ("rust_pattern_scan", "Rust pattern scan", []),
    ("pin_drift", "Pin drift", []),
    ("marketplace_manifest", "Marketplace manifest", []),
    ("skill_poisoning", "Skill poisoning", []),
    ("mcp_auth_patterns", "MCP auth patterns", []),
    ("ssrf_patterns", "SSRF patterns", []),
    ("oauth_misconfig", "OAuth 2.1 misconfig", []),
    ("hook_rce", "Hook RCE", []),
    ("langchain_vuln", "LangChain vulnerabilities", []),
    ("routines", "Claude Code routines", []),
    ("mcp_tasks", "MCP Tasks leakage", []),
    ("india_pii", "India PII", []),
    ("healthcare_ai", "Healthcare AI legal triggers", []),
    ("state_privacy", "US state consumer privacy", []),
    ("stdio_injection", "Ox MCP STDIO command-injection", []),
    ("neo4j_cve", "mcp-neo4j-cypher CVE-2026-35402", []),
    ("log_injection", "MCP tool log-injection (CVE-2026-6494)", []),
    ("mcp_middleware", "MCPwn twin-route middleware asymmetry (CVE-2026-33032)", []),
    ("oauth_surface", "Third-party OAuth surface (VERCEL-2026-04-19)", []),
    ("transport_limits", "Transport body-size limits (CVE-2026-39313)", []),
    ("mcp_sdk_hardening", "Upstream MCP SDK STDIO hardening (OX-MCP-2026-04-15)", []),
    ("dns_rebind", "MCP SDK DNS-rebinding (CVE-2025-66414/66416, CVE-2026-35568/35577)", []),
    ("gha_hardening", "GitHub Actions SHA-pin / Immutable Action policy", []),
    ("log_token_leak", "Token-shaped values in log sinks (CVE-2026-20205)", []),
    ("ssrf_redirect", "SSRF: validate-then-fetch with redirects (CVE-2026-41481)", []),
    ("ssrf_toctou", "SSRF: validate-then-fetch DNS-rebind / TOCTOU (CVE-2026-41488)", []),
    ("toxic_flow", "Toxic-flow source/sink pair scoring", []),
    ("mcp_stdio_params", "MCP StdioServerParameters config-to-spawn taint (OX-MCP-2026-04-25)", []),
    ("mcp_marketplace_fetch", "MCP marketplace-fetch → StdioServerParameters", []),
    ("mcp_server_auth", "MCP server-author missing auth (Azure MCP, CVE-2026-32211)", []),
    ("splunk_mcp_config", "splunk-mcp-server config-side token-leak (CVE-2026-20205)", []),
    ("prtitle_ipi", "PR-title indirect prompt injection (Comment-and-Control 2026-04-25)", []),
    ("mcp_fhi", "MCP function-hijacking adversarial tool descriptions (arXiv 2604.20994)", []),
    ("mcp_atlassian", "Atlassian MCP RCE chain (CVE-2026-27825/27826)", []),
    ("ipi_wild_corpus", "Wild IPI payload corpus (2026-04-24)", []),
    ("mcp_inspector_cve", "MCPJam Inspector vendored fork (CVE-2026-23744)", []),
    ("project_deal_drift", "Project Deal economic-drift (Anthropic 2026-04-26)", []),
    ("langgraph_toolnode", "LangGraph ToolNode positional-list regression (1.0.11)", []),
    ("deepseek_v4_tool_injection", "DeepSeek V4 MoE-routed tool injection", []),
    ("social_agent_hijack", "Social-agent auto-reply hijack (BHASIA 2026)", []),
    ("crewai_rce_chain", "CrewAI four-CVE chain (CERT/CC VU#221883)", []),
    ("langchain_prompt_loader", "LangChain load_prompt path traversal (CVE-2026-34070)", []),
    ("openclaw_privesc", "OpenClaw missing-role privesc (provisional)", []),
    ("docsgpt_transport_flip", "DocsGPT MCP transport-flip MITM (OX-MCP-2026-05-01)", []),
    ("gpt_researcher_transport_flip", "GPT-Researcher MCP transport-flip MITM (OX-MCP-2026-05-01)", []),
    ("mcp_tool_unsafe_eval", "Unsafe eval/exec inside @mcp.tool handler (CVE-2026-44717 class)", []),
    ("openapi_smells", "OpenAPI smells for MCP-on-REST (Hermes paper, arXiv:2605.14312)", []),
    ("metis_pomdp", "Metis POMDP closed-loop reasoning defense (arXiv:2605.10067)", []),
    ("stainless_lineage", "Stainless-generator provenance (Anthropic acquisition 2026-05-18)", []),
    ("skill_lifecycle_attribution", "Skill lifecycle outcome-attribution (SkillsVote, arXiv:2605.18401)", []),
    ("agent_harness_shared_state", "Multi-agent shared-state lock (Code-as-Harness, arXiv:2605.18747)", []),
    ("mcp_sampling_capability", "MCP `sampling` capability consent guard (MCP07:2025)", []),
    ("mcp_stateless_migration", "MCP 2026-07-28 stateless-migration smells (SEP-1442/1359)", []),
    ("eu_ai_act_art15_locale", "EU AI Act Art. 15 multilingual-eval coverage (advisory)", []),
    ("mcp_tunnel", "MCP Tunnels gateway config + credential exposure (Anthropic 2026-05-19 research preview)", []),
    ("sandbox_self_disable", "Tool-schema sandbox self-disable parameter (CVE-2026-42074)", []),
    ("shared_resource_authz", "Shared/multi-agent resource missing per-actor authz (CVE-2026-44654)", []),
    ("mcp_stdio_launcher", "MCP stdio launcher-injection config (CVE-2026-40933)", []),
    ("mcp_toolgate_asymmetry", "MCP tool-gate list-vs-call enforcement asymmetry (CVE-2026-46519)", []),
    ("mcp_env_placeholder_exfil", "MCP ${VAR} env-placeholder secret exfiltration (CVE-2026-32625)", []),
    ("mcp_http_noauth_server", "Unauthenticated MCP HTTP/SSE server on 0.0.0.0 / wildcard CORS", []),
    ("llm_sql_rce", "LLM-generated SQL on an RCE-capable DB role (CVE-2026-25879)", []),
    ("skill_untrusted_exec_path", "Untrusted-search-path exec override in skill/install flow (CVE-2026-53819)", []),
    ("argv_toctou", "Argv rebuilt after allowlist approval before spawn (CVE-2026-53822)", []),
    ("mcp_noauth_default", "MCP server unauthenticated-by-default / fail-open auth (CVE-2026-48814)", []),
    ("mcp_auth_pathtraversal", "MCP bearer-token joined into session file path (CVE-2026-52830)", []),
]


def _build_registry(strict_loading: bool = False) -> list[ScannerRegistration]:
    from agent_audit_kit.scanners import (
        mcp_config,
        hook_injection,
        trust_boundary,
        secret_exposure,
        supply_chain,
    )
    regs = [
        ScannerRegistration("MCP configuration", mcp_config.scan, ["include_user_config"]),
        ScannerRegistration("Hook injection", hook_injection.scan, ["include_user_config"]),
        ScannerRegistration("Trust boundary", trust_boundary.scan, ["include_user_config"]),
        ScannerRegistration("Secret exposure", secret_exposure.scan, ["ignore_paths"]),
        ScannerRegistration("Supply chain", supply_chain.scan, []),
    ]
    for module_name, display_name, kwargs in _OPTIONAL_SCANNERS:
        try:
            module = __import__(
                f"agent_audit_kit.scanners.{module_name}",
                fromlist=["scan"],
            )
        except ImportError as exc:
            if strict_loading:
                raise ScannerLoadError(
                    f"Scanner '{module_name}' failed to import: {exc}"
                ) from exc
            continue
        regs.append(ScannerRegistration(display_name, module.scan, kwargs))
    return regs


def reset_registry() -> None:
    """Clear the cached scanner registry (for tests that toggle strict_loading)."""
    global _REGISTRY
    _REGISTRY = None


_REGISTRY: list[ScannerRegistration] | None = None


def _get_registry(strict_loading: bool = False) -> list[ScannerRegistration]:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = _build_registry(strict_loading=strict_loading)
    return _REGISTRY


def _scanner_fail_finding(scanner_name: str, exc: BaseException) -> Finding:
    """Build an INFO finding marking that a scanner crashed."""
    rule = get_rule("AAK-INTERNAL-SCANNER-FAIL")
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        description=rule.description,
        severity=Severity.INFO,
        category=Category.AGENT_CONFIG,
        file_path="<scanner>",
        line_number=None,
        evidence=f"scanner={scanner_name!r} error={type(exc).__name__}: {exc}",
        remediation=rule.remediation,
    )


def run_scan(
    project_root: Path,
    include_user_config: bool = False,
    ignore_paths: list[str] | None = None,
    rules: list[str] | None = None,
    exclude_rules: list[str] | None = None,
    verbose_callback: Callable[[str], None] | None = None,
    strict_loading: bool = False,
) -> ScanResult:
    start = time.monotonic()
    result = ScanResult()

    def _log(msg: str) -> None:
        if verbose_callback:
            verbose_callback(msg)

    active_rules = set(rules) if rules else set(all_rule_ids())
    if exclude_rules:
        active_rules -= set(exclude_rules)
    result.rules_evaluated = len(active_rules)

    all_scanned_files: set[str] = set()
    all_findings: list[Finding] = []

    kwargs_map: dict[str, Any] = {
        "include_user_config": include_user_config,
        "ignore_paths": ignore_paths,
    }

    for reg in _get_registry(strict_loading=strict_loading):
        _log(f"Scanning {reg.name}...")
        scanner_kwargs: dict[str, Any] = {"project_root": project_root}
        for key in reg.kwargs_keys:
            if key in kwargs_map:
                scanner_kwargs[key] = kwargs_map[key]
        try:
            findings, files = reg.scan_fn(**scanner_kwargs)
        except Exception as exc:  # noqa: BLE001 — intentional broad catch; see docstring
            _log(f"  {reg.name}: CRASHED ({type(exc).__name__}: {exc})")
            _log(traceback.format_exc())
            all_findings.append(_scanner_fail_finding(reg.name, exc))
            continue
        all_findings.extend(findings)
        all_scanned_files.update(files)
        _log(f"  {reg.name}: {len(files)} files, {len(findings)} findings")

    # Apply global ignore_paths filter. Historically ignore_paths was
    # threaded only into secret_exposure (the only scanner that took
    # the kwarg); other scanners surfaced findings from explicitly
    # excluded directories. Centralising here means every scanner
    # honours the flag without each one re-implementing the path check.
    ignore_path_prefixes = tuple(p.rstrip("/") for p in (ignore_paths or []) if p)

    def _is_ignored(file_path: str) -> bool:
        if not ignore_path_prefixes:
            return False
        # Normalise leading "./" so callers can pass either form.
        normalised = file_path[2:] if file_path.startswith("./") else file_path
        return any(
            normalised == prefix or normalised.startswith(prefix + "/")
            for prefix in ignore_path_prefixes
        )

    for finding in all_findings:
        if finding.rule_id not in active_rules and finding.rule_id != "AAK-INTERNAL-SCANNER-FAIL":
            continue
        if _is_ignored(finding.file_path or ""):
            continue
        result.findings.append(finding)

    result.files_scanned = len(all_scanned_files)
    result.scan_duration_ms = (time.monotonic() - start) * 1000
    _log(f"Scan complete: {result.files_scanned} files, {len(result.findings)} findings in {result.scan_duration_ms:.0f}ms")

    return result
