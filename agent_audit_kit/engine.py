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

    for finding in all_findings:
        if finding.rule_id in active_rules or finding.rule_id == "AAK-INTERNAL-SCANNER-FAIL":
            result.findings.append(finding)

    result.files_scanned = len(all_scanned_files)
    result.scan_duration_ms = (time.monotonic() - start) * 1000
    _log(f"Scan complete: {result.files_scanned} files, {len(result.findings)} findings in {result.scan_duration_ms:.0f}ms")

    return result
