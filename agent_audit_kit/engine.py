from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from agent_audit_kit.models import Finding, ScanResult
from agent_audit_kit.rules.builtin import all_rule_ids


ScanFn = Callable[..., tuple[list[Finding], set[str]]]


@dataclass
class ScannerRegistration:
    name: str
    scan_fn: ScanFn
    kwargs_keys: list[str] = field(default_factory=list)


_REGISTRY: list[ScannerRegistration] | None = None


def _build_registry() -> list[ScannerRegistration]:
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
    # Lazy-import new scanners (available in v0.2+)
    try:
        from agent_audit_kit.scanners import agent_config
        regs.append(ScannerRegistration("Agent config", agent_config.scan, []))
    except ImportError:
        pass
    try:
        from agent_audit_kit.scanners import tool_poisoning
        regs.append(ScannerRegistration("Tool poisoning", tool_poisoning.scan, []))
    except ImportError:
        pass
    try:
        from agent_audit_kit.scanners import taint_analysis
        regs.append(ScannerRegistration("Taint analysis", taint_analysis.scan, []))
    except ImportError:
        pass
    try:
        from agent_audit_kit.scanners import transport_security
        regs.append(ScannerRegistration("Transport security", transport_security.scan, []))
    except ImportError:
        pass
    try:
        from agent_audit_kit.scanners import a2a_protocol
        regs.append(ScannerRegistration("A2A protocol", a2a_protocol.scan, []))
    except ImportError:
        pass
    try:
        from agent_audit_kit.scanners import legal_compliance
        regs.append(ScannerRegistration("Legal compliance", legal_compliance.scan, []))
    except ImportError:
        pass
    try:
        from agent_audit_kit.scanners import typescript_scan
        regs.append(ScannerRegistration("TypeScript taint analysis", typescript_scan.scan, []))
    except ImportError:
        pass
    try:
        from agent_audit_kit.scanners import rust_scan
        regs.append(ScannerRegistration("Rust taint analysis", rust_scan.scan, []))
    except ImportError:
        pass
    return regs


def _get_registry() -> list[ScannerRegistration]:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = _build_registry()
    return _REGISTRY


def run_scan(
    project_root: Path,
    include_user_config: bool = False,
    ignore_paths: list[str] | None = None,
    rules: list[str] | None = None,
    exclude_rules: list[str] | None = None,
    verbose_callback: Callable[[str], None] | None = None,
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

    for reg in _get_registry():
        _log(f"Scanning {reg.name}...")
        scanner_kwargs: dict[str, Any] = {"project_root": project_root}
        for key in reg.kwargs_keys:
            if key in kwargs_map:
                scanner_kwargs[key] = kwargs_map[key]
        findings, files = reg.scan_fn(**scanner_kwargs)
        all_findings.extend(findings)
        all_scanned_files.update(files)
        _log(f"  {reg.name}: {len(files)} files, {len(findings)} findings")

    for finding in all_findings:
        if finding.rule_id in active_rules:
            result.findings.append(finding)

    result.files_scanned = len(all_scanned_files)
    result.scan_duration_ms = (time.monotonic() - start) * 1000
    _log(f"Scan complete: {result.files_scanned} files, {len(result.findings)} findings in {result.scan_duration_ms:.0f}ms")

    return result
