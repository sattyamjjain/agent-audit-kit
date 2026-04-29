"""score_finding() — emit an AIVSS v0.8 score from rule metadata.

Inputs:
    rule_meta:   AAK RuleDefinition (or any object with .severity,
                 .cve_references, .owasp_agentic_references).
    runtime_ctx: Optional dict with AARS overrides
                 (has_tool_use, internet_egress, persistent_memory,
                  human_in_loop) and environmental overrides.

Output:
    `AIVSSScore` (v0.8) with:
        base_score   from severity
        aars         seeded by per-rule defaults; runtime_ctx overrides
        environmental seeded by runtime_ctx, defaults otherwise
        threat       inferred from CVE references + flag in defaults
        exploit      from defaults
        final_score  base_score * AARS.multiplier(), clamped 0..10
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Severity

from .aivss_schema import (
    AARSVector,
    AIVSSScore,
    EnvironmentalVector,
    ExploitAvailability,
    ThreatVector,
)


_SEVERITY_BASE: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 3.5,
    Severity.INFO: 1.0,
}

_DEFAULTS_PATH = Path(__file__).resolve().parent.parent / "data" / "aivss-v08-defaults.json"


def _load_defaults() -> dict[str, Any]:
    try:
        text = _DEFAULTS_PATH.read_text(encoding="utf-8")
    except OSError:
        return {"_default": {}, "rules": {}}
    return json.loads(text)


_DEFAULTS_CACHE: dict[str, Any] | None = None


def _defaults_for(rule_id: str) -> dict[str, Any]:
    global _DEFAULTS_CACHE
    if _DEFAULTS_CACHE is None:
        _DEFAULTS_CACHE = _load_defaults()
    rules = _DEFAULTS_CACHE.get("rules", {}) or {}
    base = dict(_DEFAULTS_CACHE.get("_default", {}) or {})
    base.update(rules.get(rule_id, {}) or {})
    return base


def score_finding(rule_meta: Any, runtime_ctx: dict[str, Any] | None = None) -> AIVSSScore:
    """Compute an AIVSS v0.8 score for a single AAK Finding / RuleDefinition.

    `rule_meta` must expose `.rule_id`, `.severity`, `.cve_references`.
    """
    rule_id = getattr(rule_meta, "rule_id", "")
    severity = getattr(rule_meta, "severity", Severity.INFO)
    cve_refs = list(getattr(rule_meta, "cve_references", []) or [])

    base = _SEVERITY_BASE.get(severity, 1.0)
    defaults = _defaults_for(rule_id)
    rt = runtime_ctx or {}

    aars_data = {**(defaults.get("aars", {}) or {}), **(rt.get("aars", {}) or {})}
    aars = AARSVector(
        has_tool_use=bool(aars_data.get("has_tool_use", False)),
        internet_egress=bool(aars_data.get("internet_egress", False)),
        persistent_memory=bool(aars_data.get("persistent_memory", False)),
        human_in_loop=bool(aars_data.get("human_in_loop", False)),
    )

    env_data = {**(defaults.get("environmental", {}) or {}), **(rt.get("environmental", {}) or {})}
    env = EnvironmentalVector(
        network_exposure=env_data.get("network_exposure", "internal"),
        data_sensitivity=env_data.get("data_sensitivity", "internal"),
        blast_radius=env_data.get("blast_radius", "host"),
    )

    threat_defaults = defaults.get("threat", {}) or {}
    threat = ThreatVector(
        poc_public=bool(threat_defaults.get("poc_public", bool(cve_refs))),
        weaponized=bool(threat_defaults.get("weaponized", False)),
        in_the_wild=bool(threat_defaults.get("in_the_wild", False)),
    )

    exploit_defaults = defaults.get("exploit", {}) or {}
    exploit = ExploitAvailability(
        patch_available=bool(exploit_defaults.get("patch_available", False)),
        patch_version=exploit_defaults.get("patch_version"),
        workaround_available=bool(exploit_defaults.get("workaround_available", False)),
    )

    final = max(0.0, min(10.0, round(base * aars.multiplier(), 2)))
    return AIVSSScore(
        aivss_version="0.8",
        base_score=base,
        aars=aars,
        environmental=env,
        threat=threat,
        exploit=exploit,
        final_score=final,
    )


def annotate_sarif(sarif: dict[str, Any], rule_lookup: Any) -> dict[str, Any]:
    """Walk a SARIF document and add AIVSS v0.8 properties to each result.

    `rule_lookup(rule_id)` should return a RuleDefinition-shaped object;
    on KeyError the result is left unscored and counted as a skipped
    annotation (logged via stderr from the CLI).
    """
    runs = sarif.get("runs", []) or []
    for run in runs:
        for result in run.get("results", []) or []:
            rid = result.get("ruleId") or ""
            try:
                rule_def = rule_lookup(rid)
            except KeyError:
                continue
            score = score_finding(rule_def, runtime_ctx=result.get("properties", {}).get("runtime_context"))
            result.setdefault("properties", {})["aivss_score"] = score.to_dict()
    return sarif


__all__ = ["annotate_sarif", "score_finding"]
