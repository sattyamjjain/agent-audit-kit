"""F4 — `aak rule lint`. Validates the RuleDefinition registry.

Invariants (v0.3.10 baseline; tighten over future releases):

    1. Every rule has a non-empty `remediation`.
    2. Every rule has a non-empty `description`.
    3. If the rule's title or description names a CVE
       (`CVE-NNNN-NNNNN`), `cve_references` must include that CVE.
    4. INFO-severity meta-rules (`AAK-*-COVERAGE-*`, `AAK-OX-*`) are
       exempt from CVE-presence checks.
    5. Every rule has at least one of `owasp_mcp_references`,
       `owasp_agentic_references`, `incident_references`, or
       `aicm_references` (so the rule maps to at least one external
       framework). INFO and INTERNAL rules exempt.

Lint is intentionally additive — running `aak rule lint --ci` on the
existing 188-rule registry must pass cleanly today. New invariants
land alongside their cleanup PR.
"""
from __future__ import annotations

import re
from typing import Any

from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


_EXEMPT_PREFIXES_FOR_CVE: tuple[str, ...] = (
    "AAK-OX-COVERAGE-",
    "AAK-PRISMA-AIRS-COVERAGE-",
    "AAK-INTERNAL-",
)


_EXEMPT_PREFIXES_FOR_FRAMEWORK: tuple[str, ...] = (
    "AAK-INTERNAL-",
)


def _violations_for(rule_id: str, rule: Any) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []

    remediation = (getattr(rule, "remediation", "") or "").strip()
    if not remediation:
        out.append({"rule_id": rule_id, "message": "missing remediation text"})

    description = (getattr(rule, "description", "") or "").strip()
    if not description:
        out.append({"rule_id": rule_id, "message": "missing description"})

    # CVE-presence invariant.
    if not rule_id.startswith(_EXEMPT_PREFIXES_FOR_CVE):
        named_cves = set(_CVE_RE.findall(description)) | set(
            _CVE_RE.findall(getattr(rule, "title", "") or "")
        )
        listed_cves = set(getattr(rule, "cve_references", []) or [])
        missing = named_cves - listed_cves
        if missing:
            out.append({
                "rule_id": rule_id,
                "message": (
                    "title/description names "
                    f"{sorted(missing)} but cve_references lacks them"
                ),
            })

    # External-framework invariant. LEGAL_COMPLIANCE rules cite
    # statutes in description text, not in our framework fields.
    if not rule_id.startswith(_EXEMPT_PREFIXES_FOR_FRAMEWORK):
        category = getattr(rule, "category", None)
        if (
            getattr(rule, "severity", Severity.INFO) != Severity.INFO
            and category != Category.LEGAL_COMPLIANCE
        ):
            has_any_external = any(
                getattr(rule, attr, None)
                for attr in (
                    "owasp_mcp_references",
                    "owasp_agentic_references",
                    "incident_references",
                    "aicm_references",
                    "cve_references",
                )
            )
            if not has_any_external:
                out.append({
                    "rule_id": rule_id,
                    "message": "no external-framework reference (CVE / OWASP / AICM / incident)",
                })

    return out


def run_lint(*, rule_filter: str | None = None) -> list[dict[str, str]]:
    """Run rule-lint over the registry, return list of violations."""
    out: list[dict[str, str]] = []
    for rid, rule in RULES.items():
        if rule_filter and rid != rule_filter:
            continue
        out.extend(_violations_for(rid, rule))
    return out


__all__ = ["run_lint"]
