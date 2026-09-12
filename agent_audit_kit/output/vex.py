"""OpenVEX v0.2.0 emission for scanned MCP/agent projects.

Companion to `output.sbom`. The SBOM answers "what do you ship"; this answers
"and are you exploitable". Product identifiers are the *same* purls
`emit_cyclonedx` emits, so the two documents join on purl with no mapping
table -- both call `_discover_mcp_packages`.

Why this emitter never writes ``not_affected``
----------------------------------------------
OpenVEX permits four statuses. This emitter produces three. ``not_affected``
is refused on purpose, and the reason is structural rather than a gap to be
filled in later:

- The spec requires a ``not_affected`` statement to carry a ``justification``
  drawn from a closed enum (``component_not_present``,
  ``vulnerable_code_not_present``, ``vulnerable_code_not_in_execute_path``,
  ``vulnerable_code_cannot_be_controlled_by_adversary``,
  ``inline_mitigations_already_exist``) or a free-text ``impact_statement``.
- Every one of those justifications is a claim about *runtime reachability* or
  *deployed mitigation*. A static read of dependency manifests and MCP config
  files establishes none of them. This scanner does not execute the project,
  does not trace call paths into vendored code, and does not observe the
  deployed environment.
- Emitting ``not_affected`` from evidence that cannot support it is the exact
  failure this document is supposed to prevent: a downstream consumer filters a
  real exposure out of their queue because an upstream tool asserted safety it
  never established.

So where a human would write "not affected", this emitter writes nothing at
all. VEX has no completeness requirement -- an absent statement asserts
nothing, which is the honest position. Under-claiming is the intended bias.

If you are here to add ``not_affected``, the bar is a reachability signal the
scanner actually produces, and the justification enum member it supports.
Do not add it on the strength of "the version looks fine".

Refs:
- OpenVEX v0.2.0: https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md
- CycloneDX companion: `agent_audit_kit/output/sbom.py`
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from agent_audit_kit import __version__
from agent_audit_kit.models import Finding, ScanResult
from agent_audit_kit.output.sbom import _discover_mcp_packages
from agent_audit_kit.rules.builtin import get_rule
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _PINS, _Pin, _fires
from agent_audit_kit.scanners.supply_chain import _semver3

CONTEXT = "https://openvex.dev/ns/v0.2.0"

# The document @id must be a unique IRI. It does not have to resolve, but it
# must live under a namespace the emitter's author controls, or uniqueness is
# not actually guaranteed -- the same reasoning already recorded against
# `documentNamespace` in `emit_spdx`. openvex.dev belongs to the spec authors,
# not to this project, so ids are minted under the project's own GitHub Pages
# origin.
_ID_NAMESPACE = "https://sattyamjjain.github.io/agent-audit-kit/vex"

STATUS_AFFECTED = "affected"
STATUS_FIXED = "fixed"
STATUS_UNDER_INVESTIGATION = "under_investigation"


def _cves_for(pin: _Pin) -> list[str]:
    """CVEs the rule registry attaches to this pin's rule."""
    try:
        return list(get_rule(pin.rule_id).cve_references)
    except Exception:  # noqa: BLE001 - a pin whose rule is gone must not break the emit
        return []


def _pins_by_package() -> dict[str, list[_Pin]]:
    """Package name (lowercased) -> pins that cover it."""
    index: dict[str, list[_Pin]] = {}
    for pin in _PINS:
        for name in pin.names:
            index.setdefault(name.lower(), []).append(pin)
    return index


def _known_cves() -> set[str]:
    """Every CVE the pin table can reason about ranges for."""
    return {cve for pin in _PINS for cve in _cves_for(pin)}


def _status_for(pin: _Pin, version: str) -> Optional[str]:
    """Status of ``version`` against ``pin``, or None when no honest status exists.

    None means "the only truthful label is not_affected", which this emitter
    refuses -- see the module docstring. The caller drops the statement.
    """
    parsed = _semver3(version)
    if parsed is None:
        # Present and in scope, but the version string is not a version this
        # tool can order (a tag, a range, a channel name). Deliberately NOT
        # routed through `_fires`, which treats an unresolvable version as
        # "fire" -- correct for a scanner that should warn, wrong for a VEX
        # document that would then assert exposure it never established.
        return STATUS_UNDER_INVESTIGATION
    if pin.introduced is not None and parsed < pin.introduced:
        # Predates the affected range. The truthful label is not_affected.
        return None
    if pin.floor is None:
        # Presence-only pin: upstream ships no fix, so being installed at any
        # version is the exposure.
        return STATUS_AFFECTED
    # Delegate the range decision to the scanner's own predicate so the VEX
    # document and the scan cannot disagree about what "vulnerable" means.
    return STATUS_AFFECTED if _fires(pin, parsed) else STATUS_FIXED


def _action_statement(pin: _Pin, findings_by_cve: dict[str, list[Finding]], cve: str) -> str:
    """Remediation text for an `affected` statement (required by the spec)."""
    for finding in findings_by_cve.get(cve, []):
        if finding.remediation:
            return finding.remediation
    try:
        return get_rule(pin.rule_id).remediation
    except Exception:  # noqa: BLE001
        return ""


def emit_openvex(
    project_root: Path,
    result: ScanResult,
    *,
    author: str = "agent-audit-kit",
    timestamp: datetime | None = None,
) -> str:
    """Emit an OpenVEX v0.2.0 document for the MCP packages in ``project_root``.

    Args:
        project_root: The scanned project root.
        result: The ScanResult whose findings supply the CVE universe.
        author: VEX document author identity.
        timestamp: Document timestamp; defaults to now (UTC). Injectable so
            callers and tests can pin it and get a byte-identical document.

    Returns:
        The OpenVEX document as indented JSON.
    """
    products = _discover_mcp_packages(project_root)
    by_package = _pins_by_package()
    known = _known_cves()

    findings_by_cve: dict[str, list[Finding]] = {}
    for finding in result.findings:
        for cve in finding.cve_references:
            findings_by_cve.setdefault(cve, []).append(finding)

    # The CVE universe is the union of what the scan surfaced and what the pin
    # table knows about the discovered packages. Findings alone are not enough:
    # a package pinned at or above its fix floor produces no finding, so a
    # findings-only universe would make `fixed` -- the single most useful thing
    # a VEX document can say -- unreachable by construction.
    universe: set[str] = set(findings_by_cve)
    for product in products:
        for covering_pin in by_package.get(product["name"].lower(), []):
            universe.update(_cves_for(covering_pin))

    statements: list[dict] = []
    for product in sorted(products, key=lambda p: p["purl"]):
        pins = by_package.get(product["name"].lower(), [])
        for cve in sorted(universe):
            covering = [p for p in pins if cve in _cves_for(p)]
            pin: Optional[_Pin] = None
            if covering:
                pin = covering[0]
                status = _status_for(pin, product["version"])
                if status is None:
                    continue
            elif cve in known:
                # The pin table knows this CVE and knows it does not name this
                # package. That is a not_affected claim. Refused: say nothing.
                continue
            else:
                # No range knowledge at all. Only speak if a finding carrying
                # this CVE actually landed on the config that declares this
                # product -- otherwise every unrelated CVE in the scan would
                # cross-multiply into noise against every product.
                source = product.get("source")
                if not any(f.file_path == source for f in findings_by_cve.get(cve, [])):
                    continue
                status = STATUS_UNDER_INVESTIGATION

            statement: dict = {
                "vulnerability": {"name": cve},
                "products": [{"@id": product["purl"]}],
                "status": status,
            }
            if status == STATUS_AFFECTED and pin is not None:
                action = _action_statement(pin, findings_by_cve, cve)
                if action:
                    statement["action_statement"] = action
            statements.append(statement)

    # Deterministic @id: same tree + same scan => same document, byte for byte.
    digest = hashlib.sha256()
    for statement in statements:
        digest.update(
            "|".join(
                (
                    statement["products"][0]["@id"],
                    statement["vulnerability"]["name"],
                    statement["status"],
                )
            ).encode("utf-8")
        )
        digest.update(b"\n")

    doc = {
        "@context": CONTEXT,
        "@id": f"{_ID_NAMESPACE}/{digest.hexdigest()}",
        "author": author,
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "version": 1,
        "tooling": f"agent-audit-kit/{__version__}",
        "statements": statements,
    }
    return json.dumps(doc, indent=2)
