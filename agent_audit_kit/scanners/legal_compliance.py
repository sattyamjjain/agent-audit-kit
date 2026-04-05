from __future__ import annotations

import json
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

# ---- AAK-LEGAL-001: Copyleft / restrictive license patterns ----
_COPYLEFT_RE = re.compile(
    r"^(AGPL|SSPL|GPL-3|EUPL)",
    re.IGNORECASE,
)

# ---- AAK-LEGAL-003: DMCA blocklisted package names ----
_DMCA_BLOCKLIST: frozenset[str] = frozenset({
    "claude-code-leaked",
    "anthropic-internal",
    "copilot-source",
})


def _find_package_jsons(project_root: Path) -> list[Path]:
    """Find all package.json files, skipping SKIP_DIRS."""
    found: list[Path] = []
    # Root package.json is the primary target
    root_pkg = project_root / "package.json"
    if root_pkg.is_file():
        found.append(root_pkg)
    # Also check workspace packages (monorepo)
    for p in project_root.rglob("package.json"):
        if any(part in SKIP_DIRS for part in p.relative_to(project_root).parts):
            continue
        if p.is_file() and p not in found:
            found.append(p)
    return found


def _check_license_field(
    data: dict,
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """AAK-LEGAL-001 and AAK-LEGAL-002: Check the license field."""
    findings: list[Finding] = []

    license_val = data.get("license")

    if license_val is None:
        # AAK-LEGAL-002: No license field
        findings.append(make_finding(
            "AAK-LEGAL-002",
            rel_path,
            "package.json has no 'license' field",
            find_line_number(raw_text, '"name"') or 1,
        ))
    elif isinstance(license_val, str):
        # AAK-LEGAL-001: Copyleft license
        if _COPYLEFT_RE.match(license_val):
            findings.append(make_finding(
                "AAK-LEGAL-001",
                rel_path,
                f"Copyleft license declared: {license_val}",
                find_line_number(raw_text, license_val),
            ))
    elif isinstance(license_val, dict):
        # Handle {"type": "...", "url": "..."} form
        license_type = license_val.get("type", "")
        if isinstance(license_type, str) and _COPYLEFT_RE.match(license_type):
            findings.append(make_finding(
                "AAK-LEGAL-001",
                rel_path,
                f"Copyleft license declared: {license_type}",
                find_line_number(raw_text, license_type),
            ))

    return findings


def _check_dependencies_for_dmca(
    data: dict,
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """AAK-LEGAL-003: Check all dependency maps for DMCA-blocklisted names."""
    findings: list[Finding] = []

    dep_sections = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "bundledDependencies",
        "bundleDependencies",
    ]

    for section_name in dep_sections:
        deps = data.get(section_name, {})
        if isinstance(deps, dict):
            for pkg_name in deps:
                normalized = str(pkg_name).lower().strip()
                # Strip scope prefix for matching (e.g. @org/claude-code-leaked)
                bare_name = normalized.split("/")[-1] if "/" in normalized else normalized
                if bare_name in _DMCA_BLOCKLIST or normalized in _DMCA_BLOCKLIST:
                    findings.append(make_finding(
                        "AAK-LEGAL-003",
                        rel_path,
                        f"DMCA-flagged package in {section_name}: {pkg_name}",
                        find_line_number(raw_text, str(pkg_name)),
                    ))
        elif isinstance(deps, list):
            # bundledDependencies can be a list of strings
            for pkg_name in deps:
                normalized = str(pkg_name).lower().strip()
                bare_name = normalized.split("/")[-1] if "/" in normalized else normalized
                if bare_name in _DMCA_BLOCKLIST or normalized in _DMCA_BLOCKLIST:
                    findings.append(make_finding(
                        "AAK-LEGAL-003",
                        rel_path,
                        f"DMCA-flagged package in {section_name}: {pkg_name}",
                        find_line_number(raw_text, str(pkg_name)),
                    ))

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan package.json files for legal compliance issues.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for pkg_path in _find_package_jsons(project_root):
        try:
            raw_text = pkg_path.read_text(encoding="utf-8")
            if len(raw_text) > 1_000_000:
                continue
            data = json.loads(raw_text)
        except (json.JSONDecodeError, OSError):
            continue

        if not isinstance(data, dict):
            continue

        rel_path = (
            str(pkg_path.relative_to(project_root))
            if pkg_path.is_relative_to(project_root)
            else str(pkg_path)
        )
        scanned_files.add(rel_path)

        findings.extend(_check_license_field(data, rel_path, raw_text))
        findings.extend(_check_dependencies_for_dmca(data, rel_path, raw_text))

    return findings, scanned_files
