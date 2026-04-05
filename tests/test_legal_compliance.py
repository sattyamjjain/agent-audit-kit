from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.scanners.legal_compliance import scan


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _write_package_json(
    tmp_path: Path,
    data: dict,
    filename: str = "package.json",
) -> None:
    """Write a package.json file."""
    (tmp_path / filename).write_text(json.dumps(data, indent=2))


_VULNERABLE_PACKAGE: dict = {
    "name": "vulnerable-project",
    "version": "1.0.0",
    "license": "AGPL-3.0",
    "dependencies": {
        "express": "^4.18.0",
        "claude-code-leaked": "0.0.1",
    },
}

_CLEAN_PACKAGE: dict = {
    "name": "clean-project",
    "version": "1.0.0",
    "license": "MIT",
    "dependencies": {
        "express": "^4.18.0",
        "lodash": "^4.17.21",
    },
    "devDependencies": {
        "jest": "^29.0.0",
    },
}


def test_vulnerable_triggers_rules(tmp_path: Path) -> None:
    """Vulnerable package.json should trigger AAK-LEGAL-001 and 003."""
    _write_package_json(tmp_path, _VULNERABLE_PACKAGE)
    findings, scanned = scan(tmp_path)
    rule_ids = {f.rule_id for f in findings}

    assert "package.json" in scanned, "package.json should be in scanned files"

    assert "AAK-LEGAL-001" in rule_ids, "Should detect AGPL-3.0 copyleft license"
    assert "AAK-LEGAL-003" in rule_ids, "Should detect DMCA-blocklisted package"


def test_missing_license_triggers_002(tmp_path: Path) -> None:
    """AAK-LEGAL-002: Package without 'license' field."""
    pkg = {
        "name": "no-license-project",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.18.0",
        },
    }
    _write_package_json(tmp_path, pkg)
    findings, _ = scan(tmp_path)
    rule_ids = {f.rule_id for f in findings}

    assert "AAK-LEGAL-002" in rule_ids, "Missing license field should trigger AAK-LEGAL-002"


def test_clean_zero_findings(tmp_path: Path) -> None:
    """Clean package.json with MIT license and normal deps should produce zero findings."""
    _write_package_json(tmp_path, _CLEAN_PACKAGE)
    findings, scanned = scan(tmp_path)

    assert "package.json" in scanned
    assert len(findings) == 0, (
        f"Clean package.json should produce zero findings, got: "
        f"{[(f.rule_id, f.evidence) for f in findings]}"
    )


def test_empty_or_missing(tmp_path: Path) -> None:
    """Missing, empty, and malformed files should produce zero findings."""
    # No package.json
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0
    assert len(scanned) == 0

    # Empty package.json
    (tmp_path / "package.json").write_text("")
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0

    # Malformed JSON
    (tmp_path / "package.json").write_text("{broken json!!}")
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0


def test_legal_001_various_copyleft_licenses(tmp_path: Path) -> None:
    """AAK-LEGAL-001 should detect AGPL, SSPL, GPL-3, and EUPL licenses."""
    copyleft_licenses = ["AGPL-3.0", "SSPL-1.0", "GPL-3.0", "EUPL-1.2"]
    for license_id in copyleft_licenses:
        pkg = {
            "name": "copyleft-test",
            "version": "1.0.0",
            "license": license_id,
        }
        _write_package_json(tmp_path, pkg)
        findings, _ = scan(tmp_path)
        legal_001 = [f for f in findings if f.rule_id == "AAK-LEGAL-001"]
        assert len(legal_001) >= 1, (
            f"License '{license_id}' should trigger AAK-LEGAL-001"
        )


def test_legal_001_permissive_licenses_not_flagged(tmp_path: Path) -> None:
    """Permissive licenses should NOT trigger AAK-LEGAL-001."""
    permissive_licenses = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense"]
    for license_id in permissive_licenses:
        pkg = {
            "name": "permissive-test",
            "version": "1.0.0",
            "license": license_id,
        }
        _write_package_json(tmp_path, pkg)
        findings, _ = scan(tmp_path)
        legal_001 = [f for f in findings if f.rule_id == "AAK-LEGAL-001"]
        assert len(legal_001) == 0, (
            f"Permissive license '{license_id}' should not trigger AAK-LEGAL-001"
        )


def test_legal_001_license_as_dict(tmp_path: Path) -> None:
    """AAK-LEGAL-001 should handle license field in dict form: {type, url}."""
    pkg = {
        "name": "dict-license-project",
        "version": "1.0.0",
        "license": {
            "type": "GPL-3.0",
            "url": "https://www.gnu.org/licenses/gpl-3.0.html",
        },
    }
    _write_package_json(tmp_path, pkg)
    findings, _ = scan(tmp_path)
    legal_001 = [f for f in findings if f.rule_id == "AAK-LEGAL-001"]
    assert len(legal_001) >= 1, "Dict-form copyleft license should trigger AAK-LEGAL-001"


def test_legal_003_dmca_in_dev_dependencies(tmp_path: Path) -> None:
    """AAK-LEGAL-003 should detect blocklisted packages in devDependencies too."""
    pkg = {
        "name": "dev-dep-test",
        "version": "1.0.0",
        "license": "MIT",
        "devDependencies": {
            "jest": "^29.0.0",
            "anthropic-internal": "0.1.0",
        },
    }
    _write_package_json(tmp_path, pkg)
    findings, _ = scan(tmp_path)
    legal_003 = [f for f in findings if f.rule_id == "AAK-LEGAL-003"]
    assert len(legal_003) >= 1, (
        "DMCA-blocklisted package in devDependencies should trigger AAK-LEGAL-003"
    )


def test_legal_003_scoped_package(tmp_path: Path) -> None:
    """AAK-LEGAL-003 should detect blocklisted names even under scoped packages."""
    pkg = {
        "name": "scoped-test",
        "version": "1.0.0",
        "license": "MIT",
        "dependencies": {
            "@shady-org/claude-code-leaked": "1.0.0",
        },
    }
    _write_package_json(tmp_path, pkg)
    findings, _ = scan(tmp_path)
    legal_003 = [f for f in findings if f.rule_id == "AAK-LEGAL-003"]
    assert len(legal_003) >= 1, (
        "Scoped package with blocklisted bare name should trigger AAK-LEGAL-003"
    )


def test_legal_003_all_blocklisted_names(tmp_path: Path) -> None:
    """All three DMCA-blocklisted names should be detected."""
    pkg = {
        "name": "all-blocked",
        "version": "1.0.0",
        "license": "MIT",
        "dependencies": {
            "claude-code-leaked": "0.0.1",
            "anthropic-internal": "0.1.0",
            "copilot-source": "0.0.1",
        },
    }
    _write_package_json(tmp_path, pkg)
    findings, _ = scan(tmp_path)
    legal_003 = [f for f in findings if f.rule_id == "AAK-LEGAL-003"]
    assert len(legal_003) >= 3, (
        f"Expected 3 DMCA findings for all blocklisted packages, got {len(legal_003)}"
    )


def test_legal_003_normal_deps_not_flagged(tmp_path: Path) -> None:
    """Normal dependency names should NOT trigger AAK-LEGAL-003."""
    pkg = {
        "name": "normal-project",
        "version": "1.0.0",
        "license": "MIT",
        "dependencies": {
            "express": "^4.18.0",
            "react": "^18.2.0",
            "lodash": "^4.17.21",
            "@types/node": "^20.0.0",
        },
    }
    _write_package_json(tmp_path, pkg)
    findings, _ = scan(tmp_path)
    legal_003 = [f for f in findings if f.rule_id == "AAK-LEGAL-003"]
    assert len(legal_003) == 0, "Normal dependencies should not be flagged"


def test_monorepo_nested_package_json(tmp_path: Path) -> None:
    """Scanner should discover nested package.json files in a monorepo."""
    # Root package.json (clean)
    _write_package_json(tmp_path, _CLEAN_PACKAGE)

    # Nested workspace package with issues
    workspace_dir = tmp_path / "packages" / "risky-pkg"
    workspace_dir.mkdir(parents=True)
    _write_package_json(
        workspace_dir,
        {
            "name": "risky-pkg",
            "version": "1.0.0",
            "license": "SSPL-1.0",
            "dependencies": {
                "copilot-source": "0.0.1",
            },
        },
        filename="package.json",
    )
    # The nested write helper writes to workspace_dir/package.json, but
    # _write_package_json writes relative to the provided tmp_path.
    # Let's write directly instead:
    (workspace_dir / "package.json").write_text(json.dumps({
        "name": "risky-pkg",
        "version": "1.0.0",
        "license": "SSPL-1.0",
        "dependencies": {
            "copilot-source": "0.0.1",
        },
    }))

    findings, scanned = scan(tmp_path)
    # Should have findings from the nested package
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-LEGAL-001" in rule_ids, "Nested SSPL license should be detected"
    assert "AAK-LEGAL-003" in rule_ids, "Nested DMCA package should be detected"


def test_bundled_dependencies_list_format(tmp_path: Path) -> None:
    """bundledDependencies (list of strings) should also be checked for DMCA."""
    pkg = {
        "name": "bundled-test",
        "version": "1.0.0",
        "license": "MIT",
        "bundledDependencies": [
            "express",
            "claude-code-leaked",
        ],
    }
    _write_package_json(tmp_path, pkg)
    findings, _ = scan(tmp_path)
    legal_003 = [f for f in findings if f.rule_id == "AAK-LEGAL-003"]
    assert len(legal_003) >= 1, (
        "DMCA-blocklisted package in bundledDependencies list should be detected"
    )


def test_json_array_root_skipped(tmp_path: Path) -> None:
    """package.json with a JSON array root should be skipped gracefully."""
    (tmp_path / "package.json").write_text(json.dumps(["not", "a", "dict"]))
    findings, scanned = scan(tmp_path)
    assert len(findings) == 0
    assert len(scanned) == 0
