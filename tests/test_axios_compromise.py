"""The axios compromise of 31 March 2026, by the releases it hit.

Two releases went out from the lead maintainer's hijacked npm account, axios
1.14.1 and 0.30.4, each pulling in plain-crypto-js 4.2.1, a remote access trojan
(https://github.com/axios/axios/issues/10636, OSV MAL-2026-2307 and MAL-2026-2306).
AAK-SUPPLY-002 and -006 carried that label on `>=1.7.0 <1.7.4`, which is a slice of
CVE-2024-39338, an unrelated SSRF, so a lockfile with 1.14.1 got nothing from them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import malicious_releases, supply_chain
from agent_audit_kit.scanners.supply_chain import KNOWN_VULNERABLE_PACKAGES, _entry_lists, _version_in_range
from agent_audit_kit.vuln_db import BUNDLED_DB

THREE = {"AAK-MALICIOUS-RELEASE-001", "AAK-SUPPLY-002", "AAK-SUPPLY-006"}


def _lock(name: str, version: str) -> str:
    return json.dumps({
        "name": "app", "lockfileVersion": 3,
        "packages": {"": {"name": "app", "version": "1.0.0"},
                     f"node_modules/{name}": {"version": version}},
    }, indent=2)


def _findings(root: Path, rules: set[str] = THREE) -> list:
    return [f for f in run_scan(root).findings if f.rule_id in rules]


@pytest.mark.parametrize("name,version", [("axios", "1.14.1"), ("axios", "0.30.4"), ("plain-crypto-js", "4.2.1")])
def test_a_lockfile_entry_gives_one_critical_finding(tmp_path: Path, name: str, version: str) -> None:
    (tmp_path / "package-lock.json").write_text(_lock(name, version))
    (finding,) = _findings(tmp_path)
    assert finding.rule_id == "AAK-MALICIOUS-RELEASE-001"
    assert finding.severity is Severity.CRITICAL
    assert finding.line_number == 9  # the `version` line of the entry
    assert f"resolves {name} {version}" in finding.evidence


@pytest.mark.parametrize("version", ["1.14.0", "1.14.2", "0.30.3", "1.7.2", "1.7.4"])
def test_the_releases_around_them_give_nothing(tmp_path: Path, version: str) -> None:
    (tmp_path / "package-lock.json").write_text(_lock("axios", version))
    assert _findings(tmp_path) == []


def test_npm_holding_package_is_not_the_trojan(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(_lock("plain-crypto-js", "0.0.1-security"))
    assert _findings(tmp_path) == []


def test_a_launch_gives_one_finding(tmp_path: Path) -> None:
    config = {"mcpServers": {"x": {"command": "npx", "args": ["-y", "axios@1.14.1"]}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(config, indent=2))
    (finding,) = _findings(tmp_path)
    assert finding.rule_id == "AAK-MALICIOUS-RELEASE-001"
    assert "MAL-2026-2307" in finding.evidence


def test_the_table_rules_stand_down_only_for_a_finding_that_will_be_reported(tmp_path: Path) -> None:
    """The pass runs after the rule filter: excluding the feed rule, or asking for
    a table rule alone, leaves the table rule's own finding."""
    (tmp_path / "package-lock.json").write_text(_lock("axios", "1.14.1"))
    excluded = run_scan(tmp_path, exclude_rules=["AAK-MALICIOUS-RELEASE-001"]).findings
    assert [f.rule_id for f in excluded if f.rule_id in THREE] == ["AAK-SUPPLY-002"]
    only = run_scan(tmp_path, rules=["AAK-SUPPLY-002"]).findings
    assert [f.rule_id for f in only] == ["AAK-SUPPLY-002"]


def test_the_stand_down_is_per_file_and_per_release(tmp_path: Path) -> None:
    """A feed finding on another file, or on another release in the same file,
    leaves a table finding alone, and a shorter version is another release."""
    (tmp_path / "package-lock.json").write_text(_lock("axios", "1.14.1"))
    web = tmp_path / "web"
    web.mkdir()
    (web / "package-lock.json").write_text(_lock("axios", "1.14.1"))
    found = _findings(tmp_path)
    assert sorted(f.rule_id for f in found) == ["AAK-MALICIOUS-RELEASE-001", "AAK-MALICIOUS-RELEASE-001"]

    from agent_audit_kit.engine import _drop_table_findings_the_feed_reports as drop
    from agent_audit_kit.scanners._helpers import make_finding

    feed = make_finding("AAK-MALICIOUS-RELEASE-001", "a.json",
                        "a.json resolves axios 1.14.1, a malicious release: MAL-2026-2307, which lists axios 1.14.1. Feed: x")
    same = make_finding("AAK-SUPPLY-002", "a.json", "axios@1.14.1 — label")
    other_version = make_finding("AAK-SUPPLY-002", "a.json", "axios@0.30.4 — label")
    prefix_version = make_finding("AAK-SUPPLY-002", "a.json", "axios@1.14 — label")
    other_file = make_finding("AAK-SUPPLY-006", "b.json", "Server 'x' uses axios@1.14.1 — label")
    typosquat = make_finding("AAK-SUPPLY-002", "a.json", "Potential typosquat: axios")
    kept = drop([feed, same, other_version, prefix_version, other_file, typosquat])
    assert kept == [feed, other_version, prefix_version, other_file, typosquat]


def test_an_every_release_entry_covers_any_version_of_the_package(tmp_path: Path) -> None:
    from agent_audit_kit.engine import _drop_table_findings_the_feed_reports as drop
    from agent_audit_kit.scanners._helpers import make_finding

    feed = make_finding(
        "AAK-MALICIOUS-RELEASE-001", "a.json",
        "a.json resolves plain-crypto-js 4.2.1, a malicious release: MAL-2026-2306 (GHSA-x), "
        "which lists every release of plain-crypto-js (https://osv.dev/x). Feed: y")
    table = make_finding("AAK-SUPPLY-002", "a.json", "plain-crypto-js@4.2.1 — label")
    longer_name = make_finding("AAK-SUPPLY-002", "a.json", "plain-crypto-js-two@4.2.1 — label")
    assert drop([feed, table, longer_name]) == [feed, longer_name]


@pytest.mark.parametrize("evidence,expected", [
    ("`npx -y axios@1.14.1` in .mcp.json installs a malicious release: MAL-2026-2307 (GHSA-x), which lists "
     "axios 1.14.1 (https://osv.dev/x). Feed: the bundled copy", ("axios", "1.14.1")),
    ("x which lists axios 9.9.9 in .mcp.json installs a malicious release: MAL-1, which lists axios 1.14.1. "
     "Feed: y", ("axios", "1.14.1")),
    ("p resolves @scope/pkg 1.0.0, a malicious release: MAL-1, which lists @scope/pkg 1.0.0. Feed: y",
     ("@scope/pkg", "1.0.0")),
    ("MAL-1, which lists every release of plain-crypto-js. Feed: y", ("plain-crypto-js", None)),
    ("`repo@sha256:abc` runs a compromised image: LITELLM-2026-10-21", None),
])
def test_listed_release_reads_the_feed_wording(evidence: str, expected: tuple[str, str | None] | None) -> None:
    assert malicious_releases.listed_release(evidence) == expected


@pytest.mark.parametrize("evidence,expected", [
    ("axios@1.14.1 — label", ("axios", "1.14.1")),
    ("Server 'a uses b@1 — x' uses axios@0.30.4 — label", ("axios", "0.30.4")),
    ("Server 'x' uses @scope/pkg@1.0.0 — label", ("@scope/pkg", "1.0.0")),
    ("requests==2.0.0 — label", ("requests", "2.0.0")),
    ("Potential typosquat: @modlecontextprotocol/server", None),
])
def test_table_release_reads_the_table_wording(evidence: str, expected: tuple[str, str] | None) -> None:
    assert supply_chain.table_release(evidence) == expected


# ---- the table, and what older clients read from it -------------------------------


def test_a_token_without_an_operator_matches_nothing() -> None:
    """The loop skipped such a token, so nothing was compared and each of these
    matched every version of the package."""
    for affected in ("1.14.1", "==1.14.1", "1.14.1 || 0.30.4", ""):
        assert not _version_in_range("1.7.4", affected), affected
        assert not _version_in_range("0.1.0", affected), affected
    assert not _version_in_range("1.14.1", "1.14.1")
    assert not _version_in_range("1.14.1", ">=1.0.0 1.14.1")


def test_an_exact_list_is_read_before_the_range() -> None:
    axios = KNOWN_VULNERABLE_PACKAGES["npm"]["axios"]
    assert _entry_lists(axios, "0.30.4") and _entry_lists(axios, "1.14.1")
    assert not _entry_lists(axios, "1.14.0") and not _entry_lists(axios, "1.14.10")
    assert not _entry_lists({"versions": ["1.0.0"], "affected": ">=0.0.0"}, "2.0.0")
    assert _entry_lists({"affected": ">=1.0.0 <2.0.0"}, "1.5.0")
    for bad in ("x", None, {}, {"affected": 7}, {"versions": "1.0.0"}):
        assert not _entry_lists(bad, "1.0.0"), bad


def test_the_code_table_and_the_database_agree() -> None:
    db = json.loads(BUNDLED_DB.read_text())
    assert db["npm"] == KNOWN_VULNERABLE_PACKAGES["npm"]


def _version_in_range_0_6_30(version: str, affected: str) -> bool:
    """`_version_in_range` as 0.6.30 shipped it, frozen here. `aak update` on that
    release downloads `data/vuln_db.json` from main."""
    try:
        parts = affected.split()
        ver_tuple = tuple(int(x) for x in version.split("."))

        i = 0
        while i < len(parts):
            token = parts[i]
            if token.startswith(">="):
                min_ver = tuple(int(x) for x in token[2:].split("."))
                if ver_tuple < min_ver:
                    return False
            elif token.startswith(">"):
                min_ver = tuple(int(x) for x in token[1:].split("."))
                if ver_tuple <= min_ver:
                    return False
            elif token.startswith("<="):
                max_ver = tuple(int(x) for x in token[2:].split("."))
                if ver_tuple > max_ver:
                    return False
            elif token.startswith("<"):
                max_ver = tuple(int(x) for x in token[1:].split("."))
                if ver_tuple >= max_ver:
                    return False
            i += 1
        return True
    except (ValueError, IndexError):
        return False


def test_an_older_client_reads_the_new_database_safely() -> None:
    """0.6.30 reads `vuln_info["affected"]` and `vuln_info["description"]` directly.
    A bare version there would match everything, and a missing key would crash it."""
    npm = json.loads(BUNDLED_DB.read_text())["npm"]
    assert set(npm) == {"axios", "plain-crypto-js"}
    for entry in npm.values():
        assert isinstance(entry["affected"], str) and isinstance(entry["description"], str)
    axios = npm["axios"]["affected"]
    assert _version_in_range_0_6_30("1.14.1", axios)
    for version in ("1.14.0", "1.14.2", "0.30.3", "0.30.4", "1.7.2", "1.7.4", "0.1.0", "2.0.0", "garbage", ""):
        assert not _version_in_range_0_6_30(version, axios), version
    trojan = npm["plain-crypto-js"]["affected"]
    for version in ("4.2.0", "4.2.1", "0.0.1", "99.0.0"):
        assert _version_in_range_0_6_30(version, trojan), version
    assert not _version_in_range_0_6_30("0.0.1-security", trojan)


def test_no_rule_points_at_the_old_range() -> None:
    for rule_id in ("AAK-SUPPLY-002", "AAK-SUPPLY-006"):
        rule = RULES[rule_id]
        text = " ".join((rule.remediation, rule.limitations))
        assert "1.7.4" not in text and "1.7.0" not in text and "1.7.3" not in text, rule_id
        assert "1.14.1" in text and "0.30.4" in text and "plain-crypto-js" in text, rule_id
        assert "AAK-MALICIOUS-RELEASE-001" in rule.limitations, rule_id
