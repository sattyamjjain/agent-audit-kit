"""runtime_advisories: declared runtimes and bundled codecs against the advisory file.

The fixtures are version strings only: Dockerfile `FROM` lines, version files, an
`engines` range, an MCP launcher path and lockfile entries. They pin each verdict
the order asked for (PHP2Shell's fixed releases and KEV dates, Node.js's three
fixed lines and its unfixed ones, Brotli and brotlicffi on PyPI), the floating
tags that cannot be judged, and what the scanner leaves alone.
"""

from __future__ import annotations

import json
import tracemalloc
from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import ScanResult, Severity
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import runtime_advisories as ra

FIXTURES = Path(__file__).parent / "fixtures" / "runtime_advisories"
ADV_001, ADV_002, ADV_003 = "AAK-RUNTIME-ADV-001", "AAK-RUNTIME-ADV-002", "AAK-RUNTIME-ADV-003"
RULE_IDS = (ADV_001, ADV_002, ADV_003)


def _found(root: Path) -> list[tuple[str, str, int | None]]:
    findings, _ = ra.scan(root)
    return sorted((f.rule_id, f.file_path, f.line_number) for f in findings)


def _evidence(root: Path) -> str:
    findings, _ = ra.scan(root)
    assert len(findings) == 1, [f.evidence for f in findings]
    return findings[0].evidence


# ---- the fixtures the order lists -------------------------------------------------------


@pytest.mark.parametrize(
    "case, expected",
    [
        ("node-24-22-0-slim", [(ADV_001, "Dockerfile", 1)]),
        ("node-24-22-1", []),
        ("node-20-19-0", [(ADV_001, "Dockerfile", 1)]),
        ("php-8-4-26-fpm", [(ADV_001, "Dockerfile", 1)]),
        ("php-8-4-27-fpm", []),
        ("nvmrc-22-23-3", [(ADV_001, ".nvmrc", 1)]),
        ("tool-versions-26-12-1", []),
        ("node-floating", [(ADV_002, "Dockerfile", 1)]),
        ("lockfiles", [(ADV_003, "uv.lock", 5)]),
        ("mcp-nvm-launcher", [(ADV_001, ".mcp.json", 4)]),
    ],
)
def test_each_fixture_gives_its_verdict(case: str, expected: list) -> None:
    assert _found(FIXTURES / case) == expected


def test_a_node_release_below_its_lines_fix_names_the_fix_and_kev() -> None:
    evidence = _evidence(FIXTURES / "node-24-22-0-slim")
    assert "Node.js 24.22.0 is below 24.22.1, the fixed release on its line, for CVE-2026-111497" in evidence
    assert "CISA KEV, added 2026-10-27, due 2026-11-10" in evidence


def test_a_line_without_a_fix_says_so_and_when_it_ended() -> None:
    evidence = _evidence(FIXTURES / "node-20-19-0")
    assert "Node.js 20.19.0 is on a line with no fixed release for CVE-2026-111497" in evidence
    assert "the 20 line reached end of life on 2026-04-30" in evidence


def test_php2shell_reports_both_cves_with_their_kev_dates() -> None:
    evidence = _evidence(FIXTURES / "php-8-4-26-fpm")
    for cve in ("CVE-2026-109618", "CVE-2026-109619"):
        assert f"below 8.4.27, the fixed release on its line, for {cve}" in evidence
    assert evidence.count("CISA KEV, added 2026-10-26, due 2026-10-29") == 2


def test_brotli_below_its_fix_fires_and_brotlicffi_at_its_fix_does_not() -> None:
    evidence = _evidence(FIXTURES / "lockfiles")
    assert "uv.lock resolves brotli 1.2.0" in evidence and "below 1.2.1" in evidence
    assert "brotlicffi" not in evidence


def test_kev_entries_are_critical_and_the_floating_rule_is_info() -> None:
    findings, _ = ra.scan(FIXTURES / "php-8-4-26-fpm")
    assert findings[0].severity is Severity.CRITICAL
    assert RULES[ADV_001].severity is Severity.CRITICAL
    assert RULES[ADV_002].severity is Severity.INFO
    assert RULES[ADV_003].severity is Severity.CRITICAL


def test_sarif_round_trip_places_every_rule_on_a_line() -> None:
    findings: list = []
    for case in ("node-24-22-0-slim", "node-floating", "lockfiles"):
        findings.extend(f for f in run_scan(project_root=FIXTURES / case).findings if f.rule_id in RULE_IDS)
    sarif = json.loads(format_results(ScanResult(findings=findings), min_severity=Severity.INFO))
    placed = {
        r["ruleId"]: r["locations"][0]["physicalLocation"]["region"]["startLine"]
        for r in sarif["runs"][0]["results"]
    }
    assert set(placed) == set(RULE_IDS)
    assert all(isinstance(line, int) and line >= 1 for line in placed.values())
    levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
    assert levels[ADV_001] == "error" and levels[ADV_002] == "note"


# ---- how a declaration is read --------------------------------------------------------------


@pytest.mark.parametrize(
    "line, rule",
    [
        ("FROM node:24.22.0-bookworm-slim", ADV_001),
        ("FROM docker.io/library/node:22.23.3-alpine3.20", ADV_001),
        ("FROM --platform=linux/amd64 node:26.12.0 AS build", ADV_001),
        ("FROM node:20", ADV_001),             # every 20.x: no fixed release on the line
        ("FROM php:8.1-fpm", ADV_001),         # end of life, no fix
        ("FROM php:7.4", ADV_001),
        ("FROM node:24-alpine", ADV_002),      # a fixed line, floating
        ("FROM node:lts", ADV_002),
        ("FROM node", ADV_002),                # no tag: latest
        ("FROM php:8", ADV_002),               # floats across lines
        ("FROM node:26.12.1", None),
        ("FROM node:27.0.0", None),            # a newer line than any fix carries it
        ("FROM node:8.17.0", None),            # before Node.js bundled Brotli
        ("FROM php:5.3.29", None),             # before either flaw
        ("FROM python:3.12.7-slim", None),     # no advisory names Python
        ("FROM node@sha256:" + "a" * 64, None),
        ("FROM bitnami/node:24.22.0", None),   # not the official image
    ],
)
def test_from_lines(tmp_path: Path, line: str, rule: str | None) -> None:
    (tmp_path / "Dockerfile").write_text(f"{line}\n")
    assert [r for r, _, _ in _found(tmp_path)] == ([rule] if rule else [])


def test_a_from_through_a_global_arg_and_a_stage_name(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "ARG NODE_VERSION=24.22.0\nFROM node:${NODE_VERSION}-slim AS build\nFROM build AS final\n"
        "FROM node:${UNSET}\n"
    )
    assert _found(tmp_path) == [(ADV_001, "Dockerfile", 2)]


def test_tool_versions_reads_every_listed_version(tmp_path: Path) -> None:
    (tmp_path / ".tool-versions").write_text("nodejs 24.22.1 20.19.0\nphp 8.4.26\npython 3.12.7\n")
    assert _found(tmp_path) == [(ADV_001, ".tool-versions", 1), (ADV_001, ".tool-versions", 2)]


def test_engines_node_is_judged_at_the_lowest_release_it_admits(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"engines": {"node": ">=18"}}, indent=2))
    evidence = _evidence(tmp_path)
    assert "Node.js 18.0.0" in evidence and "lowest release `>=18` admits" in evidence
    (tmp_path / "package.json").write_text(json.dumps({"engines": {"node": ">=22.23.4 <23 || >=24.22.1"}}))
    assert _found(tmp_path) == []


@pytest.mark.parametrize(
    "file, text, rule",
    [
        ("app.yaml", "runtime: nodejs20\n", ADV_001),
        ("app.yaml", "runtime: nodejs22\n", ADV_002),
        ("app.yaml", "runtime: php81\n", ADV_001),
        ("serverless.yml", "provider:\n  name: aws\n  runtime: nodejs24.x\n", ADV_002),
        ("serverless.yml", "functions:\n  a:\n    runtime: nodejs18.x\n", ADV_001),
        ("app.yaml", "runtime: python312\n", None),
    ],
)
def test_managed_runtimes(tmp_path: Path, file: str, text: str, rule: str | None) -> None:
    (tmp_path / file).write_text(text)
    assert [r for r, _, _ in _found(tmp_path)] == ([rule] if rule else [])


@pytest.mark.parametrize(
    "command, rule",
    [
        ("~/.nvm/versions/node/v24.22.0/bin/node", ADV_001),
        ("/Users/x/.local/share/mise/installs/node/22.23.4/bin/node", None),
        ("/opt/homebrew/Cellar/node/24.21.0_1/bin/node", ADV_001),
        ("C:\\Users\\x\\.volta\\tools\\image\\node\\20.19.0\\node.exe", ADV_001),
        ("/home/x/.asdf/installs/php/8.3.35/bin/php", ADV_001),
        ("node", None),
    ],
)
def test_mcp_launcher_paths(tmp_path: Path, command: str, rule: str | None) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": {"command": command, "args": ["x.js"]}}}))
    assert [r for r, _, _ in _found(tmp_path)] == ([rule] if rule else [])


def test_exact_pins_and_four_part_versions(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("brotlicffi==1.2.0.2\nBrotli>=1.0\n")
    assert _found(tmp_path) == [(ADV_003, "requirements.txt", 1)]


def test_a_python_project_with_no_advisory_reports_nothing(tmp_path: Path) -> None:
    (tmp_path / ".python-version").write_text("3.9.0\n")
    (tmp_path / "Dockerfile").write_text("FROM python:3.9\n")
    assert _found(tmp_path) == []


# ---- the advisory file ---------------------------------------------------------------------------


def test_the_bundled_file_holds_what_the_advisories_published() -> None:
    data = json.loads(ra.BUNDLED.read_text())
    by_key = {(a["id"], a["subject"]): a for a in data["advisories"]}
    php = by_key[("CVE-2026-109618", "php")]
    assert php["fixed_by_line"] == {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
    assert (php["kev_added"], php["kev_due"], php["affected_from"]) == ("2026-10-26", "2026-10-29", "7.3.0")
    assert by_key[("CVE-2026-109619", "php")]["affected_from"] == "5.4.0"
    node = by_key[("CVE-2026-111497", "node")]
    assert node["fixed_by_line"] == {"22": "22.23.4", "24": "24.22.1", "26": "26.12.1"}
    assert node["kev_added"] == "2026-10-27"
    assert by_key[("CVE-2026-111497", "pypi:Brotli")]["fixed_by_line"] == {"1.2": "1.2.1"}
    assert by_key[("CVE-2026-111497", "pypi:brotlicffi")]["fixed_by_line"] == {"1.2": "1.2.1.0"}
    assert all(a["read_at"] == "2026-10-28" and a["url"] for a in data["advisories"])
    assert data["eol"]["node"]["lines"]["20"] == "2026-04-30"
    assert data["eol"]["php"]["lines"]["8.1"] == "2025-12-31"


def test_a_local_copy_is_read_first_and_a_broken_one_is_skipped(tmp_path: Path) -> None:
    cache = ra.cache_path()
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"generated_at": "t", "source": "local", "advisories": [
        {"id": "CVE-TEST-1", "subject": "node", "severity": "high", "fixed_by_line": {"24": "24.99.0"}}]}))
    (tmp_path / ".nvmrc").write_text("24.22.1\n")
    findings, _ = ra.scan(tmp_path)
    assert [(f.rule_id, f.severity) for f in findings] == [(ADV_001, Severity.HIGH)]
    cache.write_text("{ not json")
    assert ra.load_advisories().origin == "bundled"
    assert _found(tmp_path) == []


def test_reports_name_the_advisory_file_and_its_age() -> None:
    result = run_scan(project_root=FIXTURES / "node-24-22-1")
    feed = result.data_feeds["runtimeAdvisories"]
    assert feed["origin"] == "bundled" and feed["generatedAt"]


# ---- crafted input -------------------------------------------------------------------------


def test_a_repeated_value_or_lockfile_row_is_reported_once(tmp_path: Path) -> None:
    """One finding per release a line or a lockfile names, at its first mention: a
    `.tool-versions` repeating one value 140,000 times made 140,000 findings."""
    (tmp_path / ".tool-versions").write_text("nodejs 22.0.0 22.0.0 22.0.0\n")
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "brotli"\nversion = "1.0.9"\n' * 3)
    findings, _ = ra.scan(tmp_path)
    assert sorted((f.rule_id, f.file_path, f.line_number) for f in findings) == [
        (ADV_001, ".tool-versions", 1), (ADV_003, "uv.lock", 2)]


def test_an_arg_expansion_past_any_image_reference_is_not_read(tmp_path: Path) -> None:
    """`FROM ${X}${X}...` of an ARG as long expanded to the square of the file: 100 KB
    took 800 MB. No image reference runs past 1,024 characters, so the expansion stops
    there and the FROM is not judged."""
    k = 6_000
    (tmp_path / "Dockerfile").write_text('ARG ["X=' + "a" * k + '"]\nFROM ["' + "${X}" * k + '"]\n')
    tracemalloc.start()
    try:
        findings, scanned = ra.scan(tmp_path)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert findings == [] and scanned == {"Dockerfile"}
    assert peak < 16_000_000, peak
    (tmp_path / "Dockerfile").write_text("ARG V=22.0.0\nFROM node:${V}\n")  # an ordinary ARG still expands
    assert [f.rule_id for f in ra.scan(tmp_path)[0]] == [ADV_001]

