"""#1125 to #1148, the watcher's OSV records for next, better-auth, openclaw, litellm,
the MCP TypeScript SDK and praisonai, read on 2026-11-11.

Each OSV record is saved unedited under tests/fixtures/osv, as
`https://api.osv.dev/v1/vulns/<id>` returned it on 2026-11-11. A test that needs the
feed `aak update` writes builds it from those records through the same `Collector`,
in the empty HOME every test gets. `CHANGELOG.cves.md` holds the reasoning.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_audit_kit import advisory_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import known_vulns, mcp_cve_pins_2026_07

FIXTURES = Path(__file__).parent / "fixtures"
OSV = FIXTURES / "osv"
CVES = FIXTURES / "cves"
LEDGER = Path(__file__).resolve().parent.parent / "CHANGELOG.cves.md"
NOW = datetime(2026, 11, 11, 6, 0, tzinfo=timezone.utc)
KNOWN = "AAK-KNOWN-VULN-001"

NEXTJS = "AAK-MCP-NEXTJS-CVE-2026-94486-001"
BA_RULE = "AAK-MCP-BETTERAUTH-CVE-2026-53512-001"
LITELLM = ("AAK-MCP-LITELLM-CVE-2026-59822-001", "AAK-MCP-LITELLM-CVE-2026-114612-001",
           "AAK-LITELLM-CVE-2026-30623-PIN-001")
OPENCLAW = "AAK-MCP-OPENCLAW-CVE-2026-62195-001"
PRAISONAI = "AAK-MCP-PRAISONAI-CVE-2026-61427-001"
TSSDK = "AAK-MCP-TSSDK-CVE-2026-111768-001"

NEXT_2464, NEXT_673Q, NEXT_P3M5 = "GHSA-2464-fhr4-w9xw", "GHSA-673q-mjm6-r5xr", "GHSA-p3m5-59mp-jv5r"
BA_965C, BA_Q84F, BA_R4XP, BA_44JH = ("GHSA-965c-763c-88jm", "GHSA-q84f-53jg-9ppm", "GHSA-r4xp-prcw-77qf",
                                      "GHSA-44jh-23m7-hpcf")
LL_G5FF, LL_HHWW = "GHSA-g5ff-637f-6q2m", "GHSA-hhww-mrg2-969h"
OC_3X84, SDK_F897, PR_26MH = "GHSA-3x84-qq85-fj65", "GHSA-f897-62hf-6gxq", "GHSA-26mh-57q7-jfvr"
FEED_ONLY = (NEXT_2464, NEXT_673Q, NEXT_P3M5, BA_965C, BA_Q84F, BA_R4XP, BA_44JH, LL_G5FF, LL_HHWW)


def _record(ident: str) -> dict:
    return json.loads((OSV / f"{ident}.json").read_text(encoding="utf-8"))


def _cache(*idents: str) -> None:
    """The cached feed `aak update` writes, holding these records: each is handed to
    the collector once per export that lists one of its packages."""
    collector = advisory_feed.Collector()
    for ident in idents:
        record = _record(ident)
        for ecosystem in sorted({a["package"]["ecosystem"] for a in record["affected"]}):
            collector.add(ecosystem, record)
    collector.write(now=NOW)


def _feed_hits(root: Path) -> dict[str, Severity]:
    """The advisory ids AAK-KNOWN-VULN-001 reports for `root` after the engine's passes."""
    return {i: f.severity for f in run_scan(root).findings if f.rule_id == KNOWN
            for i in (*FEED_ONLY, OC_3X84, SDK_F897, PR_26MH) if i in f.evidence}


def _ids(root: Path) -> set[str]:
    return {f.rule_id for f in run_scan(root).findings}


def _npm_lock(root: Path, **pkgs: str) -> Path:
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": dict(pkgs)},
        **{f"node_modules/{name}": {"version": v} for name, v in pkgs.items()}}}))
    return root


def _uv_lock(root: Path, name: str, version: str) -> Path:
    (root / "uv.lock").write_text(f'version = 1\n\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
                                  'source = { registry = "https://pypi.org/simple" }\n')
    return root


def test_the_saved_records_are_osv_s_unedited() -> None:
    for ident in (*FEED_ONLY, OC_3X84, SDK_F897, PR_26MH):
        record = _record(ident)
        assert record["id"] == ident and record["modified"].startswith("2026-10-")


# ---- next, better-auth, litellm: AAK-KNOWN-VULN-001, after `aak update` ------------------------

FEED_CASES = [
    (NEXT_2464, "ghsa-2464-fhr4-w9xw-next", Severity.CRITICAL, None),
    (NEXT_673Q, "ghsa-673q-mjm6-r5xr-next", Severity.CRITICAL, None),
    (NEXT_P3M5, "cve-2026-94482-next", Severity.HIGH, "CVE-2026-94482"),
    (BA_965C, "cve-2026-110862-better-auth", Severity.CRITICAL, "CVE-2026-110862"),
    (BA_Q84F, "cve-2026-109346-better-auth", Severity.HIGH, "CVE-2026-109346"),
    (BA_R4XP, "cve-2026-110864-better-auth", Severity.HIGH, "CVE-2026-110864"),
    (BA_44JH, "cve-2026-110861-better-auth", Severity.MEDIUM, "CVE-2026-110861"),
    (LL_G5FF, "ghsa-g5ff-637f-6q2m-litellm", Severity.HIGH, None),
    (LL_HHWW, "ghsa-hhww-mrg2-969h-litellm", Severity.MEDIUM, None),
]


@pytest.mark.parametrize("ident,fixture,severity,cve", FEED_CASES, ids=[c[0] for c in FEED_CASES])
def test_the_record_reaches_the_advisory_feed_rule(ident: str, fixture: str, severity: Severity,
                                                   cve: str | None) -> None:
    _cache(*FEED_ONLY)
    found = [f for f in run_scan(CVES / fixture / "vulnerable").findings if f.rule_id == KNOWN and ident in f.evidence]
    assert len(found) == 1 and found[0].severity is severity
    assert cve is None or cve in found[0].evidence
    assert ident not in _feed_hits(CVES / fixture / "negative")


@pytest.mark.parametrize("ident,fixture,severity,cve", FEED_CASES, ids=[c[0] for c in FEED_CASES])
def test_without_aak_update_the_record_is_not_reported(ident: str, fixture: str, severity: Severity,
                                                       cve: str | None) -> None:
    """None is bundled, so the bundled feed says nothing of it."""
    text = advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    assert ident not in text and (cve is None or cve not in text)
    assert ident not in _feed_hits(CVES / fixture / "vulnerable")


def test_the_magic_link_finding_names_both_cve_records() -> None:
    """VulnCheck's CVE-2026-110862 and GitHub's CVE-2026-114607 are one advisory."""
    _cache(*FEED_ONLY)
    (found,) = [f for f in run_scan(CVES / "cve-2026-110862-better-auth" / "vulnerable").findings
                if f.rule_id == KNOWN and BA_965C in f.evidence]
    assert "CVE-2026-110862" in found.evidence and "CVE-2026-114607" in found.evidence


@pytest.mark.parametrize("version,expected", [
    ("9.5.5", set()), ("12.3.4", {NEXT_2464}), ("13.0.0", {NEXT_2464, NEXT_P3M5}),
    ("15.5.27", {NEXT_2464, NEXT_P3M5}), ("15.5.28", set()),
    ("16.0.0", {NEXT_2464, NEXT_673Q, NEXT_P3M5}), ("16.4.0", {NEXT_2464, NEXT_673Q, NEXT_P3M5}),
    ("16.4.1", set()),
])
def test_next_ranges(tmp_path: Path, version: str, expected: set[str]) -> None:
    _cache(*FEED_ONLY)
    assert set(_feed_hits(_npm_lock(tmp_path, next=version))) == expected


@pytest.mark.parametrize("version,expected", [
    ("1.3.8-beta.2", set()), ("1.4.0-beta.17", {BA_Q84F}), ("1.6.16", {BA_965C, BA_Q84F, BA_R4XP}),
    ("1.6.34", {BA_965C, BA_Q84F, BA_R4XP, BA_44JH}), ("1.7.0-rc.3", {BA_965C, BA_R4XP, BA_44JH}),
    ("1.7.6", {BA_965C, BA_R4XP, BA_44JH}), ("1.7.7", set()),
])
def test_better_auth_ranges(tmp_path: Path, version: str, expected: set[str]) -> None:
    """1.6.34, the release-1.6 line's newest, carries none of the fixes."""
    _cache(*FEED_ONLY)
    assert set(_feed_hits(_npm_lock(tmp_path, **{"better-auth": version}))) == expected


@pytest.mark.parametrize("name,version,fires", [
    ("@better-auth/drizzle-adapter", "1.6.16", False), ("@better-auth/drizzle-adapter", "1.7.6", True),
    ("@better-auth/drizzle-adapter", "1.7.7", False), ("@better-auth/kysely-adapter", "1.6.31", True),
    ("@better-auth/kysely-adapter", "1.7.0", False),
])
def test_the_rate_limit_record_reads_both_adapters(tmp_path: Path, name: str, version: str, fires: bool) -> None:
    _cache(*FEED_ONLY)
    assert (BA_44JH in _feed_hits(_npm_lock(tmp_path, **{name: version}))) is fires


@pytest.mark.parametrize("version,expected", [
    ("1.65.4", {LL_G5FF}), ("1.65.5", {LL_G5FF, LL_HHWW}), ("1.84.0", {LL_G5FF, LL_HHWW}),
    ("1.85.0", {LL_G5FF}), ("1.94.0", {LL_G5FF}), ("1.95.0", set()),
])
def test_litellm_ranges(tmp_path: Path, version: str, expected: set[str]) -> None:
    _cache(*FEED_ONLY)
    assert set(_feed_hits(_uv_lock(tmp_path, "litellm", version))) == expected


@pytest.mark.parametrize("rule_id", [NEXTJS, BA_RULE, *LITELLM])
def test_the_pins_on_those_packages_make_no_claim_on_these_records(rule_id: str) -> None:
    rule = RULES[rule_id]
    named = " ".join([rule.description, rule.limitations, *rule.cve_references, *rule.incident_references])
    for ident, _, _, cve in FEED_CASES:
        assert ident not in named and (cve is None or cve not in named)
    assert "CVE-2026-114607" not in named  # GitHub's CVE for GHSA-965c, beside VulnCheck's


def test_the_pin_floors_stay() -> None:
    floors = {p.rule_id: p.floor for p in mcp_cve_pins_2026_07._PINS
              if p.rule_id in (NEXTJS, BA_RULE, *LITELLM)}
    assert floors == {NEXTJS: (16, 3, 8), BA_RULE: (1, 6, 13), LITELLM[0]: (1, 84, 0), LITELLM[1]: (1, 100, 4)}


# ---- openclaw: CVE-2026-62197 joins the 2026.7.1 rule ----------------------------------------


def test_openclaw_rule_names_the_cdp_record() -> None:
    rule = RULES[OPENCLAW]
    assert "CVE-2026-62197" in rule.cve_references and "GHSA-3x84-qq85-fj65" in rule.description
    assert rule.severity is Severity.HIGH


def test_openclaw_fixtures_fire_and_stay_quiet() -> None:
    fixture = CVES / "cve-2026-62197-openclaw"
    (hit,) = [f for f in mcp_cve_pins_2026_07.scan(fixture / "vulnerable")[0] if f.rule_id == OPENCLAW]
    assert "CVE-2026-62197" in hit.cve_references and "CVE-2026-62197" in hit.evidence
    assert OPENCLAW not in _ids(fixture / "negative")


@pytest.mark.parametrize("version,fires", [("2026.6.5", True), ("2026.6.6", True), ("2026.7.1", False)])
def test_openclaw_releases_the_rule_reports(tmp_path: Path, version: str, fires: bool) -> None:
    """2026.6.6 has the CDP fix and is still reported for the rule's other records."""
    assert (OPENCLAW in _ids(_npm_lock(tmp_path, openclaw=version))) is fires


def test_after_aak_update_the_feed_stands_down_for_the_rule(tmp_path: Path) -> None:
    """The feed's record of the CVE is dropped on the line the rule reports it on."""
    _cache(OC_3X84)
    vulnerable = CVES / "cve-2026-62197-openclaw" / "vulnerable"
    assert any(OC_3X84 in f.evidence for f in known_vulns.scan(vulnerable)[0])
    assert OPENCLAW in _ids(vulnerable) and OC_3X84 not in _feed_hits(vulnerable)
    assert OC_3X84 not in _feed_hits(_npm_lock(tmp_path, openclaw="2026.6.6"))


# ---- praisonai: CVE-2026-61438 joins the 4.6.78 rule, with a stated gap -----------------------


def test_praisonai_rule_names_the_sandbox_record() -> None:
    rule = RULES[PRAISONAI]
    assert "CVE-2026-61438" in rule.cve_references and "GHSA-26mh-57q7-jfvr" in rule.description
    assert "PRAISONAI_ALLOW_JOB_WORKFLOWS" in rule.remediation
    assert all(s in rule.limitations for s in ("PyPI has no 4.6.78", "4.6.81 to 4.6.102", "`praisonai-code`"))
    assert rule.limitations.endswith("a lockfile entry keeps its line at any depth.")


def test_praisonai_below_the_floor_fires() -> None:
    assert PRAISONAI in _ids(CVES / "cve-2026-61438-praisonai" / "vulnerable")


def test_praisonai_4_6_81_is_not_reported_although_it_ships_the_executor() -> None:
    """The stated limitation: PyPI's next release after 4.6.77 is 4.6.81, and it still
    allows `import os` in `_exec_inline_python`. The record says 4.6.78 fixed it, so
    neither the rule nor the feed reports it."""
    _cache(PR_26MH)
    limitation = CVES / "cve-2026-61438-praisonai" / "limitation"
    assert PRAISONAI not in _ids(limitation) and PR_26MH not in _feed_hits(limitation)


def test_praisonai_feed_record_stands_down_for_the_rule() -> None:
    _cache(PR_26MH)
    vulnerable = CVES / "cve-2026-61438-praisonai" / "vulnerable"
    assert any(PR_26MH in f.evidence for f in known_vulns.scan(vulnerable)[0])
    assert PRAISONAI in _ids(vulnerable) and PR_26MH not in _feed_hits(vulnerable)


# ---- the MCP TypeScript SDK: GHSA-f897 joins the 111768 rule ----------------------------------


def test_the_sdk_rule_names_the_body_size_record() -> None:
    rule = RULES[TSSDK]
    assert rule.incident_references == [SDK_F897] and rule.cve_references == ["CVE-2026-111768"]
    assert "@modelcontextprotocol/node" in rule.limitations and "@modelcontextprotocol/hono" in rule.limitations


def test_the_sdk_fixtures_fire_and_stay_quiet() -> None:
    fixture = CVES / "ghsa-f897-62hf-6gxq-mcp-ts-sdk"
    assert TSSDK in _ids(fixture / "vulnerable") and TSSDK not in _ids(fixture / "negative")


@pytest.mark.parametrize("version,pin,feed", [
    ("1.9.0", True, False), ("1.10.0", True, True), ("1.30.0", True, True), ("1.30.1", True, False),
    ("1.32.0", False, False),
])
def test_the_record_s_sdk_range_sits_inside_the_rule_s(tmp_path: Path, version: str, pin: bool, feed: bool) -> None:
    _cache(SDK_F897)
    root = _npm_lock(tmp_path, **{"@modelcontextprotocol/sdk": version})
    assert (TSSDK in _ids(root)) is pin and (SDK_F897 in _feed_hits(root)) is feed


def test_a_record_without_a_cve_id_is_reported_beside_the_rule(tmp_path: Path) -> None:
    """The engine stands the feed down only on a shared CVE id, which this record has not."""
    _cache(SDK_F897)
    vulnerable = CVES / "ghsa-f897-62hf-6gxq-mcp-ts-sdk" / "vulnerable"
    assert TSSDK in _ids(vulnerable) and _feed_hits(vulnerable) == {SDK_F897: Severity.HIGH}


def test_the_adapters_are_the_feed_s_alone() -> None:
    fixture = CVES / "ghsa-f897-62hf-6gxq-mcp-ts-sdk"
    assert TSSDK not in _ids(fixture / "adapters-vulnerable")
    assert SDK_F897 not in _feed_hits(fixture / "adapters-vulnerable")  # not bundled
    _cache(SDK_F897)
    found = [f for f in run_scan(fixture / "adapters-vulnerable").findings
             if f.rule_id == KNOWN and SDK_F897 in f.evidence]
    assert len(found) == 2 and all(f.severity is Severity.HIGH for f in found)
    assert {name for f in found for name in ("@modelcontextprotocol/node", "@modelcontextprotocol/hono")
            if name in f.evidence} == {"@modelcontextprotocol/node", "@modelcontextprotocol/hono"}
    assert SDK_F897 not in _feed_hits(fixture / "adapters-negative")


# ---- the ledger --------------------------------------------------------------------------------


@pytest.mark.parametrize("issue,ident", [
    ("#1125", NEXT_2464), ("#1126", NEXT_673Q), ("#1134", "CVE-2026-94482"), ("#1127", "CVE-2026-110862"),
    ("#1135", "CVE-2026-109346"), ("#1142", "CVE-2026-110864"), ("#1148", "CVE-2026-110861"),
    ("#1128", "CVE-2026-62197"), ("#1129", LL_G5FF), ("#1143", LL_HHWW), ("#1141", SDK_F897),
    ("#1144", "CVE-2026-61438"),
])
def test_every_issue_has_a_ledger_row(issue: str, ident: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {ident} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| {issue} |")
    assert "out of scope" not in rows[0].lower()
