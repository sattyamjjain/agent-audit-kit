"""#1242 to #1245 and seven held VulnCheck records for npm `n8n` (2026-11-14).

VulnCheck published eleven n8n records on 13 Nov 2026 (CVE-2026-126381 to -126391). The
watcher filed four as `pin floor stale` against AAK-MCP-N8N-CVE-2026-72768-001, whose
floor is 2.41.4, and held seven. Each is decided on its own:

* CVE-2026-126386 (the MCP OAuth endpoints redirect to any registered client's URI) and
  CVE-2026-126387 (Instance AI's Browser Use serves an MCP tool that reads the server's
  files) are on n8n's MCP surface. Both are MEDIUM and fixed in the same releases, so
  they share a new rule, AAK-MCP-N8N-CVE-2026-126386-001. Raising the HIGH rule's floor
  would report 2.41.4 to 2.45.4 under flaws those releases do not have.
* The other nine are workflow nodes, a trigger, the credential OAuth callback, the
  outbound HTTP helper, the expression sandbox and the Docker image's GraphicsMagick.
  None is on n8n's MCP surface, so, as with the 2026-11-07 and 2026-11-11 n8n records,
  AAK-KNOWN-VULN-001 reports them after `aak update` and no pin moves.

Every fixed release was read in the published npm packages (n8n and the internal
packages it pins exactly) and, for the image record, in the Dockerfile at each release
tag. The NVD API records are saved unedited under tests/fixtures/nvd_cna, read on
2026-11-14. `CHANGELOG.cves.md` holds the reasoning.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit import advisory_feed, nvd_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import known_vulns, mcp_cve_pins_2026_07
from agent_audit_kit.scanners.known_vulns import evidence_cves

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
NVD_CNA = HERE / "fixtures" / "nvd_cna"
FIXTURE = HERE / "fixtures" / "cves" / "cve-2026-126386-n8n-mcp-oauth"
LEDGER = REPO / "CHANGELOG.cves.md"

FEED_RULE = "AAK-KNOWN-VULN-001"
N8N_MCP_PIN = "AAK-MCP-N8N-CVE-2026-126386-001"
N8N_HIGH_PIN = "AAK-MCP-N8N-CVE-2026-72768-001"
N8N_WEBHOOK_PIN = "AAK-MCP-N8N-CVE-2026-59207-001"
N8N_OAUTH_TRIGGER_PIN = "AAK-MCP-N8N-CVE-2026-65594-001"

OAUTH_REDIRECT = "CVE-2026-126386"
BROWSER_UPLOAD = "CVE-2026-126387"
PIN_CVES = [OAUTH_REDIRECT, BROWSER_UPLOAD]
FEED_CVES = [
    "CVE-2026-126381",  # Vector Store (OracleDB) metadata filter key
    "CVE-2026-126382",  # Asana Trigger webhook secret
    "CVE-2026-126383",  # MongoDB node update key (#1242)
    "CVE-2026-126384",  # GraphicsMagick in the Docker image (#1244)
    "CVE-2026-126385",  # dynamic-credential OAuth callback (#1243)
    "CVE-2026-126388",  # credentials on cross-origin redirects
    "CVE-2026-126389",  # Chat Trigger embedded chat
    "CVE-2026-126390",  # NocoDB attachment download
    "CVE-2026-126391",  # expression sandbox (#1245)
]
ALL_CVES = sorted(PIN_CVES + FEED_CVES)


def _record(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _entries(cve: str) -> list[dict[str, Any]]:
    return nvd_feed.record_entries(_record(cve), nvd_feed.load_package_map(), nvd_feed.Tally())


def _cache(*cves: str) -> None:
    """Write the records to the feed cache as `aak update` converts them (HOME is per test)."""
    entries = [entry for cve in cves for entry in _entries(cve)]
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": [],
                                "nvd": nvd_feed.merged(entries)}), encoding="utf-8")


def _lockfile(root: Path, version: str) -> Path:
    (root / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"node_modules/n8n": {"version": version}}}),
        encoding="utf-8")
    return root


def _feed(findings: list[Any]) -> dict[str, Severity]:
    return {cve: f.severity for f in findings if f.rule_id == FEED_RULE for cve in evidence_cves(f.evidence)}


def _pin_ids(root: Path) -> set[str]:
    return {f.rule_id for f in mcp_cve_pins_2026_07.scan(root)[0]}


def _package_json(root: Path, version: str) -> Path:
    (root / "package.json").write_text(json.dumps({"dependencies": {"n8n": version}}), encoding="utf-8")
    return root


# ---- the records -------------------------------------------------------------------------------


@pytest.mark.parametrize("cve", ALL_CVES)
def test_each_saved_record_names_npm_n8n_by_its_package_url(cve: str) -> None:
    vuln = _record(cve)
    assert vuln["cve"]["id"] == cve
    assert vuln["cve"]["sourceIdentifier"] == "disclosure@vulncheck.com"
    assert {(e["ecosystem"], e["name"], e["mapped_by"]) for e in _entries(cve)} == {("npm", "n8n", "packageURL")}


def test_the_records_end_each_line_where_the_advisories_do() -> None:
    """The CNA ranges `aak update` keeps, read from the saved records."""
    four_lines = [{"introduced": "0", "fixed": "1.123.89"}, {"introduced": "2.0.0", "fixed": "2.45.5"},
                  {"introduced": "2.46.0", "fixed": "2.46.1"}, {"introduced": "3.0.0", "fixed": "3.0.1"}]
    two_x = [{"introduced": "0", "fixed": "2.45.5"}, {"introduced": "2.46.0", "fixed": "2.46.1"},
             {"introduced": "3.0.0", "fixed": "3.0.1"}]

    def ranges(cve: str) -> list[dict[str, str]]:
        (entry,) = _entries(cve)
        return sorted(entry["ranges"], key=lambda r: r["introduced"])

    for cve in ("CVE-2026-126383", "CVE-2026-126384", OAUTH_REDIRECT, "CVE-2026-126389",
                "CVE-2026-126390", "CVE-2026-126391"):
        assert ranges(cve) == four_lines, cve
    for cve in ("CVE-2026-126385", BROWSER_UPLOAD, "CVE-2026-126388"):
        assert ranges(cve) == two_x, cve
    assert ranges("CVE-2026-126381") == [{"introduced": "0", "fixed": "2.43.5"},
                                         {"introduced": "2.44.0", "fixed": "2.44.1"},
                                         {"introduced": "3.0.0", "fixed": "3.0.1"}]
    assert ranges("CVE-2026-126382") == [{"introduced": "0", "fixed": "2.38.0"},
                                         {"introduced": "3.0.0", "fixed": "3.0.1"}]


# ---- CVE-2026-126386 and CVE-2026-126387: the new rule -----------------------------------------


def test_the_rule_is_registered_at_medium() -> None:
    rule = RULES[N8N_MCP_PIN]
    assert rule.severity is Severity.MEDIUM
    assert rule.category is Category.SUPPLY_CHAIN
    assert rule.cve_references == PIN_CVES
    for text in ("GHSA-rc3w-8jc8-7x3w", "GHSA-9qx8-fhxv-w794", "/mcp-oauth/register", "browser_upload"):
        assert text in rule.description
    assert "MCP07:2025" in rule.owasp_mcp_references
    assert "STA-08" in rule.aicm_references


def test_the_pin_row() -> None:
    (pin,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == N8N_MCP_PIN]
    assert pin.names == ("n8n",) and pin.ecosystem == "js"
    assert (pin.introduced, pin.floor) == ((1, 120, 0), (1, 123, 89))
    assert pin.also == (((2, 0, 0), (2, 45, 5)), ((2, 46, 0), (2, 46, 1)))
    assert pin.requires_version


def test_the_other_n8n_rules_keep_their_floors_and_claim_none_of_the_records() -> None:
    rows = {p.rule_id: (p.floor, p.also) for p in mcp_cve_pins_2026_07._PINS
            if p.rule_id in (N8N_HIGH_PIN, N8N_WEBHOOK_PIN)}
    assert rows == {N8N_HIGH_PIN: ((2, 41, 4), (((2, 42, 0), (2, 42, 1)),)),
                    N8N_WEBHOOK_PIN: ((2, 41, 4), (((2, 42, 0), (2, 42, 1)),))}
    named = {cve: rule_id for rule_id, rule in RULES.items() for cve in rule.cve_references if cve in ALL_CVES}
    assert named == {OAUTH_REDIRECT: N8N_MCP_PIN, BROWSER_UPLOAD: N8N_MCP_PIN}


@pytest.mark.parametrize(("tree", "fires"), [("vulnerable", True), ("negative", False)])
def test_fixtures(tree: str, fires: bool) -> None:
    found = [f for f in mcp_cve_pins_2026_07.scan(FIXTURE / tree)[0] if f.rule_id == N8N_MCP_PIN]
    assert bool(found) is fires
    if fires:
        assert [(f.file_path, f.severity) for f in found] == [("package.json", Severity.MEDIUM)]


def test_the_finding_survives_the_full_engine() -> None:
    """2.45.4 is above every older n8n floor, so the new rule is the only n8n finding."""
    found = {f.rule_id: f.severity for f in run_scan(FIXTURE / "vulnerable").findings if "N8N" in f.rule_id}
    assert found == {N8N_MCP_PIN: Severity.MEDIUM}


@pytest.mark.parametrize(("version", "fires"), [
    ("1.119.2", False),   # no MCP OAuth endpoints, no Browser Use
    ("1.120.0", True),    # the MCP OAuth endpoints first ship
    ("1.123.88", True),
    ("1.123.89", False),  # the 1.x fix
    ("1.123.96", False),
    ("2.0.0", True),
    ("2.28.7", True),     # the open redirect only
    ("2.29.0", True),     # Browser Use first ships (@n8n/mcp-browser 0.12.0)
    ("2.41.4", True),     # the HIGH rule's floor
    ("2.45.4", True),
    ("2.45.5", False),    # the fix: the authorization-request check, mcp-browser 0.25.1
    ("2.45.7", False),
    ("2.46.0", True),     # newer than 2.45.5 and still affected
    ("2.46.1", False),
    ("2.47.7", False),    # latest on 2026-11-14
    ("^2.45.5", True),    # admits 2.46.0
    ("^2.46.1", False),
    (">=2.47.0", False),
    ("3.0.0", False),     # npm has no 3.x release; the records' 3.0.0 is not reported
    ("latest", False),    # resolves to a fixed release: a stated version is required
    ("*", False),
])
def test_versions(tmp_path: Path, version: str, fires: bool) -> None:
    assert (N8N_MCP_PIN in _pin_ids(_package_json(tmp_path, version))) is fires


def test_an_unversioned_n8n_is_reported_by_three_rules_not_four(tmp_path: Path) -> None:
    ids = {i for i in _pin_ids(_package_json(tmp_path, "latest")) if i.startswith("AAK-MCP-N8N-")}
    assert ids == {N8N_WEBHOOK_PIN, N8N_OAUTH_TRIGGER_PIN, N8N_HIGH_PIN}


@pytest.mark.parametrize(("version", "rule", "feed"), [
    ("1.119.2", False, {OAUTH_REDIRECT, BROWSER_UPLOAD}),  # the records start at the first release
    ("1.123.88", True, set()),
    ("1.123.89", False, {BROWSER_UPLOAD}),  # its record names no 1.x fix; 1.x has no Browser Use
    ("2.45.4", True, set()),
    ("2.46.0", True, set()),
    ("2.46.1", False, set()),
])
def test_after_aak_update_the_feed_stands_down_where_the_rule_reports(
        tmp_path: Path, version: str, rule: bool, feed: set[str]) -> None:
    _cache(*PIN_CVES)
    root = _lockfile(tmp_path, version)
    findings = run_scan(root).findings
    assert (N8N_MCP_PIN in {f.rule_id for f in findings}) is rule
    assert set(_feed(findings)) == feed
    if rule:  # the feed did find both; the engine dropped them for the rule's finding
        raw = {cve for f in known_vulns.scan(root)[0] if f.rule_id == FEED_RULE for cve in evidence_cves(f.evidence)}
        assert raw == set(PIN_CVES)


# ---- the other nine: the advisory feed after `aak update` --------------------------------------

_FOUR_LINES = [("1.123.88", True), ("1.123.89", False), ("2.41.4", True), ("2.45.4", True),
               ("2.45.5", False), ("2.46.0", True), ("2.46.1", False), ("2.47.7", False)]
_TWO_X = [("1.123.89", True), ("2.45.4", True), ("2.45.5", False), ("2.46.0", True),
          ("2.46.1", False), ("2.47.7", False)]
_CASES = (
    [(cve, v, fires) for cve in ("CVE-2026-126383", "CVE-2026-126384", "CVE-2026-126389",
                                 "CVE-2026-126390", "CVE-2026-126391") for v, fires in _FOUR_LINES]
    + [(cve, v, fires) for cve in ("CVE-2026-126385", "CVE-2026-126388") for v, fires in _TWO_X]
    # OracleDB vector store: below 2.43.5 and 2.44.0 below 2.44.1.
    + [("CVE-2026-126381", v, fires) for v, fires in [
        ("1.123.89", True), ("2.43.4", True), ("2.43.5", False), ("2.44.0", True), ("2.44.1", False),
        ("2.45.4", False)]]
    # Asana Trigger: below 2.38.0.
    + [("CVE-2026-126382", v, fires) for v, fires in [
        ("1.123.89", True), ("2.37.11", True), ("2.38.0", False), ("2.45.4", False)]]
)
_SEVERITY = {"CVE-2026-126383": Severity.HIGH, "CVE-2026-126384": Severity.HIGH,
             "CVE-2026-126385": Severity.HIGH, "CVE-2026-126391": Severity.HIGH,
             "CVE-2026-126381": Severity.MEDIUM, "CVE-2026-126382": Severity.MEDIUM,
             "CVE-2026-126388": Severity.MEDIUM, "CVE-2026-126389": Severity.MEDIUM,
             "CVE-2026-126390": Severity.MEDIUM}


@pytest.mark.parametrize(("cve", "version", "fires"), _CASES)
def test_each_record_reaches_the_advisory_feed_rule(tmp_path: Path, cve: str, version: str, fires: bool) -> None:
    _cache(cve)
    found = _feed(run_scan(_lockfile(tmp_path, version)).findings)
    assert (cve in found) is fires
    if fires:
        assert found[cve] is _SEVERITY[cve]


def test_at_2_45_4_the_feed_reports_seven_and_the_new_rule_two(tmp_path: Path) -> None:
    """2.45.4 is above every older n8n floor: no older pin reports it."""
    _cache(*ALL_CVES)
    findings = run_scan(_lockfile(tmp_path, "2.45.4")).findings
    assert sorted(_feed(findings)) == [
        "CVE-2026-126383", "CVE-2026-126384", "CVE-2026-126385", "CVE-2026-126388",
        "CVE-2026-126389", "CVE-2026-126390", "CVE-2026-126391"]
    assert {f.rule_id for f in findings if "N8N" in f.rule_id} == {N8N_MCP_PIN}


def test_without_aak_update_none_is_reported(tmp_path: Path) -> None:
    findings = run_scan(_lockfile(tmp_path, "2.45.4")).findings
    assert not set(_feed(findings)) & set(ALL_CVES)


def test_the_bundled_feed_holds_none_of_the_records() -> None:
    """The bundled feed is held to the pins (tests/test_pin_floors_vs_advisories.py)."""
    text = advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    assert [cve for cve in ALL_CVES if cve in text] == []


# ---- CVE-2026-126384: the image is not read ----------------------------------------------------


def test_the_n8n_image_reference_is_not_read(tmp_path: Path) -> None:
    """The GraphicsMagick fix is in the official image (the n8n Dockerfile at 1.123.89, 2.45.5
    and 2.46.1 removes five coders), but no AAK reader takes the `n8nio/n8n` image's tag, even
    with every record cached: only an npm declaration of `n8n` is reported."""
    _cache(*ALL_CVES)
    (tmp_path / "compose.yaml").write_text(
        "services:\n  n8n:\n    image: n8nio/n8n:2.45.4\n"
        "  mirror:\n    image: docker.n8n.io/n8nio/n8n:2.45.4\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM n8nio/n8n:2.45.4\n", encoding="utf-8")
    findings = run_scan(tmp_path).findings
    assert not [f for f in findings if "N8N" in f.rule_id or set(evidence_cves(f.evidence)) & set(ALL_CVES)]
    assert "`n8nio/n8n`" in RULES[N8N_MCP_PIN].limitations


# ---- the watcher -------------------------------------------------------------------------------


def _watcher() -> Any:
    spec = importlib.util.spec_from_file_location("cve_watcher_n8n_1114", REPO / "scripts" / "cve_watcher.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_watcher_reads_the_new_row_and_files_none_of_the_records_again(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """`pin floor stale` compares a record's range with every `_Pin` row naming the package.
    With the new row read, the only releases the eleven records list that no n8n row reports
    are the 3.x line, which npm does not have, and the ledger names all eleven, so the
    watcher never files one of them again."""
    w = _watcher()
    rows = [r for r in w.pin_rows() if r.names_package("npm", "n8n")]
    (row,) = [r for r in rows if r.rule_id == N8N_MCP_PIN]
    assert (row.floor, row.introduced, row.also) == (
        (1, 123, 89), (1, 120, 0), (((2, 0, 0), (2, 45, 5)), ((2, 46, 0), (2, 46, 1))))
    for cve in ALL_CVES:
        (entry,) = _entries(cve)
        found = w.stale_pin(entry, rows)
        assert found is not None and "no release of it from 3.0.0 up" in found[1], cve
    monkeypatch.setattr(w, "CHANGELOG_PATH", LEDGER)
    assert set(ALL_CVES) <= w._already_tracked()


# ---- the ledger --------------------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "issue"), [
    ("CVE-2026-126381", "not filed"), ("CVE-2026-126382", "not filed"), ("CVE-2026-126383", "#1242"),
    ("CVE-2026-126384", "#1244"), ("CVE-2026-126385", "#1243"), (OAUTH_REDIRECT, "not filed"),
    (BROWSER_UPLOAD, "not filed"), ("CVE-2026-126388", "not filed"), ("CVE-2026-126389", "not filed"),
    ("CVE-2026-126390", "not filed"), ("CVE-2026-126391", "#1245"),
])
def test_every_record_has_one_ledger_row(cve: str, issue: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| {issue} |")
    assert "out of scope" not in rows[0].lower()
    assert (N8N_MCP_PIN in rows[0]) is (cve in PIN_CVES)
