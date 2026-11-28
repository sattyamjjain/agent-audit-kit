"""2026-11-28 intake: five VulnCheck records of 27 Nov 2026 on MCP servers.

CVE-2026-138026 (Crypto APIs' fourteen @cryptoapis-io/mcp-* servers), CVE-2026-138027 (bagel-mcp),
CVE-2026-138032 (WhoDB's CLI) and CVE-2026-138033 (mcp-video-analyzer) are version pins; WhoDB's
binary and Docker Hub image are also a launch row for AAK-KNOWN-VULN-002. CVE-2026-138034
(bigcommerce-api-mcp) is out of scope: the project publishes no package, no image and no tag of an
affected release. Ranges were read in the npm tarballs, the wheels and WhoDB's tags; NVD's records
are saved unedited under tests/fixtures/nvd_cna as the API returned them on 2026-11-28, and
`CHANGELOG.cves.md` holds the reasoning. Nothing here touches the network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit import advisory_feed, nvd_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_cve_pins_2026_07

CRYPTO_PIN = "AAK-MCP-CRYPTOAPIS-CVE-2026-138026-001"
BAGEL_PIN = "AAK-MCP-BAGEL-CVE-2026-138027-001"
WHODB_PIN = "AAK-MCP-WHODB-CVE-2026-138032-001"
VIDEO_PIN = "AAK-MCP-VIDEOANALYZER-CVE-2026-138033-001"
KNOWN, KNOWN_LAUNCH = "AAK-KNOWN-VULN-001", "AAK-KNOWN-VULN-002"
CRYPTO, BAGEL, WHODB, VIDEO, BIGCOMMERCE = (
    "CVE-2026-138026", "CVE-2026-138027", "CVE-2026-138032", "CVE-2026-138033", "CVE-2026-138034")

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
LEDGER = HERE.parent / "CHANGELOG.cves.md"

PIN_RULES: dict[str, tuple[str, Severity, str, list[str]]] = {
    CRYPTO_PIN: (CRYPTO, Severity.HIGH, "cve-2026-138026-cryptoapis", ["MCP07:2025", "MCP04:2025"]),
    BAGEL_PIN: (BAGEL, Severity.HIGH, "cve-2026-138027-bagel-mcp", ["MCP02:2025", "MCP05:2025", "MCP04:2025"]),
    WHODB_PIN: (WHODB, Severity.MEDIUM, "cve-2026-138032-whodb", ["MCP02:2025", "MCP05:2025", "MCP04:2025"]),
    VIDEO_PIN: (VIDEO, Severity.MEDIUM, "cve-2026-138033-mcp-video-analyzer", ["MCP05:2025", "MCP04:2025"]),
}

# (package, first release, last affected release, its own fix, `latest` on 2026-11-28), from npm's
# registry; every fix is the package's 2026-09-24 release, as the CNA record and the vendor's
# GHSA-mhj6-wq83-cqf5 name it.
CRYPTO_PACKAGES = [
    ("@cryptoapis-io/mcp-address-history", "0.1.0", "0.3.1", "0.4.0", "0.5.0"),
    ("@cryptoapis-io/mcp-address-latest", "0.1.0", "0.3.1", "0.4.0", "0.5.0"),
    ("@cryptoapis-io/mcp-aml", "0.1.0", "0.1.0", "0.2.0", "0.4.0"),
    ("@cryptoapis-io/mcp-block-data", "0.1.0", "0.3.0", "0.4.0", "0.5.0"),
    ("@cryptoapis-io/mcp-blockchain-events", "0.1.0", "0.4.0", "0.5.0", "0.6.0"),
    ("@cryptoapis-io/mcp-blockchain-fees", "0.1.0", "0.4.0", "0.5.0", "0.6.0"),
    ("@cryptoapis-io/mcp-broadcast", "0.1.0", "0.4.0", "0.5.0", "0.6.0"),
    ("@cryptoapis-io/mcp-contracts", "0.1.0", "0.3.0", "0.4.0", "0.5.0"),
    ("@cryptoapis-io/mcp-hd-wallet", "0.1.0", "0.3.1", "0.4.0", "0.5.0"),
    ("@cryptoapis-io/mcp-market-data", "0.1.0", "0.3.0", "0.4.0", "0.5.0"),
    ("@cryptoapis-io/mcp-prepare-transactions", "0.1.0", "0.4.0", "0.5.0", "0.6.0"),
    ("@cryptoapis-io/mcp-simulate", "0.1.0", "0.3.1", "0.4.0", "0.5.0"),
    ("@cryptoapis-io/mcp-transactions-data", "0.1.0", "0.3.0", "0.4.0", "0.5.0"),
    ("@cryptoapis-io/mcp-utils", "0.1.0", "0.3.0", "0.4.0", "0.5.0"),
]


def _nvd(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _pin_ids(root: Path) -> list[str]:
    return [f.rule_id for f in mcp_cve_pins_2026_07.scan(root)[0]]


def _write(root: Path, name: str, text: str) -> Path:
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(text, encoding="utf-8")
    return root


def _mcp(root: Path, command: str, args: list[str]) -> Path:
    return _write(root, ".mcp.json", json.dumps({"mcpServers": {"s": {"command": command, "args": args}}}, indent=2))


def _package_json(root: Path, deps: dict[str, str]) -> Path:
    return _write(root, "package.json", json.dumps({"name": "p", "dependencies": deps}, indent=2))


def _cache(nvd: list[dict[str, Any]], launch: list[dict[str, Any]]) -> None:
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "entries": [], "nvd": nvd,
                                "launch": launch}), encoding="utf-8")


# ---- the saved records ----------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "opening"), [
    (CRYPTO, "Crypto APIs MCP server packages (@cryptoapis-io/mcp-*) before 0.4.0, mcp-blockchain-events"),
    (BAGEL, "Bagel (bagel-mcp) before 2.5.5 exposes unsandboxed DuckDB SQL execution"),
    (WHODB, "WhoDB from 0.88.0 before 0.132.0 contains an access control bypass in the MCP whodb_query tool"),
    (VIDEO, "mcp-video-analyzer 0.2.0 before 0.10.1 contains a server-side request forgery vulnerability"),
    (BIGCOMMERCE, "bigcommerce-api-mcp before 1.0.1 contains a missing authentication vulnerability"),
])
def test_each_saved_nvd_record_is_the_one_read(cve: str, opening: str) -> None:
    record = _nvd(cve)["cve"]
    assert record["id"] == cve
    (text,) = [d["value"] for d in record["descriptions"] if d["lang"] == "en"]
    assert text.startswith(opening)


def test_the_crypto_apis_record_names_fourteen_packages_each_with_its_own_fix() -> None:
    affected = _nvd(CRYPTO)["cve"]["affected"]
    named = {}
    for block in affected:
        for data in block["affectedData"]:
            (version,) = data["versions"]
            named[nvd_feed.purl_package(data["packageURL"])[1]] = (version["version"], version["lessThan"])
    assert named == {name: ("0", fix) for name, _first, _last, fix, _latest in CRYPTO_PACKAGES}


# ---- the rules and their fixtures -----------------------------------------------------------


@pytest.mark.parametrize("rule_id", sorted(PIN_RULES))
def test_rule_metadata(rule_id: str) -> None:
    cve, severity, _fixture, owasp_mcp = PIN_RULES[rule_id]
    rule = RULES[rule_id]
    assert rule.cve_references == [cve]
    assert rule.severity is severity
    assert rule.owasp_mcp_references == owasp_mcp
    assert "ASI04" in rule.owasp_agentic_references


@pytest.mark.parametrize("rule_id", sorted(PIN_RULES))
def test_fixture_pair(rule_id: str) -> None:
    _cve, _severity, fixture, _owasp = PIN_RULES[rule_id]
    vulnerable = [f for f in run_scan(CVES / fixture / "vulnerable").findings if f.rule_id == rule_id]
    assert len(vulnerable) == 1 and vulnerable[0].line_number is not None
    assert rule_id not in {f.rule_id for f in run_scan(CVES / fixture / "negative").findings}


def test_the_crypto_apis_rows_are_the_records_packages_and_fixes() -> None:
    rows = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == CRYPTO_PIN]
    assert [(p.names, p.floor, p.introduced, p.requires_version, p.ecosystem) for p in rows] == [
        ((name,), tuple(int(x) for x in fix.split(".")), None, True, "js")
        for name, _first, _last, fix, _latest in CRYPTO_PACKAGES]


# ---- Crypto APIs, CVE-2026-138026 -----------------------------------------------------------


@pytest.mark.parametrize(("name", "first", "last", "fix", "latest"), CRYPTO_PACKAGES)
def test_crypto_apis_launches_fire_up_to_each_packages_own_fix(
    tmp_path: Path, name: str, first: str, last: str, fix: str, latest: str,
) -> None:
    fired = {v: CRYPTO_PIN in _pin_ids(_mcp(tmp_path / v, "npx", ["-y", f"{name}@{v}", "--transport", "http"]))
             for v in (first, last, fix, latest)}
    assert fired == {first: True, last: True, fix: False, latest: False}


@pytest.mark.parametrize(("deps", "fires"), [
    ({"@cryptoapis-io/mcp-blockchain-events": "0.4.0"}, True),   # 0.4.0 is another package's fix
    ({"@cryptoapis-io/mcp-aml": "0.2.0"}, False),                # below the others' 0.4.0, at its own
    ({"@cryptoapis-io/mcp-utils": "^0.3.0"}, True),              # a range that admits an affected version
    ({"@cryptoapis-io/mcp-utils": "^0.4.0"}, False),
    ({"@cryptoapis-io/mcp-shared": "0.3.2"}, False),             # not named by the record
])
def test_crypto_apis_package_json(tmp_path: Path, deps: dict[str, str], fires: bool) -> None:
    assert (CRYPTO_PIN in _pin_ids(_package_json(tmp_path, deps))) is fires


def test_crypto_apis_unversioned_launch_is_not_reported(tmp_path: Path) -> None:
    """Every package's `latest` is fixed, so the README's `npx -y @cryptoapis-io/mcp-utils` states none."""
    assert CRYPTO_PIN not in _pin_ids(_mcp(tmp_path, "npx", ["-y", "@cryptoapis-io/mcp-utils"]))


def test_crypto_apis_reports_each_package_once_per_file(tmp_path: Path) -> None:
    root = _package_json(tmp_path, {"@cryptoapis-io/mcp-utils": "0.3.0",
                                    "@cryptoapis-io/mcp-broadcast": "0.4.0",
                                    "@cryptoapis-io/mcp-aml": "0.2.0"})
    found = sorted(f.evidence.split(" referenced")[0] for f in mcp_cve_pins_2026_07.scan(root)[0]
                   if f.rule_id == CRYPTO_PIN)
    assert found == ["@cryptoapis-io/mcp-broadcast", "@cryptoapis-io/mcp-utils"]


def test_crypto_apis_lockfile_entry_is_judged(tmp_path: Path) -> None:
    lock = {"name": "p", "lockfileVersion": 3, "packages": {
        "": {"dependencies": {"@cryptoapis-io/mcp-hd-wallet": "0.3.1"}},
        "node_modules/@cryptoapis-io/mcp-hd-wallet": {"version": "0.3.1"}}}
    assert CRYPTO_PIN in _pin_ids(_write(tmp_path, "package-lock.json", json.dumps(lock, indent=2)))


# ---- bagel-mcp, CVE-2026-138027 -------------------------------------------------------------


@pytest.mark.parametrize(("line", "fires"), [
    ("bagel-mcp==2.5.1", True),    # the first release on PyPI
    ("bagel-mcp==2.5.4", True),
    ("bagel-mcp==2.5.5", False),
    ("bagel-mcp==2.5.6", False),   # `latest` on 2026-11-28
    ("bagel-mcp>=2.5.0", True),    # a range that admits an affected version
    ("bagel-mcp", False),          # `latest` is fixed, so a version must be stated
    ("bagel_mcp==2.5.4", True),    # PEP 503 name
    ("bagel==0.11.7", False),      # Neurobagel's package, another project
])
def test_bagel_requirements(tmp_path: Path, line: str, fires: bool) -> None:
    assert (BAGEL_PIN in _pin_ids(_write(tmp_path, "requirements.txt", line + "\n"))) is fires


@pytest.mark.parametrize(("command", "args", "fires"), [
    ("uvx", ["bagel-mcp==2.5.4"], True),
    ("uvx", ["--from", "bagel-mcp[ros]==2.5.4", "bagel-mcp", "--transport", "stdio"], True),
    ("uvx", ["--from", "bagel-mcp[ros]", "bagel-mcp", "--transport", "stdio"], False),  # the README's
    ("uvx", ["bagel-mcp==2.5.5"], False),
    ("npx", ["-y", "bagel-mcp@2.5.4"], False),   # not an npm name; the pin is PyPI's
])
def test_bagel_launches(tmp_path: Path, command: str, args: list[str], fires: bool) -> None:
    assert (BAGEL_PIN in _pin_ids(_mcp(tmp_path, command, args))) is fires


def test_bagel_npm_manifest_is_not_judged(tmp_path: Path) -> None:
    assert BAGEL_PIN not in _pin_ids(_package_json(tmp_path, {"bagel-mcp": "2.5.4"}))


# ---- WhoDB, CVE-2026-138032 -----------------------------------------------------------------


@pytest.mark.parametrize(("spec", "fires"), [
    ("@clidey/whodb-cli@0.87.0", False),   # checks no statement; outside the record's range
    ("@clidey/whodb-cli@0.88.0", True),
    ("@clidey/whodb-cli@0.131.0", True),
    ("@clidey/whodb-cli@0.132.0", False),
    ("@clidey/whodb-cli@0.139.0", False),  # `latest` on 2026-11-28
    ("@clidey/whodb-cli", False),          # `latest` is fixed, so a version must be stated
    # Every wrapper release requires exactly @clidey/whodb-cli at its own number (npm's registry,
    # 2026-11-28), so a wrapper's version is the CLI's: 0.127.0 is the first affected one.
    ("@clidey/whodb@0.127.0", True),
    ("@clidey/whodb@0.131.0", True),
    ("@clidey/whodb@0.132.0", False),
    ("whodb@0.127.0", True),
    ("whodb@0.131.0", True),
    ("whodb@0.132.0", False),
    ("whodb@0.1.0", False),                # requires @clidey/whodb-cli 0.1.0, which ships no binary
    ("@clidey/whodb-cli@0.1.0", False),
])
def test_whodb_launches(tmp_path: Path, spec: str, fires: bool) -> None:
    assert (WHODB_PIN in _pin_ids(_mcp(tmp_path, "npx", ["-y", spec, "mcp", "serve"]))) is fires


def test_whodb_binary_by_name_is_not_the_pins(tmp_path: Path) -> None:
    """`"command": "whodb"` states no release; the launch row reports it (below), not the pin."""
    assert WHODB_PIN not in _pin_ids(_mcp(tmp_path, "whodb", ["mcp", "serve"]))


def test_whodb_pypi_name_is_not_judged(tmp_path: Path) -> None:
    assert WHODB_PIN not in _pin_ids(_write(tmp_path, "requirements.txt", "whodb==0.131.0\n"))


def test_whodb_lockfile_with_wrapper_and_cli_reports_once(tmp_path: Path) -> None:
    lock = {"name": "p", "lockfileVersion": 3, "packages": {
        "": {"dependencies": {"whodb": "0.131.0"}},
        "node_modules/whodb": {"version": "0.131.0"},
        "node_modules/@clidey/whodb-cli": {"version": "0.131.0"}}}
    assert _pin_ids(_write(tmp_path, "package-lock.json", json.dumps(lock, indent=2))).count(WHODB_PIN) == 1


# ---- mcp-video-analyzer, CVE-2026-138033 ----------------------------------------------------


@pytest.mark.parametrize(("spec", "fires"), [
    ("mcp-video-analyzer@0.2.0", True),    # the first release, the record's lower bound
    ("mcp-video-analyzer@0.10.0", True),
    ("mcp-video-analyzer@0.10.1", False),
    ("mcp-video-analyzer@0.12.0", False),  # `latest` on 2026-11-28
    ("mcp-video-analyzer", False),         # `latest` is fixed, so a version must be stated
])
def test_video_analyzer_launches(tmp_path: Path, spec: str, fires: bool) -> None:
    assert (VIDEO_PIN in _pin_ids(_mcp(tmp_path, "npx", ["-y", spec]))) is fires


@pytest.mark.parametrize(("name", "text"), [
    ("requirements.txt", "mcp-video-analyzer==0.10.0\n"),
    (".mcp.json", json.dumps({"mcpServers": {"s": {"command": "uvx", "args": ["mcp-video-analyzer==0.10.0"]}}})),
])
def test_video_analyzer_pypi_forms_are_not_judged(tmp_path: Path, name: str, text: str) -> None:
    assert VIDEO_PIN not in _pin_ids(_write(tmp_path, name, text))


# ---- the advisory feed --------------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "pin", "packages", "name", "text"), [
    (CRYPTO, CRYPTO_PIN, [("npm", name) for name, *_ in CRYPTO_PACKAGES], "package.json",
     json.dumps({"dependencies": {"@cryptoapis-io/mcp-blockchain-events": "0.4.0"}}, indent=2)),
    (BAGEL, BAGEL_PIN, [("PyPI", "bagel-mcp")], "requirements.txt", "bagel-mcp==2.5.4\n"),
    (VIDEO, VIDEO_PIN, [("npm", "mcp-video-analyzer")], "package.json",
     json.dumps({"dependencies": {"mcp-video-analyzer": "0.10.0"}}, indent=2)),
])
def test_the_advisory_feed_stands_down_for_each_pin(
    tmp_path: Path, cve: str, pin: str, packages: list[tuple[str, str]], name: str, text: str,
) -> None:
    """The CNA record's packageURL maps it to the registry, so `aak update` carries it and
    AAK-KNOWN-VULN-001 would report it; on the line the pin reports, it stands down."""
    rows = nvd_feed.load_package_map()
    assert [(e, n) for e, n, _ in nvd_feed.record_packages(_nvd(cve), rows)] == packages
    _cache(nvd_feed.merged(nvd_feed.record_entries(_nvd(cve), rows, nvd_feed.Tally())), [])
    root = _write(tmp_path, name, text)
    findings = run_scan(root).findings
    assert [f.rule_id for f in findings if f.rule_id in (pin, KNOWN)] == [pin]
    # The feed entry is live: with the pin's rule left out, the feed reports the same line.
    (line,) = {f.line_number for f in findings if f.rule_id == pin}
    kept = run_scan(root, rules=[KNOWN]).findings
    assert [(f.rule_id, f.line_number) for f in kept if f.rule_id in (pin, KNOWN)] == [(KNOWN, line)]


def test_the_github_records_map_to_no_package() -> None:
    rows = nvd_feed.load_package_map()
    assert nvd_feed.record_packages(_nvd(WHODB), rows) == []
    assert nvd_feed.record_packages(_nvd(BIGCOMMERCE), rows) == []


def test_bigcommerce_maps_to_nothing_and_is_counted_unmapped() -> None:
    """No package, image or affected tag to match: the project is run from a clone."""
    tally = nvd_feed.Tally()
    assert nvd_feed.record_entries(_nvd(BIGCOMMERCE), nvd_feed.load_package_map(), tally,
                                   nvd_feed.load_launch_map()) == []
    assert tally.unmapped == 1 and tally.unmapped_pairs == {("isaacgounton", "bigcommerce-api-mcp"): 1}


# ---- WhoDB's launch row -------------------------------------------------------------------------


def _whodb_launch_entries() -> list[dict[str, Any]]:
    tally = nvd_feed.Tally()
    entries = nvd_feed.record_entries(_nvd(WHODB), nvd_feed.load_package_map(), tally, nvd_feed.load_launch_map())
    assert (tally.mapped, tally.launch, tally.entries) == (1, 1, 1)
    return nvd_feed.merged(entries)


def test_the_whodb_record_maps_to_its_launch_row() -> None:
    (entry,) = _whodb_launch_entries()
    assert (entry["ecosystem"], entry["name"], entry["ranges"], entry["fixed"], entry["severity"]) == (
        advisory_feed.LAUNCH, "clidey/whodb", [{"introduced": "0.88.0", "fixed": "0.132.0"}], ["0.132.0"], "MEDIUM")
    assert entry["match"] == {"commands": ["whodb", "whodb-cli"], "go_modules": [], "images": ["clidey/whodb-cli"]}


@pytest.mark.parametrize(("name", "text", "expected"), [
    (".mcp.json", {"command": "docker", "args": ["run", "-i", "--rm", "clidey/whodb-cli:0.131.0", "mcp", "serve"]},
     "launches clidey/whodb 0.131.0, which CVE-2026-138032"),
    (".mcp.json", {"command": "docker", "args": ["run", "-i", "--rm", "clidey/whodb-cli:0.90.0", "mcp", "serve"]},
     "launches clidey/whodb 0.90.0, which CVE-2026-138032"),   # the oldest tag on Docker Hub
    (".mcp.json", {"command": "docker", "args": ["run", "-i", "--rm", "clidey/whodb-cli:0.133.0", "mcp", "serve"]},
     None),
    (".mcp.json", {"command": "docker", "args": ["run", "-i", "--rm", "clidey/whodb-cli:latest", "mcp", "serve"]},
     "it is tagged `latest`"),
    (".mcp.json", {"command": "whodb", "args": ["mcp", "serve"]}, "starts the installed `whodb` binary"),
    (".mcp.json", {"command": "/opt/homebrew/bin/whodb-cli", "args": ["mcp", "serve"]},
     "starts the installed `whodb-cli` binary"),
    (".mcp.json", {"command": "docker", "args": ["run", "-i", "--rm", "clidey/whodb:0.131.0"]}, None),  # web app
    (".mcp.json", {"command": "npx", "args": ["-y", "@clidey/whodb-cli@0.131.0", "mcp", "serve"]}, None),  # the pin's
    ("compose.yaml", "services:\n  mcp:\n    image: clidey/whodb-cli:0.120.0\n",
     "launches clidey/whodb 0.120.0, which CVE-2026-138032"),
    ("compose.yaml", "services:\n  mcp:\n    image: clidey/whodb-cli:0.139.0\n", None),
])
def test_the_whodb_launch_row_after_a_cached_feed(tmp_path: Path, name: str, text: Any, expected: str | None) -> None:
    _cache([], _whodb_launch_entries())
    body = text if isinstance(text, str) else json.dumps({"mcpServers": {"whodb": text}}, indent=2)
    findings = [f for f in run_scan(_write(tmp_path, name, body)).findings if f.rule_id == KNOWN_LAUNCH]
    if expected is None:
        assert findings == []
    else:
        (finding,) = findings
        assert finding.severity is Severity.MEDIUM and expected in finding.evidence


def test_without_the_cached_feed_the_whodb_launch_is_not_reported(tmp_path: Path) -> None:
    """The bundled feed does not carry the record: `aak update` brings it."""
    root = _mcp(tmp_path, "docker", ["run", "-i", "--rm", "clidey/whodb-cli:0.131.0", "mcp", "serve"])
    assert KNOWN_LAUNCH not in {f.rule_id for f in run_scan(root).findings}


# ---- the ledger -----------------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "says"), [
    (CRYPTO, CRYPTO_PIN), (BAGEL, BAGEL_PIN), (WHODB, WHODB_PIN), (VIDEO, VIDEO_PIN),
    (BIGCOMMERCE, "**Out of scope**"),
])
def test_every_record_has_one_ledger_row(cve: str, says: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith("| not filed |") and says in rows[0]
