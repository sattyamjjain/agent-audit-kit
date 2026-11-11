"""#1224, #1225 and four held records: two MCP servers, four new rules.

Every range below was read in the published artifacts on 2026-11-11, not taken from
the advisory alone. The Dynatrace MCP server: every stable npm tarball from 0.1.0 to
2.1.2, the 0.5.0 release candidates through unpkg, and Docker's MCP catalog image
`mcp/dynatrace-mcp-server:latest`, whose /app/dist/index.js is byte-identical to
npm's 2.1.0 and which is not read, since it publishes only `latest`. Code Graph RAG: the PyPI wheels from 0.0.79 to 0.0.639 and 0.6.30, the
0.0.79 and 0.0.100 sdists, and the GHCR image at 0.0.88, 0.0.100, 0.0.496, 0.0.584
and 0.0.639 (the 0.0.99 and 0.0.534 images through the source at the commit their
labels name). The OSV records are saved unedited under tests/fixtures/osv, as
`https://api.osv.dev/v1/vulns/<id>` returned them on 2026-11-11. `CHANGELOG.cves.md`
holds the reasoning.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_audit_kit import advisory_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import container_image_pins, mcp_cve_pins_2026_07

DT_HTTP_RULE = "AAK-MCP-DYNATRACE-CVE-2026-123811-001"
DT_DQL_RULE = "AAK-MCP-DYNATRACE-CVE-2026-123810-001"
CGR_READ_RULE = "AAK-MCP-CODEGRAPHRAG-CVE-2026-77604-001"
CGR_SYMLINK_RULE = "AAK-MCP-CODEGRAPHRAG-CVE-2026-87008-001"
OUR_RULES = (DT_HTTP_RULE, DT_DQL_RULE, CGR_READ_RULE, CGR_SYMLINK_RULE)
KNOWN_RULE = "AAK-KNOWN-VULN-001"
DT = "@dynatrace-oss/dynatrace-mcp-server"
CGR_IMAGE = "ghcr.io/vitali87/code-graph-rag"

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CVES = FIXTURES / "cves"
OSV = FIXTURES / "osv"
LEDGER = Path(__file__).resolve().parent.parent / "CHANGELOG.cves.md"
NOW = datetime(2026, 11, 11, 9, 0, tzinfo=timezone.utc)

GHSA_HTTP, GHSA_WORKFLOW, GHSA_DQL, GHSA_NOTEBOOK = (
    "GHSA-p7w7-4929-vpj5", "GHSA-xrmj-5g4g-8987", "GHSA-pqh8-p93p-2rx7", "GHSA-pc2w-4mq8-32qw")
GHSA_READ, GHSA_SYMLINK = "GHSA-vvr2-h2jp-838m", "GHSA-85gg-2gfq-q95m"
RECORDS = (GHSA_HTTP, GHSA_WORKFLOW, GHSA_DQL, GHSA_NOTEBOOK, GHSA_READ, GHSA_SYMLINK)


def _ids(root: Path) -> set[str]:
    found = mcp_cve_pins_2026_07.scan(root)[0] + container_image_pins.scan(root)[0]
    return {f.rule_id for f in found}


def _write(tmp_path: Path, name: str, content: str) -> Path:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return tmp_path


def _package_json(tmp_path: Path, spec: str) -> Path:
    return _write(tmp_path, "package.json", json.dumps({"dependencies": {DT: spec}}))


def _npm_lock(tmp_path: Path, version: str) -> Path:
    return _write(tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {DT: version}},
        f"node_modules/{DT}": {"version": version}}}))


def _uv_lock(tmp_path: Path, version: str) -> Path:
    return _write(tmp_path, "uv.lock", f'version = 1\n\n[[package]]\nname = "code-graph-rag"\n'
                  f'version = "{version}"\nsource = {{ registry = "https://pypi.org/simple" }}\n')


def _launch(command: str, *args: str) -> str:
    return json.dumps({"mcpServers": {"s": {"command": command, "args": list(args)}}})


# ---- the rules ---------------------------------------------------------------------------------


@pytest.mark.parametrize(("rule_id", "severity", "cves"), [
    (DT_HTTP_RULE, Severity.HIGH, ["CVE-2026-123811"]),
    (DT_DQL_RULE, Severity.MEDIUM, ["CVE-2026-123810", "CVE-2026-123809", "CVE-2026-123812"]),
    (CGR_READ_RULE, Severity.HIGH, ["CVE-2026-77604"]),
    (CGR_SYMLINK_RULE, Severity.HIGH, ["CVE-2026-87008"]),
])
def test_rules_are_registered_at_their_severity(rule_id: str, severity: Severity, cves: list[str]) -> None:
    rule = RULES[rule_id]
    assert rule.severity is severity
    assert rule.category is Category.SUPPLY_CHAIN
    assert rule.cve_references == cves
    assert all(cve in rule.description for cve in cves)


def test_the_http_rule_says_stdio_is_not_exposed() -> None:
    """The version cannot tell how the server is launched, and the text says so."""
    rule = RULES[DT_HTTP_RULE]
    assert "The default stdio transport is not affected." in rule.description
    assert "It reads the version, not the transport" in rule.limitations


def test_the_pins_are_the_ranges_the_artifacts_show() -> None:
    """Dynatrace: `--http` first ships in 0.5.0 and 2.0.0 adds the token and the Host
    allowlist; 0.1.0, the first release, already puts `clusterId` into DQL, and 2.1.1
    escapes it. Code Graph RAG: the MCP server first ships in a PyPI file at 0.0.148,
    0.0.345 fixes read_file and has no structural tools, AstGrepService arrives in
    0.0.421 and 0.0.589 resolves symlinks; the two ranges are disjoint, one rule each.
    `latest` is fixed for both packages."""
    rows = [(p.rule_id, p.names, p.floor, p.introduced, p.also, p.requires_version, p.ecosystem)
            for p in mcp_cve_pins_2026_07._PINS if p.rule_id in OUR_RULES]
    assert rows == [
        (DT_HTTP_RULE, (DT,), (2, 0, 0), (0, 5, 0), (), True, "js"),
        (DT_DQL_RULE, (DT,), (2, 1, 1), None, (), True, "js"),
        (CGR_READ_RULE, ("code-graph-rag",), (0, 0, 345), (0, 0, 148), (), True, "py"),
        (CGR_SYMLINK_RULE, ("code-graph-rag",), (0, 0, 589), (0, 0, 421), (), True, "py"),
    ]


def test_the_image_rows() -> None:
    rows = [(p.rule_id, p.image, p.floor, p.introduced, p.floating_affected, p.cves)
            for p in container_image_pins._PINS if p.rule_id in OUR_RULES]
    assert rows == [
        (CGR_READ_RULE, CGR_IMAGE, (0, 0, 345), None, False, ("CVE-2026-77604",)),
        (CGR_SYMLINK_RULE, CGR_IMAGE, (0, 0, 589), (0, 0, 421), False, ("CVE-2026-87008",)),
    ]


# ---- fixtures ----------------------------------------------------------------------------------


@pytest.mark.parametrize(("fixture", "expected"), [
    # 1.8.5 is inside both Dynatrace ranges, so it gets both rules
    ("cve-2026-123811-dynatrace-mcp-http", {DT_HTTP_RULE, DT_DQL_RULE}),
    ("cve-2026-123810-dynatrace-mcp-dql", {DT_DQL_RULE}),             # 2.1.0
    ("cve-2026-123809-dynatrace-mcp-workflow", {DT_DQL_RULE}),        # 0.4.0, before --http
    ("cve-2026-123812-dynatrace-mcp-notebook", {DT_HTTP_RULE, DT_DQL_RULE}),   # 1.8.6
    ("cve-2026-77604-code-graph-rag", {CGR_READ_RULE}),               # 0.0.246
    ("cve-2026-87008-code-graph-rag-symlink", {CGR_SYMLINK_RULE}),    # 0.0.584
])
def test_fixtures_positive_and_negative(fixture: str, expected: set[str]) -> None:
    """Each `vulnerable*` tree fires exactly the expected rules from both tables, and
    every `negative*` tree stays quiet."""
    root = CVES / fixture
    vulnerable = sorted(p for p in root.iterdir() if p.name.startswith("vulnerable"))
    negatives = sorted(p for p in root.iterdir() if p.name.startswith("negative"))
    assert vulnerable and negatives
    for tree in vulnerable:
        assert _ids(tree) == expected, tree.name
    for tree in negatives:
        assert _ids(tree) == set(), tree.name


@pytest.mark.parametrize(("fixture", "tree", "where"), [
    ("cve-2026-123811-dynatrace-mcp-http", "vulnerable", {(DT_HTTP_RULE, ".mcp.json", 5),
                                                          (DT_DQL_RULE, ".mcp.json", 5)}),
    ("cve-2026-77604-code-graph-rag", "vulnerable", {(CGR_READ_RULE, "requirements.txt", 1)}),
    ("cve-2026-77604-code-graph-rag", "vulnerable-image", {(CGR_READ_RULE, "docker-compose.yml", 3)}),
    ("cve-2026-87008-code-graph-rag-symlink", "vulnerable", {(CGR_SYMLINK_RULE, "uv.lock", 5)}),
    ("cve-2026-87008-code-graph-rag-symlink", "vulnerable-image", {(CGR_SYMLINK_RULE, "docker-compose.yml", 3)}),
])
def test_findings_land_on_the_declaring_line(fixture: str, tree: str, where: set[tuple]) -> None:
    root = CVES / fixture / tree
    found = mcp_cve_pins_2026_07.scan(root)[0] + container_image_pins.scan(root)[0]
    assert {(f.rule_id, f.file_path, f.line_number) for f in found} == where


@pytest.mark.parametrize(("fixture", "severities"), [
    ("cve-2026-123811-dynatrace-mcp-http", {DT_HTTP_RULE: Severity.HIGH, DT_DQL_RULE: Severity.MEDIUM}),
    ("cve-2026-123810-dynatrace-mcp-dql", {DT_DQL_RULE: Severity.MEDIUM}),
    ("cve-2026-77604-code-graph-rag", {CGR_READ_RULE: Severity.HIGH}),
    ("cve-2026-87008-code-graph-rag-symlink", {CGR_SYMLINK_RULE: Severity.HIGH}),
])
def test_the_findings_survive_the_full_engine(fixture: str, severities: dict[str, Severity]) -> None:
    found = {f.rule_id: f.severity for f in run_scan(CVES / fixture / "vulnerable").findings
             if f.rule_id in OUR_RULES}
    assert found == severities


# ---- Dynatrace versions and references ---------------------------------------------------------


@pytest.mark.parametrize(("spec", "expected"), [
    ("0.1.0", {DT_DQL_RULE}),                  # the first release: clusterId into DQL, the workflow tool
    ("0.4.0", {DT_DQL_RULE}),                  # no HTTP mode yet
    ("0.5.0", {DT_HTTP_RULE, DT_DQL_RULE}),    # --http arrives
    ("1.2.0", {DT_HTTP_RULE, DT_DQL_RULE}),    # the notebook tool arrives, ungated
    ("1.8.7", {DT_HTTP_RULE, DT_DQL_RULE}),    # notebook gated; HTTP still open
    ("^1.8.0", {DT_HTTP_RULE, DT_DQL_RULE}),
    ("2.0.0", {DT_DQL_RULE}),                  # bearer token and Host allowlist; workflow tool removed
    ("2.1.0", {DT_DQL_RULE}),                  # still interpolates the DQL values
    (">=2.0.0", {DT_DQL_RULE}),
    ("2.1.1", set()),                          # validateTimeframe and escapeDqlStringValue
    ("2.1.2", set()),                          # the final release
    ("latest", set()),                         # resolves to 2.1.2
    ("*", set()),
])
def test_dynatrace_versions(tmp_path: Path, spec: str, expected: set[str]) -> None:
    assert _ids(_package_json(tmp_path, spec)) == expected


@pytest.mark.parametrize(("content", "expected"), [
    (_launch("npx", "-y", f"{DT}@1.8.5"), {DT_HTTP_RULE, DT_DQL_RULE}),
    (_launch("npx", "-y", f"{DT}@2.0.1"), {DT_DQL_RULE}),
    (_launch("npx", "-y", f"{DT}@latest"), set()),       # the README's launch
    (_launch("npx", "-y", DT), set()),
    (_launch("mcp-server-dynatrace"), set()),             # a global install, run by its bin name
    (_launch("docker", "run", "-i", "--rm", "mcp/dynatrace-mcp-server"), set()),   # catalog image, not read
])
def test_dynatrace_launches(tmp_path: Path, content: str, expected: set[str]) -> None:
    assert _ids(_write(tmp_path, ".mcp.json", content)) == expected


@pytest.mark.parametrize("image", [
    "mcp/dynatrace-mcp-server", "mcp/dynatrace-mcp-server:latest", "mcp/dynatrace-mcp-server:2.1.0",
    "docker.io/mcp/dynatrace-mcp-server",
])
def test_dynatrace_catalog_image_is_not_read(tmp_path: Path, image: str) -> None:
    """Docker's catalog image publishes only `latest`, a moving tag: once rebuilt from a
    fixed release, a pin on it would keep firing, and no project file says which build
    it pulled. So no image row reads it, whatever the tag."""
    root = _write(tmp_path, "docker-compose.yml", f"services:\n  dt:\n    image: {image}\n")
    assert _ids(root) == set()
    assert not any("dynatrace" in p.image for p in container_image_pins._PINS)


@pytest.mark.parametrize(("fixture", "rule_id", "stated"), [
    # 2.0.x without MCP_BEARER_TOKEN still answers unauthenticated calls
    ("cve-2026-123811-dynatrace-mcp-http", DT_HTTP_RULE,
     "2.0.0 and 2.0.1 still serve unauthenticated calls when `MCP_BEARER_TOKEN` is unset"),
    # Docker's catalog image, a 2.1.0 build published only as `latest`
    ("cve-2026-123810-dynatrace-mcp-dql", DT_DQL_RULE,
     "Docker's MCP catalog image `mcp/dynatrace-mcp-server` is not read"),
])
def test_stated_limitations_are_misses(fixture: str, rule_id: str, stated: str) -> None:
    (limitation,) = [p for p in (CVES / fixture).iterdir() if p.name.startswith("limitation")]
    assert rule_id not in _ids(limitation)
    assert stated in RULES[rule_id].limitations


def test_unaffected_release_candidates_read_as_their_release(tmp_path: Path) -> None:
    """0.5.0-rc.1 to rc.3 have no HTTP mode, but a pre-release reads as its release, so
    they are reported as 0.5.0 is. The rule text says so."""
    assert DT_HTTP_RULE in _ids(_package_json(tmp_path, "0.5.0-rc.1"))
    assert "0.5.0-rc.1 to 0.5.0-rc.3, which have no HTTP mode, read as 0.5.0" in RULES[DT_HTTP_RULE].limitations


# ---- Code Graph RAG versions and references ----------------------------------------------------


@pytest.mark.parametrize(("version", "expected"), [
    ("0.0.79", set()),                  # the first PyPI release: no codebase_rag/mcp in wheel or sdist
    ("0.0.100", set()),
    ("0.0.148", {CGR_READ_RULE}),       # the MCP server ships; paginated read_file unchecked
    ("0.0.246", {CGR_READ_RULE}),
    ("0.0.345", set()),                 # read_file resolved; no structural tools yet
    ("0.0.421", {CGR_SYMLINK_RULE}),    # AstGrepService arrives, comparing unresolved paths
    ("0.0.584", {CGR_SYMLINK_RULE}),
    ("0.0.589", set()),                 # resolves before classifying
    ("0.6.30", set()),
])
def test_code_graph_rag_versions(tmp_path: Path, version: str, expected: set[str]) -> None:
    """The ranges are disjoint: no release gets both rules, and each finding names only
    the CVE that release carries."""
    assert _ids(_write(tmp_path, "requirements.txt", f"code-graph-rag=={version}\n")) == expected
    assert _ids(_uv_lock(tmp_path, version)) == expected


@pytest.mark.parametrize(("name", "content", "expected"), [
    ("requirements.txt", "code_graph_rag==0.0.246\n", {CGR_READ_RULE}),
    ("requirements.txt", "code-graph-rag>=0.0.300,<0.0.400\n", {CGR_READ_RULE}),   # admits 0.0.345 and below
    ("requirements.txt", "code-graph-rag>=0.0.345,<0.0.400\n", set()),             # admits only 0.0.345
    ("requirements.txt", "code-graph-rag~=0.0.500\n", {CGR_SYMLINK_RULE}),
    # a range that admits releases from both intervals gets both findings
    ("requirements.txt", "code-graph-rag>=0.0.200,<0.0.500\n", {CGR_READ_RULE, CGR_SYMLINK_RULE}),
    ("requirements.txt", "code-graph-rag\n", set()),                               # latest, 0.6.30
    ("requirements.txt", "codebase-rag==1.0.1\n", set()),                          # another project
    (".mcp.json", _launch("uvx", "code-graph-rag==0.0.246", "mcp-server"), {CGR_READ_RULE}),
    (".mcp.json", _launch("uvx", "--from", "code-graph-rag==0.0.584", "code-graph-rag", "mcp-server"),
     {CGR_SYMLINK_RULE}),
    (".mcp.json", _launch("uvx", "code-graph-rag", "mcp-server"), set()),
    (".mcp.json", _launch("code-graph-rag", "mcp-server"), set()),       # the guide's pip install, by name
    (".mcp.json", _launch("uv", "run", "--directory", "/src/code-graph-rag", "code-graph-rag", "mcp-server"),
     set()),                                                              # the guide's source checkout
])
def test_code_graph_rag_references(tmp_path: Path, name: str, content: str, expected: set[str]) -> None:
    assert _ids(_write(tmp_path, name, content)) == expected


@pytest.mark.parametrize(("tag", "expected"), [
    ("0.0.88", [CGR_READ_RULE]), ("0.0.99", [CGR_READ_RULE]),
    ("0.0.100", [CGR_READ_RULE]),                                 # built from source, server included
    ("0.0.345", []),
    ("0.0.496", [CGR_SYMLINK_RULE]), ("0.0.534", [CGR_SYMLINK_RULE]), ("0.0.584", [CGR_SYMLINK_RULE]),
    ("0.0.639", []), ("0.0", []), ("latest", []), (None, []),
])
def test_code_graph_rag_image_tags(tmp_path: Path, tag: str | None, expected: list[str]) -> None:
    ref = CGR_IMAGE if tag is None else f"{CGR_IMAGE}:{tag}"
    root = _write(tmp_path, "docker-compose.yml", f"services:\n  cgr:\n    image: {ref}\n")
    assert [f.rule_id for f in container_image_pins.scan(root)[0]] == expected


# ---- the advisory feed, after `aak update` -----------------------------------------------------


def _record(ident: str) -> dict:
    return json.loads((OSV / f"{ident}.json").read_text(encoding="utf-8"))


def _cache() -> None:
    """The cached feed `aak update` writes, holding the six GitHub records."""
    collector = advisory_feed.Collector()
    for ident in RECORDS:
        record = _record(ident)
        for ecosystem in sorted({a["package"]["ecosystem"] for a in record["affected"]}):
            collector.add(ecosystem, record)
    collector.write(now=NOW)


def _scan(root: Path) -> dict[str, set[str]]:
    """Rule ids the engine keeps, and the advisory ids AAK-KNOWN-VULN-001 still reports."""
    findings = run_scan(root).findings
    rules = {f.rule_id for f in findings if f.rule_id in OUR_RULES}
    feed = {i for f in findings if f.rule_id == KNOWN_RULE for i in RECORDS if i in f.evidence}
    return {"rules": rules, "feed": feed}


def test_the_saved_records_are_osv_s_unedited() -> None:
    for ident in RECORDS:
        record = _record(ident)
        assert record["id"] == ident and record["modified"].startswith("2026-11-")


def test_none_of_the_records_is_bundled() -> None:
    text = advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    assert not any(ident in text for ident in RECORDS)


@pytest.mark.parametrize(("version", "rules", "feed"), [
    # Every advisory the rules name is stood down on the rules' line.
    ("1.8.5", {DT_HTTP_RULE, DT_DQL_RULE}, set()),
    ("2.0.0", {DT_DQL_RULE}, set()),
    # The HTTP advisory's range starts at 0; releases before 0.5.0 have no HTTP mode,
    # and the HIGH rule does not report them, so the feed's own finding stays.
    ("0.1.0", {DT_DQL_RULE}, {GHSA_HTTP}),
    ("0.4.0", {DT_DQL_RULE}, {GHSA_HTTP}),
    ("2.1.1", set(), set()),
])
def test_dynatrace_with_the_feed(tmp_path: Path, version: str, rules: set[str], feed: set[str]) -> None:
    _cache()
    assert _scan(_npm_lock(tmp_path, version)) == {"rules": rules, "feed": feed}


@pytest.mark.parametrize(("version", "rules", "feed"), [
    ("0.0.584", {CGR_SYMLINK_RULE}, set()),
    # Both advisories start at 0 and the symlink one runs to 0.0.587, so the feed
    # reports releases the code shows unaffected: no MCP server in the PyPI files
    # before 0.0.148, and no structural tools before 0.0.421. Each rule stands down
    # only the advisory for the CVE it names.
    ("0.0.79", set(), {GHSA_READ, GHSA_SYMLINK}),
    ("0.0.100", set(), {GHSA_READ, GHSA_SYMLINK}),
    ("0.0.148", {CGR_READ_RULE}, {GHSA_SYMLINK}),
    ("0.0.246", {CGR_READ_RULE}, {GHSA_SYMLINK}),
    ("0.0.345", set(), {GHSA_SYMLINK}),
    ("0.0.589", set(), set()),
])
def test_code_graph_rag_with_the_feed(tmp_path: Path, version: str, rules: set[str], feed: set[str]) -> None:
    _cache()
    assert _scan(_uv_lock(tmp_path, version)) == {"rules": rules, "feed": feed}


# ---- the ledger --------------------------------------------------------------------------------


def _ledger_rows(cve: str) -> list[str]:
    return [line for line in LEDGER.read_text(encoding="utf-8").splitlines()
            if line.startswith(f"| {cve} ")]


@pytest.mark.parametrize(("cve", "issue", "rule_id"), [
    ("CVE-2026-123811", "#1225", DT_HTTP_RULE),
    ("CVE-2026-123810", "not filed", DT_DQL_RULE),
    ("CVE-2026-123809", "not filed", DT_DQL_RULE),
    ("CVE-2026-123812", "not filed", DT_DQL_RULE),
    ("CVE-2026-77604", "#1224", CGR_READ_RULE),
    ("CVE-2026-87008", "not filed", CGR_SYMLINK_RULE),
])
def test_covered_rows_name_their_rule(cve: str, issue: str, rule_id: str) -> None:
    (row,) = _ledger_rows(cve)
    assert row.rstrip().endswith(f"| {issue} |")
    assert rule_id in row and "out of scope" not in row.lower()
