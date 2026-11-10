"""AAK-MALICIOUS-RELEASE-001 and the offline feed it reads.

litellm 1.107.0 (OSV MAL-2026-2144) passed every rule on 0.6.27. These tests pin
the four places the rule reads a release (a pinned declaration, a lockfile, an
installed dist-info, an image digest), what does not match (the safe 1.106.2, a
pre-release, a range, a tag), that a scan never touches the network, the
cached-then-bundled load order, and `aak update`'s rebuild: atomic, MAL- records
only, the old cache kept on failure. Every fixture is a version string, a fake
dist-info folder or a digest; nothing is fetched.
"""

from __future__ import annotations

import http.client
import io
import json
import socket
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_audit_kit import malicious_feed
from agent_audit_kit.cli import cli
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import ScanResult, Severity
from agent_audit_kit.output.console import format_results as console_results
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.malicious_releases import scan

FIXTURES = Path(__file__).parent / "fixtures" / "malicious_releases"
RULE = "AAK-MALICIOUS-RELEASE-001"
DIGEST = "sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e"


def _found(root: Path) -> set[tuple[str, int | None]]:
    findings, _ = scan(root)
    assert all(f.rule_id == RULE for f in findings)
    return {(f.file_path, f.line_number) for f in findings}


def _cached_feed(entries: list[dict], oci: list[dict] | None = None) -> Path:
    path = malicious_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "generated_at": "2026-10-28T00:00:00Z", "source": "test feed", "entries": entries, "oci": oci or [],
    }))
    return path


def _entry(name: str, ecosystem: str = "PyPI", **extra: object) -> dict:
    return {"id": f"MAL-TEST-{name}", "aliases": [], "ecosystem": ecosystem, "name": name,
            "versions": [], "modified": "", "url": "", **extra}


# ---- the fixtures ----------------------------------------------------------------------


def test_each_place_a_release_is_read_fires() -> None:
    assert _found(FIXTURES / "firing") == {
        ("requirements.txt", 1),
        ("uv.lock", 5),
        ("lib/python3.12/site-packages/litellm-1.107.0.dist-info/METADATA", 3),
        ("docker-compose.yml", 3),
    }


def test_the_evidence_names_the_feed_id_and_the_feed() -> None:
    findings, _ = scan(FIXTURES / "firing")
    for finding in findings:
        assert "MAL-2026-2144" in finding.evidence or "LITELLM-2026-10-21" in finding.evidence
        assert "bundled copy generated" in finding.evidence
        assert finding.severity is Severity.CRITICAL


def test_the_vendors_safe_pin_does_not_fire() -> None:
    assert _found(FIXTURES / "negative") == set()


def test_a_tag_without_a_digest_does_not_fire() -> None:
    assert _found(FIXTURES / "tag-only") == set()
    tagged = run_scan(project_root=FIXTURES / "tag-only")
    assert RULE not in {f.rule_id for f in tagged.findings}


def test_a_scan_never_touches_the_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a scan opened a network connection")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    result = run_scan(project_root=FIXTURES / "firing")
    assert len([f for f in result.findings if f.rule_id == RULE]) == 4
    assert not [f for f in result.findings if f.rule_id == "AAK-INTERNAL-SCANNER-FAIL"]


def test_the_rule_is_critical() -> None:
    assert RULES[RULE].severity is Severity.CRITICAL


# ---- what matches ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line, fires",
    [
        ("litellm==1.107.0", True),
        ("litellm==1.107", True),        # PEP 440: 1.107 is 1.107.0
        ("LiteLLM[proxy]==1.82.8", True),
        ("litellm===1.82.7", True),
        ("litellm==1.107.0rc1", False),  # OSV: the release candidates are not affected
        ("litellm==1.106.2", False),
        ("litellm>=1.107.0", False),      # a range says nothing about what was installed
        ("litellm", False),
    ],
)
def test_a_requirement_matches_only_an_exact_listed_version(tmp_path: Path, line: str, fires: bool) -> None:
    (tmp_path / "requirements.txt").write_text(line + "\n")
    assert bool(_found(tmp_path)) is fires


def test_an_every_version_entry_matches_any_declaration(tmp_path: Path) -> None:
    _cached_feed([_entry("aak-typosquat", all_versions=True)])
    (tmp_path / "requirements.txt").write_text("aak_typosquat>=0.1\n")
    assert _found(tmp_path) == {("requirements.txt", 1)}


def test_npm_lockfiles_ranges_and_the_security_placeholder(tmp_path: Path) -> None:
    _cached_feed([
        _entry("aak-evil", "npm", all_versions=True),
        _entry("aak-ranged", "npm", ranges=[{"introduced": "1.2.0", "fixed": "1.3.0"}]),
    ])
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "x"},
        "node_modules/aak-evil": {"version": "0.0.1-security"},
        "node_modules/aak-ranged": {"version": "1.2.5"},
    }}, indent=2))
    findings, _ = scan(tmp_path)
    assert [("aak-ranged" in f.evidence, f.line_number) for f in findings] == [(True, 10)]


def test_an_mcp_config_launch_and_package_json_are_read(tmp_path: Path) -> None:
    _cached_feed([_entry("aak-evil", "npm", versions=["1.0.0"])])
    (tmp_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"x": {"command": "npx", "args": ["-y", "aak-evil@1.0.0"]}}}, indent=2))
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"aak-evil": "1.0.0"}}, indent=2))
    assert {path for path, _ in _found(tmp_path)} == {".mcp.json", "package.json"}


def test_a_program_run_by_name_names_no_registry(tmp_path: Path) -> None:
    _cached_feed([_entry("aak-evil", "npm", all_versions=True)])
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"x": {"command": "aak-evil"}}}))
    assert _found(tmp_path) == set()


def test_poetry_and_pipfile_lockfiles_are_read(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "litellm"\nversion = "1.82.7"\n')
    (tmp_path / "Pipfile.lock").write_text(json.dumps({"default": {"litellm": {"version": "==1.82.8"}}}, indent=2))
    assert {path for path, _ in _found(tmp_path)} == {"poetry.lock", "Pipfile.lock"}


def test_a_digest_in_a_comment_is_not_a_deployment(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text(f"services:\n  a:\n    # was litellm/litellm@{DIGEST}\n    image: x:1\n")
    assert _found(tmp_path) == set()


def test_a_digest_matches_under_any_registry_name(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(f"FROM ghcr.io/berriai/litellm@{DIGEST}\n")
    assert _found(tmp_path) == {("Dockerfile", 1)}


# ---- crates.io and Go (MAL-2026-18776, env-test-guard, 9 Nov 2026) ----------------------------

CARGO = FIXTURES / "cargo"


@pytest.mark.parametrize("project", ["env-test-guard-0.3.0", "env_test_guard-0.3.0"])
def test_a_cargo_lock_resolving_env_test_guard_fires_once_whatever_its_spelling(project: str) -> None:
    findings, _ = scan(CARGO / project)
    (finding,) = findings
    # The Cargo.lock reader AAK-KNOWN-VULN-001 uses places a crate at its `name` line.
    assert (finding.rule_id, finding.file_path, finding.line_number) == (RULE, "Cargo.lock", 14)
    assert finding.evidence.startswith("Cargo.lock resolves env-test-guard 0.3.0, a malicious release: MAL-2026-18776")


def test_the_clean_cargo_lock_twin_is_quiet() -> None:
    assert scan(CARGO / "env-test-guard-0.1.0")[0] == []


def test_a_go_mod_requiring_a_listed_module_fires() -> None:
    _cached_feed([_entry("example.com/evil/telemetry", ecosystem="Go", versions=["0.4.1"])])
    findings, _ = scan(FIXTURES / "go" / "malicious-module")
    (finding,) = findings
    assert (finding.file_path, finding.line_number) == ("go.mod", 7)
    assert finding.evidence.startswith("go.mod requires example.com/evil/telemetry v0.4.1, a malicious release: MAL-TEST-")


def test_a_go_module_path_keeps_its_case_and_a_crate_folds_its_separators() -> None:
    _cached_feed([_entry("Example.com/Evil", ecosystem="Go", versions=["1.0.0"]),
                  _entry("some_crate", ecosystem="crates.io", versions=["1.0.0"])])
    feed = malicious_feed.load_feed()
    assert feed.match("Go", "Example.com/Evil", "v1.0.0") and not feed.match("Go", "example.com/evil", "v1.0.0")
    assert feed.match("crates.io", "some-crate", "1.0.0") and feed.match("crates.io", "Some_Crate", "1.0.0")


@pytest.mark.parametrize(("ecosystem", "a", "b"), [("Go", "v1.2.3", "1.2.3"), ("Go", "v0.4.1", "=0.4.1"),
                                                   ("crates.io", "0.3.0", "=0.3.0")])
def test_a_leading_v_or_equals_names_the_same_version(ecosystem: str, a: str, b: str) -> None:
    assert malicious_feed.version_key(ecosystem, a) == malicious_feed.version_key(ecosystem, b)
    assert malicious_feed.version_order(ecosystem, a) == malicious_feed.version_order(ecosystem, b) is not None


def test_parse_feed_keeps_crates_io_and_go_and_skips_an_unknown_registry(tmp_path: Path) -> None:
    feed = malicious_feed.parse_feed({"entries": [
        _entry("env-test-guard", ecosystem="crates.io", versions=["0.3.0"]),
        _entry("example.com/evil", ecosystem="Go", versions=["1.0.0"]),
        _entry("evil", ecosystem="RubyGems", versions=["1.0.0"]),
    ]}, "cached", tmp_path / "feed.json")
    assert set(feed.names("crates.io")) == {"env-test-guard"} and set(feed.names("Go")) == {"example.com/evil"}
    assert not feed.names("RubyGems")


def test_osv_entries_read_a_crates_io_record_by_its_versions() -> None:
    record = json.loads((FIXTURES / "osv" / "MAL-2026-18776.json").read_text())
    (entry,) = malicious_feed.osv_entries(record, "crates.io")
    assert (entry["name"], entry["versions"], entry["aliases"]) == ("env-test-guard", ["0.2.0", "0.3.0"], [])
    assert "ranges" not in entry and "all_versions" not in entry
    assert malicious_feed.osv_entries(record, "Go") == []


def test_osv_entries_keep_a_go_semver_range_and_the_feed_reads_it(tmp_path: Path) -> None:
    record = {"id": "MAL-2026-9100", "modified": "2026-11-09T00:00:00Z", "affected": [{
        "package": {"ecosystem": "Go", "name": "example.com/evil/telemetry"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.4.0"}, {"fixed": "0.5.0"}]}],
    }]}
    (entry,) = malicious_feed.osv_entries(record, "Go")
    assert entry["ranges"] == [{"introduced": "0.4.0", "fixed": "0.5.0"}] and entry["versions"] == []
    feed = malicious_feed.parse_feed({"entries": [entry]}, "cached", tmp_path / "feed.json")
    assert feed.match("Go", "example.com/evil/telemetry", "v0.4.1")
    assert not feed.match("Go", "example.com/evil/telemetry", "v0.5.0")
    assert not feed.match("Go", "example.com/evil/telemetry", "v0.3.9")


def test_github_entries_read_the_ghsa_7w47_rest_shape() -> None:
    advisory = json.loads((FIXTURES / "github" / "GHSA-7w47-jmjx-gvm2.json").read_text())
    entries = malicious_feed.github_entries([advisory])
    assert [(e["ecosystem"], e["name"], e["versions"]) for e in entries] == [
        ("crates.io", "env-test-guard", ["0.2.0"]), ("crates.io", "env-test-guard", ["0.3.0"]),
    ]
    assert {e["id"] for e in entries} == {"GHSA-7w47-jmjx-gvm2"}
    assert {e["modified"] for e in entries} == {"2026-11-09T06:30:33Z"}
    assert malicious_feed.github_entries([{**advisory, "withdrawn_at": "2026-11-10T00:00:00Z"}]) == []


def test_github_entries_keep_a_go_range() -> None:
    (entry,) = malicious_feed.github_entries([{"ghsa_id": "GHSA-gggg-gggg-gggg", "vulnerabilities": [
        {"package": {"ecosystem": "go", "name": "example.com/evil"}, "vulnerable_version_range": ">= 1.0.0, < 1.2.0"}]}])
    assert (entry["ecosystem"], entry["ranges"]) == ("Go", [{"introduced": "1.0.0", "fixed": "1.2.0"}])


def test_refresh_reads_a_crates_io_mal_record_from_one_download() -> None:
    calls: list[str] = []
    crates = {"MAL-2026-9200": {"id": "MAL-2026-9200", "modified": "m", "affected": [
        {"package": {"ecosystem": "crates.io", "name": "evil_crate"}, "versions": ["1.0.0"]}]}}
    opener = _opener(exports={"crates.io": crates})

    def counting(request: urllib.request.Request, timeout: float | None = None) -> _Response:
        calls.append(request.full_url)
        return opener(request, timeout)

    done = malicious_feed.refresh(opener=counting, now=NOW)
    assert done.counts["OSV crates.io"] == 1 and done.counts["OSV Go"] == 0
    assert sorted(calls) == sorted(malicious_feed.OSV_EXPORT.format(ecosystem=e) for e in malicious_feed.ECOSYSTEMS)
    feed = malicious_feed.load_feed()
    assert feed.match("crates.io", "evil-crate", "1.0.0")
    for ecosystem in malicious_feed.ECOSYSTEMS:
        assert malicious_feed.OSV_EXPORT.format(ecosystem=ecosystem) in feed.source


# ---- whole-repository image entries (ARTEX, The Hacker News, 5 Nov 2026) ---------------------

ARTEX = "ARTEX-2026-11-05-TOMICDD"
ARTEX_TWIN = "ARTEX-2026-11-05-CONGDONGLINUX"
OTHER_DIGEST = "sha256:" + "b" * 64


@pytest.mark.parametrize("reference", [
    "tomicdd/artex", "tomicdd/artex:latest", "docker.io/tomicdd/artex:v2", "TomicDD/Artex",
    f"index.docker.io/tomicdd/artex@{OTHER_DIGEST}", "registry-1.docker.io/tomicdd/artex",
    "docker.io/tomicdd/artex:v2@" + OTHER_DIGEST,
])
def test_every_spelling_of_the_repository_is_one_name(reference: str) -> None:
    assert malicious_feed.canonical_repository(reference) == "docker.io/tomicdd/artex"
    assert malicious_feed.load_feed().repository(reference).id == ARTEX


@pytest.mark.parametrize("reference", [
    "tomicdd/artex-pro", "tomicdd/artex2", "nottomicdd/artex", "ghcr.io/tomicdd/artex", "artex",
    "tomicdd/artex/sub", "${REGISTRY}/tomicdd/artex", "",
])
def test_a_lookalike_or_another_registrys_repository_is_not_listed(reference: str) -> None:
    assert malicious_feed.load_feed().repository(reference) is None


def test_docker_rules_for_registries_ports_and_library() -> None:
    canonical = malicious_feed.canonical_repository
    assert canonical("artex") == canonical("library/artex") == canonical("docker.io/library/artex:1")
    assert canonical("artex") == "docker.io/library/artex"
    assert canonical("localhost:5000/team/app:1.0") == "localhost:5000/team/app"
    assert canonical("localhost/app") == "localhost/app"
    assert canonical("registry.example.net:443/a/b@" + OTHER_DIGEST) == "registry.example.net:443/a/b"


def test_a_compose_image_by_tag_reports_its_line(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  console:\n    image: tomicdd/artex:latest\n    ports: ['8080:8080']\n"
    )
    findings, _ = scan(tmp_path)
    (finding,) = findings
    assert (finding.file_path, finding.line_number) == ("docker-compose.yml", 3)
    assert finding.evidence == (
        "`tomicdd/artex:latest` runs docker.io/tomicdd/artex, which ARTEX-2026-11-05-TOMICDD lists as a "
        "repository that ships only malicious builds "
        "(https://thehackernews.com/2026/11/backdoored-docker-image-for-artex-ai.html). Feed: the bundled "
        f"copy generated {malicious_feed.load_feed().generated_at}. Treat a host that ran it as compromised."
    )


def test_a_dockerfile_from_with_a_platform_flag_reports(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM --platform=linux/amd64 docker.io/tomicdd/artex\nRUN echo tomicdd/artex\n"
    )
    findings, _ = scan(tmp_path)
    (finding,) = findings
    assert finding.line_number == 1 and finding.evidence.startswith("`docker.io/tomicdd/artex` runs ")


def test_a_kubernetes_image_by_digest_reports_once(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(
        "spec:\n  containers:\n    - name: console\n"
        f"      image: congdonglinux/artex@{OTHER_DIGEST}\n"
    )
    findings, _ = scan(tmp_path)
    (finding,) = findings
    assert finding.line_number == 4 and ARTEX_TWIN in finding.evidence
    assert finding.evidence.startswith(f"`congdonglinux/artex@{OTHER_DIGEST}` runs docker.io/congdonglinux/artex")


def test_a_helm_repository_with_its_tag_reports_on_the_repository_line(tmp_path: Path) -> None:
    (tmp_path / "values.yaml").write_text(
        "image:\n  registry: docker.io\n  repository: tomicdd/artex\n  tag: v1\n"
    )
    findings, _ = scan(tmp_path)
    (finding,) = findings
    assert finding.line_number == 3 and finding.evidence.startswith("`docker.io/tomicdd/artex:v1` runs ")


def test_a_template_tag_is_quoted_whole(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text('a:\n  image: "tomicdd/artex:${TAG}"\nb: {image: congdonglinux/artex}\n')
    findings, _ = scan(tmp_path)
    assert sorted((f.line_number, f.evidence.split(" runs ")[0]) for f in findings) == [
        (2, "`tomicdd/artex:${TAG}`"), (3, "`congdonglinux/artex`"),
    ]


def test_lookalikes_other_registries_comments_and_prose_are_quiet(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text(
        "services:\n"
        "  a:\n    image: tomicdd/artex-pro\n"
        "  b:\n    image: tomicdd/artex2\n"
        "  c:\n    image: ghcr.io/tomicdd/artex\n"
        "  d:\n    # image: tomicdd/artex\n    image: nginx:1.27\n"
        "  e:\n    command: [\"docker\", \"run\", \"tomicdd/artex\"]\n"
    )
    (tmp_path / "README.md").write_text("Do not run tomicdd/artex; pull the image from the vendor.\n")
    (tmp_path / "notes.yaml").write_text("description: the tomicdd/artex image was backdoored\n")
    assert _found(tmp_path) == set()


def test_a_helm_repository_without_a_tag_is_not_read(tmp_path: Path) -> None:
    (tmp_path / "values.yaml").write_text("image:\n  repository: tomicdd/artex\n  pullPolicy: Always\n")
    assert _found(tmp_path) == set()


def test_a_listed_digest_under_a_listed_repository_reports_once(tmp_path: Path) -> None:
    _cached_feed([], oci=[
        {"id": "WHOLE", "image": "docker.io/evil/app", "all_tags": True, "digests": [], "tags": []},
        {"id": "DIGEST", "image": "docker.io/evil/app", "digests": [OTHER_DIGEST], "tags": ["v1"]},
    ])
    (tmp_path / "compose.yaml").write_text(f"a:\n  image: evil/app@{OTHER_DIGEST}\nb:\n  image: evil/app:v9\n")
    findings, _ = scan(tmp_path)
    assert sorted((f.line_number, f.evidence.split(" which ")[1].split(" ")[0]) for f in findings) == [
        (2, "DIGEST"), (4, "WHOLE"),
    ]


def test_a_repository_reference_is_read_only_within_256_characters(tmp_path: Path) -> None:
    """The reader looks back at most 256 characters for where a reference starts, so a
    registry name longer than that is not read (the limitation says so)."""
    near, far = "r" * 200 + ".example", "r" * 250 + ".example"
    _cached_feed([], oci=[
        {"id": "NEAR", "image": f"{near}/evil/app", "all_tags": True},
        {"id": "FAR", "image": f"{far}/evil/app", "all_tags": True},
    ])
    (tmp_path / "compose.yaml").write_text(f"a:\n  image: {near}/evil/app:1\nb:\n  image: {far}/evil/app:1\n")
    findings, _ = scan(tmp_path)
    assert [(f.line_number, "NEAR" in f.evidence) for f in findings] == [(2, True)]


def test_all_tags_counts_only_a_real_bool(tmp_path: Path) -> None:
    feed = malicious_feed.parse_feed({"entries": [], "oci": [
        {"id": "STRING", "image": "docker.io/evil/one", "all_tags": "yes", "digests": []},
        {"id": "ONE", "image": "docker.io/evil/two", "all_tags": 1, "digests": []},
        {"id": "REAL", "image": "evil/three", "all_tags": True},
    ]}, "cached", tmp_path / "feed.json")
    assert sorted(feed.repositories) == ["docker.io/evil/three"]
    assert feed.repository("evil/one") is None and feed.repository("evil/two") is None


def test_an_entry_without_all_tags_or_digests_indexes_nothing(tmp_path: Path) -> None:
    feed = malicious_feed.parse_feed({"entries": [], "oci": [
        {"id": "EMPTY", "image": "docker.io/evil/app", "all_tags": False, "digests": [], "tags": ["latest"]},
        {"id": "TEMPLATE", "image": "${REGISTRY}/evil/app", "all_tags": True},
    ]}, "cached", tmp_path / "feed.json")
    assert feed.images == {} and feed.repositories == {}
    assert feed.repository("evil/app:latest") is None


def test_existing_image_entries_still_build_with_positional_fields() -> None:
    image = malicious_feed.Image("ID", "docker.io/a/b", frozenset(), (), "")
    assert image.all_tags is False


# ---- the feed and its load order ------------------------------------------------------------


def test_the_bundled_feed_holds_what_osv_and_the_vendor_published() -> None:
    data = json.loads(malicious_feed.BUNDLED_FEED.read_text())
    litellm, local_commander, axios, plain_crypto, env_test_guard = data["entries"]
    assert (litellm["id"], litellm["ecosystem"], litellm["name"]) == ("MAL-2026-2144", "PyPI", "litellm")
    assert litellm["versions"] == ["1.82.7", "1.82.8", "1.107.0"]
    assert litellm["modified"] == "2026-10-21T22:01:01.881791175Z"
    # MAL-2026-18425 is bundled exactly as `aak update` would read the OSV record,
    # saved unedited from https://api.osv.dev/v1/vulns/MAL-2026-18425 on 2026-11-01.
    record = json.loads((FIXTURES / "osv" / "MAL-2026-18425.json").read_text())
    assert malicious_feed.osv_entries(record, "npm") == [local_commander]
    assert local_commander["versions"] == ["0.3.52"] and local_commander["aliases"] == ["GHSA-7j62-5j84-72fv"]
    assert "MAL-2026-2144" in data["source"] and "MAL-2026-18425" in data["source"]
    # The axios compromise of 31 March 2026, saved unedited from
    # https://api.osv.dev/v1/vulns/<id> on 2026-11-07.
    for entry, ident in ((axios, "MAL-2026-2307"), (plain_crypto, "MAL-2026-2306")):
        record = json.loads((FIXTURES / "osv" / f"{ident}.json").read_text())
        assert malicious_feed.osv_entries(record, "npm") == [entry]
        assert ident in data["source"]
    assert axios["versions"] == ["0.30.4", "1.14.1"] and "all_versions" not in axios
    assert plain_crypto["all_versions"] is True and "0.0.1-security" in plain_crypto["versions"]
    # MAL-2026-18776 the same way, from https://api.osv.dev/v1/vulns/MAL-2026-18776 on
    # 2026-11-10. The record names no alias: GitHub's GHSA-7w47-jmjx-gvm2 lists the same two
    # releases, but OSV does not link it, so the entry does not either.
    record = json.loads((FIXTURES / "osv" / "MAL-2026-18776.json").read_text())
    assert malicious_feed.osv_entries(record, "crates.io") == [env_test_guard]
    assert (env_test_guard["name"], env_test_guard["versions"]) == ("env-test-guard", ["0.2.0", "0.3.0"])
    assert env_test_guard["modified"] == "2026-11-09T04:45:05.142026828Z" and "MAL-2026-18776" in data["source"]
    images = {image["id"]: image for image in data["oci"]}
    assert images["LITELLM-2026-10-21"]["digests"] == [DIGEST] and len(DIGEST) == len("sha256:") + 64
    # The two repositories The Hacker News calls backdoored, listed whole: it names no
    # tag and no digest, and the six other namespaces it names are not called backdoored.
    artex = "https://thehackernews.com/2026/11/backdoored-docker-image-for-artex-ai.html"
    assert {key: (image["image"], image["all_tags"], image["digests"], image["tags"], image["url"])
            for key, image in images.items() if image.get("all_tags")} == {
        "ARTEX-2026-11-05-TOMICDD": ("docker.io/tomicdd/artex", True, [], [], artex),
        "ARTEX-2026-11-05-CONGDONGLINUX": ("docker.io/congdonglinux/artex", True, [], [], artex),
    }
    assert artex in data["source"]


def test_the_cached_feed_is_read_first_and_a_broken_one_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("aak-cached-only==1.0.0\n")
    _cached_feed([_entry("aak-cached-only", versions=["1.0.0"])])
    assert malicious_feed.load_feed().origin == "cached"
    assert _found(tmp_path) == {("requirements.txt", 1)}
    malicious_feed.cache_path().write_text("{ not json")
    assert malicious_feed.load_feed().origin == "bundled"
    assert _found(tmp_path) == set()


def test_reports_name_the_feed_copy_and_its_age() -> None:
    result = run_scan(project_root=FIXTURES / "negative")
    feed = result.data_feeds["maliciousReleases"]
    assert feed["origin"] == "bundled" and feed["generatedAt"]
    sarif = json.loads(format_results(result))
    assert sarif["runs"][0]["properties"]["dataFeeds"]["maliciousReleases"]["generatedAt"] == feed["generatedAt"]
    assert f"Malicious-release feed: bundled copy, generated {feed['generatedAt']}" in console_results(result)


def test_an_empty_scan_result_has_no_feed_note() -> None:
    sarif = json.loads(format_results(ScanResult()))
    assert "properties" not in sarif["runs"][0]


# ---- `aak update`: rebuilding the cached feed ----------------------------------------------------


def _export(records: dict[str, dict]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, record in records.items():
            archive.writestr(f"{name}.json", json.dumps(record))
    return buffer.getvalue()


_PYPI = {
    "MAL-2026-1": {"id": "MAL-2026-1", "modified": "m", "affected": [{"package": {"ecosystem": "PyPI", "name": "aak-one"},
                                                                       "versions": ["1.0"]}]},
    "MAL-2026-2": {"id": "MAL-2026-2", "withdrawn": "2026-01-01", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "aak-gone"}, "versions": ["1.0"]}]},
    "GHSA-xxxx-xxxx-xxxx": {"id": "GHSA-xxxx-xxxx-xxxx", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "aak-not-malware"}, "versions": ["1.0"]}]},
}
_NPM = {
    "MAL-2026-3": {"id": "MAL-2026-3", "aliases": ["GHSA-aaaa-bbbb-cccc"], "affected": [
        {"package": {"ecosystem": "npm", "name": "aak-squat"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
    "MAL-2026-4": {"id": "MAL-2026-4", "affected": [
        {"package": {"ecosystem": "npm", "name": "aak-ranged"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.2.0"}, {"fixed": "1.3.0"}]}]}]},
}


class _Response(io.BytesIO):
    def __init__(self, body: bytes, link: str = "") -> None:
        super().__init__(body)
        self.headers = {"Link": link}


def _opener(fail_on: str | None = None, github: list[tuple[list, str]] | None = None,
            exports: dict[str, dict[str, dict]] | None = None):
    pages = list(github or [])
    exports = exports or {}

    def opener(request: urllib.request.Request, timeout: float | None = None) -> _Response:
        url = request.full_url
        if fail_on and fail_on in url:
            raise urllib.error.URLError("network unreachable (test)")
        if url.endswith("/PyPI/all.zip"):
            return _Response(_export(_PYPI))
        if url.endswith("/npm/all.zip"):
            return _Response(_export(_NPM))
        if url.endswith(("/Go/all.zip", "/crates.io/all.zip")):
            return _Response(_export(exports.get(url.rsplit("/", 2)[-2], {})))
        if url.startswith("https://api.github.com/advisories"):
            body, link = pages.pop(0) if pages else ([], "")  # a registry with no queued page has none
            return _Response(json.dumps(body).encode(), link)
        raise AssertionError(url)

    return opener


NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


def test_refresh_keeps_only_mal_records_and_carries_the_bundled_digests() -> None:
    done = malicious_feed.refresh(opener=_opener(), now=NOW)
    data = json.loads(done.path.read_text())
    assert data["generated_at"] == "2026-10-28T12:00:00Z"
    assert sorted(e["id"] for e in data["entries"]) == [
        "MAL-2026-1", "MAL-2026-18425", "MAL-2026-18776", "MAL-2026-2144", "MAL-2026-2306", "MAL-2026-2307",
        "MAL-2026-3", "MAL-2026-4",
    ]
    assert data["oci"][0]["digests"] == [DIGEST]
    assert [image["id"] for image in data["oci"] if image.get("all_tags") is True] == [
        "ARTEX-2026-11-05-TOMICDD", "ARTEX-2026-11-05-CONGDONGLINUX",
    ]
    assert done.counts == {"OSV PyPI": 1, "OSV npm": 2, "OSV crates.io": 0, "OSV Go": 0, "bundled": 5}
    feed = malicious_feed.load_feed()
    assert feed.origin == "cached"
    assert feed.repository("tomicdd/artex:latest").id == "ARTEX-2026-11-05-TOMICDD"
    assert feed.match("npm", "aak-squat", "9.9.9") and feed.match("npm", "aak-ranged", "1.2.5")
    assert not feed.match("npm", "aak-ranged", "1.3.0")
    assert not list(done.path.parent.glob(".osv-export-*")) and not list(done.path.parent.glob(".malicious-*"))


def test_refresh_reads_github_malware_advisories_with_a_token() -> None:
    first = [{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "vulnerabilities": [  # already in OSV under an alias
        {"package": {"ecosystem": "npm", "name": "aak-squat"}, "vulnerable_version_range": ">= 0"}]}]
    second = [{"ghsa_id": "GHSA-dddd-eeee-ffff", "identifiers": [{"type": "GHSA", "value": "GHSA-dddd-eeee-ffff"}],
               "updated_at": "u", "html_url": "https://github.com/advisories/GHSA-dddd-eeee-ffff",
               "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "aak-gh"},
                                    "vulnerable_version_range": "= 2.0.0"}]}]
    pages = [
        (first, '<https://api.github.com/advisories?type=malware&ecosystem=npm&after=X>; rel="next"'),
        ([], ""),
        (second, ""),
    ]
    done = malicious_feed.refresh(github_token="test-token", opener=_opener(github=pages), now=NOW)
    assert done.github == "read" and done.counts["GitHub"] == 1
    assert malicious_feed.load_feed().match("PyPI", "aak-gh", "2.0.0")


@pytest.mark.parametrize("fail_on", ["/PyPI/all.zip", "/npm/all.zip"])
def test_a_failed_refresh_keeps_the_old_cache_and_writes_nothing(fail_on: str) -> None:
    old = _cached_feed([_entry("aak-old", versions=["1.0"])])
    before = old.read_bytes()
    with pytest.raises(malicious_feed.FeedUpdateError):
        malicious_feed.refresh(opener=_opener(fail_on=fail_on), now=NOW)
    assert old.read_bytes() == before
    assert sorted(p.name for p in old.parent.iterdir()) == ["malicious_releases.json"]


def test_aak_update_exits_non_zero_when_the_feed_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_audit_kit import vuln_db

    monkeypatch.setattr(vuln_db, "update_database", lambda: 7)
    monkeypatch.setattr(malicious_feed, "refresh", lambda **_: (_ for _ in ()).throw(
        malicious_feed.FeedUpdateError("URLError: offline")))
    result = CliRunner().invoke(cli, ["update", "--nvd-days", "0"])
    assert result.exit_code == 2
    assert "feed update failed: URLError: offline" in result.output
    assert "bundled feed" in result.output


def test_aak_update_reports_what_it_wrote(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_audit_kit import vuln_db

    monkeypatch.setattr(vuln_db, "update_database", lambda: 7)
    monkeypatch.setattr(malicious_feed.urllib.request, "urlopen", _opener())
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    result = CliRunner().invoke(cli, ["update", "--nvd-days", "0"])
    assert result.exit_code == 0, result.output
    assert "Malicious-release feed updated: 8 entries" in result.output
    assert "GitHub: skipped" in result.output


def test_github_malware_needs_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setattr(malicious_feed, "refresh", lambda **_: pytest.fail("refreshed without a token"))
    result = CliRunner().invoke(cli, ["update", "--github-malware", "--nvd-days", "0"])
    assert result.exit_code == 2 and "needs GITHUB_TOKEN or GH_TOKEN" in result.output


def test_a_token_alone_does_not_page_github(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_audit_kit import vuln_db

    seen: dict[str, object] = {}
    monkeypatch.setattr(vuln_db, "update_database", lambda: 1)
    monkeypatch.setattr(malicious_feed, "refresh", lambda **kw: seen.update(kw) or malicious_feed.Refreshed(
        Path("feed.json"), "t", {}, "skipped"))
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    assert CliRunner().invoke(cli, ["update", "--nvd-days", "0"]).exit_code == 0
    assert seen["github_token"] is None
    assert CliRunner().invoke(cli, ["update", "--github-malware", "--nvd-days", "0"]).exit_code == 0
    assert seen["github_token"] == "test-token"
    assert set(seen) == {"github_token", "on_record"}  # the advisory feed reads the same downloads


def test_a_lockfile_repeating_one_release_reports_it_once(tmp_path: Path) -> None:
    """One finding per release a lockfile resolves, at its first entry: 300,000 copies of
    one entry made 300,000 findings."""
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "litellm"\nversion = "1.107.0"\n' * 3)
    findings = [f for f in scan(tmp_path)[0] if f.rule_id == RULE]
    assert [(f.file_path, f.line_number) for f in findings] == [("uv.lock", 2)]


# ---- AAK-MALICIOUS-RELEASE-002: an unpinned launch of a package with listed releases ---------


UNPINNED = "AAK-MALICIOUS-RELEASE-002"
LAUNCH_RULES = {RULE, UNPINNED, "AAK-SUPPLY-001", "AAK-MCP-007"}


def _launch_findings(root: Path, **kwargs: object) -> list[tuple[str, str, str, int | None]]:
    result = run_scan(project_root=root, **kwargs)  # type: ignore[arg-type]
    return sorted(
        (f.rule_id, f.severity.value, f.file_path, f.line_number)
        for f in result.findings if f.rule_id in LAUNCH_RULES
    )


def _mcp(tmp_path: Path, *args: str, command: str = "npx", name: str = ".mcp.json",
         key: str = "mcpServers") -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({key: {"lc": {"command": command, "args": list(args)}}}, indent=2))
    return path


def test_an_unpinned_launch_of_local_commander_agent_is_one_high_finding() -> None:
    root = FIXTURES / "unpinned-launch"
    result = run_scan(project_root=root)
    launch = [f for f in result.findings if f.rule_id in LAUNCH_RULES]
    assert [(f.rule_id, f.severity, f.file_path, f.line_number) for f in launch] == [
        (UNPINNED, Severity.HIGH, ".mcp.json", 5),
    ]
    evidence = launch[0].evidence
    for part in ("Server 'lc' arg: local-commander-agent", "`npx local-commander-agent`",
                 "MAL-2026-18425", "GHSA-7j62-5j84-72fv", "local-commander-agent 0.3.52",
                 "Pin a release outside the list", "check the launcher cache",
                 "`aak scan --include-user-config`", "bundled copy generated"):
        assert part in evidence, part


def test_the_launch_was_supply_001_alone_before_002(tmp_path: Path) -> None:
    """Without 002 the same launch is AAK-SUPPLY-001 (AAK-MCP-007 already stood down
    for it): 002 replaces both, it does not add a second report."""
    _mcp(tmp_path, "-y", "local-commander-agent")
    excluded = run_scan(project_root=tmp_path, exclude_rules=[UNPINNED])
    assert [f.rule_id for f in excluded.findings if f.rule_id in LAUNCH_RULES] == ["AAK-SUPPLY-001"]
    only_007 = run_scan(project_root=tmp_path, rules=["AAK-MCP-007", UNPINNED])
    assert [f.rule_id for f in only_007.findings] == [UNPINNED]


def test_a_launch_pinned_outside_the_list_is_quiet(tmp_path: Path) -> None:
    _mcp(tmp_path, "-y", "local-commander-agent@0.3.61")
    assert [r for r in _launch_findings(tmp_path) if r[0] in (RULE, UNPINNED)] == []


def test_a_launch_pinned_to_the_listed_release_stays_001(tmp_path: Path) -> None:
    _mcp(tmp_path, "-y", "local-commander-agent@0.3.52")
    assert [r for r in _launch_findings(tmp_path) if r[0] in (RULE, UNPINNED)] == [
        (RULE, "critical", ".mcp.json", 7),
    ]


def test_vs_code_servers_map_reads_the_same(tmp_path: Path) -> None:
    _mcp(tmp_path, "-y", "local-commander-agent", name=".vscode/mcp.json", key="servers")
    assert _launch_findings(tmp_path) == [(UNPINNED, "high", ".vscode/mcp.json", 7)]


def test_an_unpinned_uvx_launch_of_litellm_names_mal_2026_2144(tmp_path: Path) -> None:
    _mcp(tmp_path, "litellm", command="uvx")
    findings = [f for f in run_scan(project_root=tmp_path).findings if f.rule_id in LAUNCH_RULES]
    assert [(f.rule_id, f.severity) for f in findings] == [(UNPINNED, Severity.HIGH)]
    assert "MAL-2026-2144" in findings[0].evidence
    assert "litellm 1.82.7, 1.82.8, 1.107.0" in findings[0].evidence


def test_an_every_version_entry_stays_001_and_is_not_002(tmp_path: Path) -> None:
    _cached_feed([_entry("aak-typosquat", "npm", all_versions=True)])
    _mcp(tmp_path, "-y", "aak-typosquat")
    assert [r[0] for r in _launch_findings(tmp_path) if r[0] in (RULE, UNPINNED)] == [RULE]


def test_a_name_that_only_starts_with_a_listed_one_is_quiet(tmp_path: Path) -> None:
    _mcp(tmp_path, "-y", "local-commander-agentx")
    assert [r for r in _launch_findings(tmp_path) if r[0] in (RULE, UNPINNED)] == []


@pytest.mark.parametrize(
    "spec, fires",
    [
        ("local-commander-agent@latest", True),   # a tag is whatever the registry says today
        ("local-commander-agent@^0.3.0", True),   # admits 0.3.52
        ("local-commander-agent@~0.3.50", True),
        ("local-commander-agent@^0.3.53", False),  # starts above the listed release
        ("local-commander-agent@>=0.4.0", False),
        ("github:example/local-commander-agent", False),  # not the registry
    ],
)
def test_a_range_is_reported_only_when_it_admits_a_listed_release(tmp_path: Path, spec: str, fires: bool) -> None:
    _mcp(tmp_path, "-y", spec)
    assert any(r[0] == UNPINNED for r in _launch_findings(tmp_path)) is fires


def test_002_stands_down_only_supply_001_at_or_below_its_severity(tmp_path: Path) -> None:
    from dataclasses import replace

    from agent_audit_kit.engine import _drop_launches_supply_chain_reports

    _mcp(tmp_path, "-y", "local-commander-agent")
    findings = run_scan(project_root=tmp_path, exclude_rules=[UNPINNED]).findings
    supply = [f for f in findings if f.rule_id == "AAK-SUPPLY-001"]
    (unpinned,) = [f for f in run_scan(project_root=tmp_path, rules=[UNPINNED]).findings]
    assert _drop_launches_supply_chain_reports(supply + [unpinned]) == [unpinned]
    lowered = replace(unpinned, severity=Severity.LOW)
    assert _drop_launches_supply_chain_reports(supply + [lowered]) == supply + [lowered]
    elsewhere = replace(unpinned, file_path="other/.mcp.json")
    assert _drop_launches_supply_chain_reports(supply + [elsewhere]) == supply + [elsewhere]


def test_a_launch_key_does_not_match_a_longer_package_name() -> None:
    from agent_audit_kit.scanners._launchers import launch_head, names_launch

    evidence = launch_head("lc", "pkg-two") + " is launched by `npx pkg-two`"
    assert names_launch(evidence, launch_head("lc", "pkg-two"))
    assert not names_launch(evidence, launch_head("lc", "pkg"))


# ---- the launchers' caches (--include-user-config) -------------------------------------------


def _npx_cache(tmp_path: Path, name: str, version: str) -> Path:
    cache = tmp_path / "npm-cache"
    package = cache / "_npx" / "0123456789abcdef" / "node_modules" / name
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": name, "version": version}, indent=2))
    return cache


def test_the_npx_cache_is_read_only_when_asked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    cache = _npx_cache(tmp_path, "local-commander-agent", "0.3.52")
    monkeypatch.setenv("npm_config_cache", str(cache))
    assert [f for f in run_scan(project_root=project).findings if f.rule_id == RULE] == []
    (finding,) = [f for f in run_scan(project_root=project, include_user_config=True).findings
                  if f.rule_id == RULE]
    where = cache / "_npx" / "0123456789abcdef" / "node_modules" / "local-commander-agent"
    assert finding.file_path == (where / "package.json").as_posix() and finding.line_number == 3
    assert finding.evidence.startswith(f"npx cache at {where.as_posix()} holds local-commander-agent 0.3.52")
    assert "MAL-2026-18425" in finding.evidence and finding.severity is Severity.CRITICAL


def test_the_npx_cache_defaults_to_dot_npm_and_reads_scoped_packages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    _cached_feed([_entry("@aak/evil", "npm", versions=["1.0.0"])])
    home = Path(os.environ["HOME"])
    for key in [k for k in os.environ if k.lower() == "npm_config_cache"]:
        monkeypatch.delenv(key)
    _npx_cache(home, "@aak/evil", "1.0.0").rename(home / ".npm")
    findings = [f for f in run_scan(project_root=tmp_path, include_user_config=True).findings if f.rule_id == RULE]
    assert [f.file_path for f in findings] == [
        (home / ".npm" / "_npx" / "0123456789abcdef" / "node_modules" / "@aak" / "evil" / "package.json").as_posix()
    ]


def test_a_cached_release_the_feed_does_not_list_is_quiet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("npm_config_cache", str(_npx_cache(tmp_path, "local-commander-agent", "0.3.61")))
    project = tmp_path / "project"
    project.mkdir()
    assert [f for f in run_scan(project_root=project, include_user_config=True).findings if f.rule_id == RULE] == []


def _uv_env(cache: Path, version: str = "1.107.0", linked: bool = True) -> Path:
    archive = cache / "archive-v0" / "abcdEFGHijkl0123"
    dist = archive / "lib" / "python3.12" / "site-packages" / f"litellm-{version}.dist-info"
    dist.mkdir(parents=True)
    (archive / "pyvenv.cfg").write_text("home = /usr/bin\n")
    (dist / "METADATA").write_text(f"Metadata-Version: 2.1\nName: litellm\nVersion: {version}\n")
    entry = cache / "environments-v2" / "253c7120a97b53a1" / "b2ea1928ed61d84d"
    entry.parent.mkdir(parents=True)
    if linked:
        entry.symlink_to(archive, target_is_directory=True)
    else:
        archive.rename(entry)
    return entry


@pytest.mark.parametrize("linked", [True, False], ids=["uv-0.9-link", "directory"])
def test_the_uv_cache_environments_are_read_when_asked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, linked: bool) -> None:
    cache = tmp_path / "uv-cache"
    entry = _uv_env(cache, linked=linked)
    monkeypatch.setenv("UV_CACHE_DIR", str(cache))
    project = tmp_path / "project"
    project.mkdir()
    assert [f for f in run_scan(project_root=project).findings if f.rule_id == RULE] == []
    (finding,) = [f for f in run_scan(project_root=project, include_user_config=True).findings
                  if f.rule_id == RULE]
    dist = entry / "lib" / "python3.12" / "site-packages" / "litellm-1.107.0.dist-info"
    assert finding.file_path == (dist / "METADATA").as_posix() and finding.line_number == 3
    assert finding.evidence.startswith(f"uvx cache at {dist.as_posix()} holds litellm 1.107.0")
    assert "MAL-2026-2144" in finding.evidence


def test_a_uv_environment_under_the_scan_root_is_reported_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / ".cache" / "uv"
    _uv_env(cache)
    monkeypatch.setenv("UV_CACHE_DIR", str(cache))
    findings = [f for f in run_scan(project_root=tmp_path, include_user_config=True).findings if f.rule_id == RULE]
    assert [f.file_path for f in findings] == [
        ".cache/uv/archive-v0/abcdEFGHijkl0123/lib/python3.12/site-packages/litellm-1.107.0.dist-info/METADATA"
    ]


def test_the_cache_directories_follow_the_documented_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import os

    from agent_audit_kit.scanners.malicious_releases import npm_cache_dir, uv_cache_dir

    home = Path(os.environ["HOME"])
    for key in [k for k in os.environ if k.lower() == "npm_config_cache"]:
        monkeypatch.delenv(key)
    monkeypatch.delenv("UV_CACHE_DIR")
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    if os.name != "nt":
        assert npm_cache_dir() == home / ".npm"
        assert uv_cache_dir() == home / ".cache" / "uv"
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        assert uv_cache_dir() == tmp_path / "xdg" / "uv"
        monkeypatch.setenv("XDG_CACHE_HOME", "relative/xdg")  # XDG ignores a relative path
        assert uv_cache_dir() == home / ".cache" / "uv"
    monkeypatch.setenv("NPM_CONFIG_CACHE", str(tmp_path / "npm"))  # npm reads its variables in any case
    assert npm_cache_dir() == tmp_path / "npm"


def test_aak_scan_include_user_config_reads_the_caches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("npm_config_cache", str(_npx_cache(tmp_path, "local-commander-agent", "0.3.52")))
    project = tmp_path / "project"
    project.mkdir()
    args = ["scan", str(project), "--format", "json", "--severity", "info", "--fail-on", "none"]
    plain = json.loads(CliRunner().invoke(cli, args).output)
    asked = json.loads(CliRunner().invoke(cli, args + ["--include-user-config"]).output)
    assert RULE not in {f["ruleId"] for f in plain["findings"]}
    assert RULE in {f["ruleId"] for f in asked["findings"]}


def test_each_server_launching_the_package_is_its_own_finding(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {
        name: {"command": "npx", "args": ["-y", "local-commander-agent"]} for name in ("a", "b")}}, indent=2))
    findings = [f for f in run_scan(project_root=tmp_path).findings if f.rule_id in LAUNCH_RULES]
    assert sorted((f.rule_id, f.evidence.split(" is launched")[0]) for f in findings) == [
        (UNPINNED, "Server 'a' arg: local-commander-agent"),
        (UNPINNED, "Server 'b' arg: local-commander-agent"),
    ]
