"""AAK-KNOWN-VULN-002: NVD records matched to the MCP servers, binaries and images a project launches.

On 0.6.29, and on main after #1149, a project whose `.mcp.json` ran MoLing 0.4.0
scanned clean: MoLing is a Go MCP server shipped as a binary, its NVD record of
30 Oct 2026 (CVE-2026-62863, CVSS 9.6) names vendor `gojue` and product `moling`
and no package, and GitHub's CNA writes its range as the text `< 0.5.0`. TAKO
(`fctrid/ai-agent-for-okta`, CVE-2026-63377 at 9.8 and CVE-2026-63378 at 8.8) was
in the same place. These tests pin the order's fixtures under tests/fixtures/launch,
the launches the rule reads (a command, `go run`, `docker run`, a repository URL, a
shell line, YAML and Dockerfile image references), how a release is read (semver,
pre-releases, two-part tags, `latest`, digests), one finding per file and advisory,
and the engine pass that keeps a version pin's finding over this one. The feed is
the bundled one, or a cached file written here; nothing is fetched.
"""

from __future__ import annotations

import json
import random
import re
import shutil
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit import advisory_feed
from agent_audit_kit.scanners import known_vulns_launch as launch_module
from agent_audit_kit.scanners.container_image_pins import _COMMENT_RE, _REPOSITORY_KEY_RE, _TAG_RE, _in_image_slot
from agent_audit_kit.engine import _drop_known_vulns_a_rule_reports, run_scan
from agent_audit_kit.models import Finding, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners._helpers import make_finding
from agent_audit_kit.scanners.known_vulns_launch import RULE, scan

FIXTURES = Path(__file__).parent / "fixtures" / "launch"
MOLING, TAKO_ADMIN, TAKO_PYTHON = "CVE-2026-62863", "CVE-2026-63377", "CVE-2026-63378"
_CVES = (MOLING, TAKO_ADMIN, TAKO_PYTHON)


def _found(root: Path) -> list[tuple[Severity, str, str, int | None]]:
    """(severity, the CVE the evidence names, file, line) per finding, in order."""
    findings, _ = scan(root)
    assert all(f.rule_id == RULE for f in findings)
    out = []
    for f in findings:
        (cve,) = [c for c in _CVES if c in f.evidence]
        out.append((f.severity, cve, f.file_path, f.line_number))
    return out


def _evidence(root: Path) -> list[str]:
    return [f.evidence for f in scan(root)[0]]


def _project(tmp_path: Path, files: dict[str, Any]) -> Path:
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else json.dumps(content, indent=2), encoding="utf-8")
    return tmp_path


def _server(command: str | list[str], *args: str, key: str = "mcpServers") -> dict[str, Any]:
    return {key: {"s": {"command": command, "args": list(args)}}}


# ---- the order's fixtures ---------------------------------------------------------------------------


def test_moling_launched_with_go_run_at_0_4_0_is_critical() -> None:
    assert _found(FIXTURES / "moling-vulnerable") == [(Severity.CRITICAL, MOLING, ".mcp.json", 5)]
    (evidence,) = _evidence(FIXTURES / "moling-vulnerable")
    assert evidence.startswith(
        "`go run github.com/gojue/moling@v0.4.0` in .mcp.json launches gojue/moling v0.4.0, which CVE-2026-62863 "
        "(NVD CNA record, CVSS 3.x 9.6) lists as affected; it is fixed in 0.5.0 "
        "(https://nvd.nist.gov/vuln/detail/CVE-2026-62863). Feed: the bundled copy generated ")


def test_moling_at_0_5_0_is_clean() -> None:
    assert _found(FIXTURES / "moling-fixed") == []


def test_moling_started_by_its_binary_is_medium_naming_the_range_and_the_fix() -> None:
    assert _found(FIXTURES / "moling-unpinned") == [(Severity.MEDIUM, MOLING, ".mcp.json", 4)]
    (evidence,) = _evidence(FIXTURES / "moling-unpinned")
    assert "could not be read" in evidence and "lists < 0.5.0 as affected; it is fixed in 0.5.0" in evidence
    assert evidence.startswith("`/usr/local/bin/moling` in .mcp.json launches gojue/moling, but it starts the "
                               "installed `moling` binary, whose release the config does not state")


def test_vs_code_s_servers_key_reaches_the_same_result() -> None:
    assert _found(FIXTURES / "moling-vscode") == [(Severity.CRITICAL, MOLING, ".vscode/mcp.json", 6)]


def test_an_unrelated_server_named_molingx_is_quiet() -> None:
    """Neither the `molingx` binary nor the github.com/gojue/molingx module is MoLing."""
    assert _found(FIXTURES / "molingx") == []


def test_tako_s_image_in_a_compose_file_reports_both_cves() -> None:
    """STEP 0 found the image in TAKO's own docker-compose.yml, so its fixture is a compose file."""
    assert _found(FIXTURES / "tako-compose-vulnerable") == [
        (Severity.CRITICAL, TAKO_ADMIN, "docker-compose.yml", 3),
        (Severity.HIGH, TAKO_PYTHON, "docker-compose.yml", 3),
    ]
    assert _found(FIXTURES / "tako-compose-fixed") == []


def test_through_the_engine_the_rule_reports_and_nothing_stands_it_down() -> None:
    result = run_scan(project_root=FIXTURES / "moling-vulnerable")
    assert [(f.rule_id, f.severity) for f in result.findings if f.rule_id == RULE] == [(RULE, Severity.CRITICAL)]


def test_the_rule_is_registered_critical_and_feed_driven() -> None:
    rule = RULES[RULE]
    assert rule.severity is Severity.CRITICAL and rule.cve_references == []
    assert rule.limitations.endswith("A file over 2 MB is not read.")


# ---- how a release is read --------------------------------------------------------------------------


@pytest.mark.parametrize("tag, expected", [
    ("3.0.0-beta", [(Severity.CRITICAL, TAKO_ADMIN), (Severity.HIGH, TAKO_PYTHON)]),
    # The tag TAKO's compose at v3.0.1-beta runs, pushed an hour before the fix commit.
    ("3.0.1-alpha", [(Severity.CRITICAL, TAKO_ADMIN), (Severity.HIGH, TAKO_PYTHON)]),
    ("v2.1.1", [(Severity.CRITICAL, TAKO_ADMIN), (Severity.HIGH, TAKO_PYTHON)]),
    ("3.0.1-beta", []),
    ("3.1.1", []),
    ("3.1", []),                                                                 # the whole 3.1 line is fixed
    ("2.1", [(Severity.CRITICAL, TAKO_ADMIN), (Severity.HIGH, TAKO_PYTHON)]),    # the whole 2.1 line is affected
    ("3.0", [(Severity.MEDIUM, TAKO_ADMIN), (Severity.MEDIUM, TAKO_PYTHON)]),    # both: could not be read
    ("latest", [(Severity.MEDIUM, TAKO_ADMIN), (Severity.MEDIUM, TAKO_PYTHON)]),
    ("arm64-m-test", [(Severity.MEDIUM, TAKO_ADMIN), (Severity.MEDIUM, TAKO_PYTHON)]),
])
def test_an_image_tag_is_read_as_semver(tmp_path: Path, tag: str, expected: list[tuple[Severity, str]]) -> None:
    root = _project(tmp_path, {"compose.yaml": f"services:\n  tako:\n    image: fctrid/ai-agent-for-okta:{tag}\n"})
    assert [(severity, cve) for severity, cve, _, _ in _found(root)] == expected


@pytest.mark.parametrize("version, severity", [
    ("v0.4.0", Severity.CRITICAL),
    ("v0.4.1-0.20251001000000-abcdef123456", Severity.CRITICAL),   # a pseudo-version after 0.4.0
    ("v0.5.1-0.20251101000000-abcdef123456", None),                # one after the fix
    ("v0.4", Severity.CRITICAL),                                   # the newest v0.4.x, all affected
    ("v0.5.0", None),
    ("latest", Severity.MEDIUM),
    ("master", Severity.MEDIUM),
    ("ae07f704cbc88d4419fc0fbaec278090fcd0502d", Severity.MEDIUM),
])
def test_go_run_reads_the_module_version(tmp_path: Path, version: str, severity: Severity | None) -> None:
    root = _project(tmp_path, {".mcp.json": _server("go", "run", f"github.com/gojue/moling@{version}", "-l", ":8080")})
    assert [s for s, _, _, _ in _found(root)] == ([severity] if severity else [])


def test_go_run_of_a_package_inside_the_module_is_the_module(tmp_path: Path) -> None:
    root = _project(tmp_path, {".mcp.json": _server("go", "run", "-mod=mod", "github.com/gojue/moling/cli@v0.4.0")})
    assert [s for s, _, _, _ in _found(root)] == [Severity.CRITICAL]


@pytest.mark.parametrize("server, expected", [
    (_server("docker", "run", "-i", "--rm", "-e", "OKTA_ORG=x", "fctrid/ai-agent-for-okta:3.0.0-beta"),
     [Severity.CRITICAL, Severity.HIGH]),
    (_server("podman", "run", "docker.io/fctrid/ai-agent-for-okta:3.0.0-beta"), [Severity.CRITICAL, Severity.HIGH]),
    (_server("docker", "run", "fctrid/ai-agent-for-okta"), [Severity.MEDIUM, Severity.MEDIUM]),
    (_server("docker", "run", "fctrid/ai-agent-for-okta@sha256:" + "a" * 64), [Severity.MEDIUM, Severity.MEDIUM]),
    (_server("docker", "run", "fctrid/ai-agent-for-okta:3.1.1"), []),
    (_server("docker", "run", "fctrid/ai-agent-for-okta-extra:1.0.0"), []),
    (_server("docker", "pull", "fctrid/ai-agent-for-okta:3.0.0-beta"), []),   # not a launch
])
def test_docker_run_in_an_mcp_config(tmp_path: Path, server: dict[str, Any], expected: list[Severity]) -> None:
    root = _project(tmp_path, {".mcp.json": server})
    assert [s for s, _, _, _ in _found(root)] == expected


@pytest.mark.parametrize("arg, expected", [
    ("git+https://github.com/fctr-id/okta-ai-agent@v3.0.0-beta", [Severity.CRITICAL, Severity.HIGH]),
    ("https://github.com/fctr-id/okta-ai-agent/archive/refs/tags/v3.0-beta.tar.gz",
     [Severity.MEDIUM, Severity.MEDIUM]),      # `3.0-beta` is not a release
    ("https://github.com/gojue/moling/releases/download/v0.4.0/moling_0.4.0_linux_amd64.tar.gz",
     [Severity.CRITICAL]),
    ("github.com/fctr-id/okta-ai-agent", [Severity.MEDIUM, Severity.MEDIUM]),
    ("git+https://github.com/fctr-id/okta-ai-agent#egg=tako", [Severity.MEDIUM, Severity.MEDIUM]),
    ("https://github.com/gojue/moling/blob/master/README.md", []),          # a link into it is not a launch
    ("github:fctr-id/okta-ai-agent#v3.0.0-beta", []),                      # GitHub shorthand: a stated blind spot
    ("--docs=https://github.com/gojue/moling", []),
    ("https://github.com/gojue/moling-extras@v0.1.0", []),
])
def test_a_repository_url_argument(tmp_path: Path, arg: str, expected: list[Severity]) -> None:
    root = _project(tmp_path, {".mcp.json": _server("uvx", "--from", arg, "tool")})
    assert [s for s, _, _, _ in _found(root)] == expected


@pytest.mark.parametrize("server, expected", [
    (_server("bash", "-c", "go run github.com/gojue/moling@v0.4.0 -l 127.0.0.1:8080"), [Severity.CRITICAL]),
    (_server("cmd", "/c", "moling.exe"), [Severity.MEDIUM]),
    (_server("sh", "-c", "bash -c 'moling -l :8080'"), [Severity.MEDIUM]),
    (_server("go run github.com/gojue/moling@v0.4.0"), [Severity.CRITICAL]),   # the whole line in `command`
    (_server(["go", "run", "github.com/gojue/moling@v0.4.0"]), [Severity.CRITICAL]),
    (_server("C:\\tools\\MoLing.exe"), [Severity.MEDIUM]),
    ({"mcpServers": {"s": {"url": "http://127.0.0.1:8080/sse"}}}, []),        # starts nothing
])
def test_shell_lines_and_command_forms(tmp_path: Path, server: dict[str, Any], expected: list[Severity]) -> None:
    root = _project(tmp_path, {".mcp.json": server})
    assert [s for s, _, _, _ in _found(root)] == expected


@pytest.mark.parametrize("files, expected", [
    ({"compose.yaml": "services:\n  t:\n    # image: fctrid/ai-agent-for-okta:3.0.0-beta\n    image: busybox\n"}, []),
    ({"compose.yaml": "x-note: run fctrid/ai-agent-for-okta for the agent\nservices: {}\n"}, []),
    ({"values.yaml": "image:\n  repository: fctrid/ai-agent-for-okta\n  tag: 3.0.0-beta\n"},
     [(Severity.CRITICAL, TAKO_ADMIN, "values.yaml", 2), (Severity.HIGH, TAKO_PYTHON, "values.yaml", 2)]),
    ({"Dockerfile": "FROM --platform=linux/amd64 fctrid/ai-agent-for-okta:3.0.0-beta\nRUN true\n"},
     [(Severity.CRITICAL, TAKO_ADMIN, "Dockerfile", 1), (Severity.HIGH, TAKO_PYTHON, "Dockerfile", 1)]),
    ({"Dockerfile": "FROM fctrid/ai-agent-for-okta\n"},
     [(Severity.MEDIUM, TAKO_ADMIN, "Dockerfile", 1), (Severity.MEDIUM, TAKO_PYTHON, "Dockerfile", 1)]),
    ({"k8s/deploy.yaml": "spec:\n  containers:\n  - name: t\n    image: \"fctrid/ai-agent-for-okta:${TAG}\"\n"}, []),
])
def test_yaml_and_dockerfile_references(tmp_path: Path, files: dict[str, str],
                                        expected: list[tuple[Severity, str, str, int]]) -> None:
    assert _found(_project(tmp_path, files)) == expected


# ---- what it does not see (the rule's limitations) -------------------------------------------------


def test_a_yaml_mcp_config_s_command_is_not_read(tmp_path: Path) -> None:
    """A YAML file is read for image references only, so a server it starts is not seen."""
    files = {"mcp.yaml": "mcpServers:\n  moling:\n    command: go\n    args: [run, github.com/gojue/moling@v0.4.0]\n"}
    assert _found(_project(tmp_path, files)) == []


@pytest.mark.parametrize("name, head", [
    (".mcp.json", json.dumps(_server("go", "run", "github.com/gojue/moling@v0.4.0"), indent=2)),
    ("Dockerfile", "FROM fctrid/ai-agent-for-okta:3.0.0-beta\n"),
], ids=["json", "dockerfile"])
def test_a_file_over_2_mb_is_not_read(tmp_path: Path, name: str, head: str) -> None:
    """The cap the limitations end on: a file of exactly MAX_FILE_BYTES is read, one byte more is not."""
    for size, read in ((launch_module.MAX_FILE_BYTES, True), (launch_module.MAX_FILE_BYTES + 1, False)):
        pad = size - len(head.encode()) - 2
        filler = " " * (pad + 2) if name.endswith(".json") else "#" + "x" * pad + "\n"
        root = tmp_path / str(size)
        _project(root, {name: head + filler})
        assert (root / name).stat().st_size == size
        assert bool(scan(root)[0]) is read


def test_an_image_tag_suffix_reads_as_a_pre_release(tmp_path: Path) -> None:
    """`1.2.3-alpine` is semver's pre-release of 1.2.3, so for a fix in 1.2.3 it reads affected."""
    entry = {"id": "CVE-2026-0001", "aliases": [], "ecosystem": "launch", "name": "example/agent",
             "ranges": [{"introduced": "0", "fixed": "1.2.3"}], "versions": [], "fixed": ["1.2.3"],
             "severity": "HIGH", "score": 7.5, "scored_by": "nvd-cvss3", "modified": "t",
             "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001", "source": "nvd", "cna": "test",
             "mapped_by": "map", "repo": "github.com/example/agent",
             "match": {"commands": [], "go_modules": [], "images": ["example/agent"]}}
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "entries": [], "nvd": [], "launch": [entry]}))
    reported = {}
    for tag in ("1.2.2-alpine", "1.2.3-alpine", "1.2.3", "1.2.4-alpine"):
        root = _project(tmp_path / tag, {"compose.yaml": f"services:\n  a:\n    image: example/agent:{tag}\n"})
        reported[tag] = [f.severity for f in scan(root)[0]]
    assert reported == {"1.2.2-alpine": [Severity.HIGH], "1.2.3-alpine": [Severity.HIGH],
                        "1.2.3": [], "1.2.4-alpine": []}


# ---- one finding per file and advisory --------------------------------------------------------------


def test_one_finding_per_file_and_advisory_counting_the_rest(tmp_path: Path) -> None:
    config = {"mcpServers": {
        "a": {"command": "moling", "args": []},                                         # could not be read
        "b": {"command": "go", "args": ["run", "github.com/gojue/moling@v0.4.0"]},       # in range
        "c": {"command": "go", "args": ["run", "github.com/gojue/moling@v0.3.2"]},       # in range
        "d": {"command": "go", "args": ["run", "github.com/gojue/moling@v0.5.0"]},       # outside it
    }}
    root = _project(tmp_path, {".mcp.json": config})
    (finding,) = scan(root)[0]
    assert finding.severity is Severity.CRITICAL and finding.line_number == 11  # b's module, one argument a line
    assert "launches gojue/moling v0.4.0 (and 1 more launch in its range)" in finding.evidence


def test_each_file_is_judged_on_its_own(tmp_path: Path) -> None:
    root = _project(tmp_path, {"a/.mcp.json": _server("moling"), "b/.mcp.json": _server("go", "run",
                                                                                         "github.com/gojue/moling@v0.4.0")})
    assert [(s, f) for s, _, f, _ in _found(root)] == [(Severity.MEDIUM, "a/.mcp.json"),
                                                       (Severity.CRITICAL, "b/.mcp.json")]


def test_files_the_rule_cannot_read_are_skipped(tmp_path: Path) -> None:
    root = _project(tmp_path, {".mcp.json": "{ not json", "node_modules/x/.mcp.json": _server("moling")})
    assert scan(root)[0] == []


# ---- the feed it reads ------------------------------------------------------------------------------


def test_with_no_launch_entries_nothing_is_read(tmp_path: Path) -> None:
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "entries": [], "nvd": [], "launch": []}))
    shutil.copytree(FIXTURES / "moling-vulnerable", tmp_path / "p")
    assert scan(tmp_path / "p") == ([], set())


def test_a_cache_written_before_launch_rows_still_reports_the_bundled_ones() -> None:
    """0.6.29's `aak update` wrote no `launch` list; until the next update, the bundled one stands in."""
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "entries": []}))
    assert _found(FIXTURES / "moling-vulnerable") == [(Severity.CRITICAL, MOLING, ".mcp.json", 5)]


# ---- the engine pass shared with AAK-KNOWN-VULN-001 -------------------------------------------------


def _launch(severity: Severity, line: int = 3) -> Finding:
    finding = make_finding(RULE, "compose.yaml", f"... which {TAKO_ADMIN} (NVD CNA record) lists as affected", line)
    finding.severity = severity
    return finding


def _pin(severity: Severity, rule: str = "AAK-MCP-OBOT-CVE-2026-101084-001", line: int = 3) -> Finding:
    finding = make_finding(rule, "compose.yaml", "pinned", line)
    finding.severity = severity
    finding.cve_references = [TAKO_ADMIN]
    return finding


@pytest.mark.parametrize("pin, kept", [
    (_pin(Severity.CRITICAL), False),
    (_pin(Severity.HIGH), True),            # below this finding's severity
    (_pin(Severity.CRITICAL, line=4), True),  # another line
])
def test_a_rule_reporting_the_cve_on_the_line_stands_this_one_down(pin: Finding, kept: bool) -> None:
    launch = _launch(Severity.CRITICAL)
    out = _drop_known_vulns_a_rule_reports([launch, pin])
    assert (launch in out) is kept and pin in out


def test_the_two_feed_rules_never_stand_each_other_down() -> None:
    launch = _launch(Severity.CRITICAL)
    package = make_finding("AAK-KNOWN-VULN-001", "compose.yaml", f"... {TAKO_ADMIN} ...", 3)
    package.cve_references = [TAKO_ADMIN]
    out = _drop_known_vulns_a_rule_reports([launch, package])
    assert launch in out and package in out


# ---- the image reader: container_image_pins' rules, read in one pass ---------------------------------


def _reference_refs(text: str, kind: str, pattern: re.Pattern[str]) -> list[tuple[str, str | None, bool, int]]:
    """`container_image_pins._inline_hit`'s rules applied to every reference, each
    line prefix sliced and searched again: the reading `_inline_refs` must give."""
    out = []
    for m in pattern.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        prefix = text[line_start:m.start()]
        if _COMMENT_RE.search(prefix) or (kind == "yaml" and _REPOSITORY_KEY_RE.search(prefix)):
            continue
        line = text.count("\n", 0, m.start()) + 1
        nxt = text[m.end():m.end() + 1]
        if nxt == ":":
            tag_m = _TAG_RE.match(text, m.end())
            if tag_m is not None:
                out.append((text[m.start():tag_m.end()], tag_m.group(1), False, line))
            continue
        end, digest = m.end(), False
        if nxt == "@":
            digest_m = launch_module._DIGEST_RE.match(text, m.end())
            if digest_m is None:
                continue
            end, digest = digest_m.end(), True
        before = text[m.start() - 1:m.start()]
        if (before in ("'", '"') and text[end:end + 1] == before) or _in_image_slot(prefix):
            out.append((text[m.start():end], None, digest, line))
    return out


_NAMES = ("fctrid/ai-agent-for-okta", "docker.io/fctrid/ai-agent-for-okta", "FCTRID/AI-Agent-For-Okta",
          "xfctrid/ai-agent-for-okta", "fctrid/ai-agent-for-okta-x", "index.docker.io/fctrid/ai-agent-for-okta")
_TAILS = ("", ":3.0.0-beta", ":latest", ":${T}", "@sha256:" + "ab" * 32, ":3.1@sha256:" + "cd" * 32, "@nope", ":")
_LEADS = ("image: ", "image:", "  image:  '", 'Image : "', "myimage: ", "# ", "x # ", "x#", "FROM ",
          "FROM --platform=linux/amd64 ", "FROM -- ", "from\t", "FROM -x ", "repository: ", "  - '", "note: run ",
          "image:" + " " * 300, "  repository:   \"", "", "'", '"')
_ENDS = ("", "'", '"', " # c", " x", "\t")


@pytest.mark.parametrize("kind", ["yaml", "dockerfile"])
def test_the_image_reader_reads_what_container_image_pins_reads(kind: str) -> None:
    rng = random.Random(f"launch-{kind}")
    (pattern, _entries), = launch_module._index(advisory_feed.load_feed().launch).image_res
    for _ in range(3000):
        lines = []
        for _ in range(rng.randint(1, 4)):
            lines.append("".join(rng.choice(_LEADS) + rng.choice(_NAMES) + rng.choice(_TAILS) + rng.choice(_ENDS)
                                 for _ in range(rng.randint(1, 3))))
        text = "\n".join(lines) + rng.choice(("", "\n"))
        assert list(launch_module._inline_refs(text, kind, pattern)) == _reference_refs(text, kind, pattern), text
