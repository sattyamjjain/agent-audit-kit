"""Container image tag pins (scanners/container_image_pins.py).

Obot, MetaMCP and heym ship only as container images, so their CVEs were
deferred (#836-#838, #842, #848, #849) or recorded as non-pinnable (#854) until
something read an image tag. Each pin is measured on its fixtures through the
scanner and through a full `run_scan`:

- Obot: v0.21.0, v0.22.1, v0.24.1 (Helm values) and v0.24.2 (the 0.24 backport
  without #7375) fire; v0.25.0 does not.
- MetaMCP: 2.4.22 and `latest` (the same image on 2026-10-03) fire. There is no
  fixed release, so the negative is a reference that states no version.
- heym: 0.0.108 fires, 0.0.109 does not.
- mark3labs mcp-filesystem-server (#881): 0.11.1 and `latest` fire. There is no
  fixed release, so the negative is a look-alike image and an interpolated tag.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.container_image_pins import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves"
OBOT = "AAK-MCP-OBOT-CVE-2026-101084-001"
# CVE-2026-105138 (#926): v0.12.0 up to v0.26.2, so every Obot tag below the
# CRITICAL pin's v0.25.0 floor from v0.12.0 on is reported by both rules.
OBOT_STATIC = "AAK-MCP-OBOT-CVE-2026-105138-001"
METAMCP = "AAK-MCP-METAMCP-CVE-2026-79538-001"
HEYM = "AAK-MCP-HEYM-CVE-2026-100858-001"
MARK3LABS_FS = "AAK-MCP-MARK3LABS-FS-CVE-2026-79534-001"
# CVE-2026-108115 (#957): Kortix's API image from 0.10.7 up to 0.13.52.
KORTIX = "AAK-MCP-KORTIX-CVE-2026-108115-001"
# CVE-2026-108865 (#973): Unla's gateway images, every tag through v0.10.0.
UNLA = "AAK-MCP-UNLA-CVE-2026-108865-001"
# CVE-2026-108756 (#976): Trinity's backend image through 0.9.5.
TRINITY = "AAK-MCP-TRINITY-CVE-2026-108756-001"


def _ids(root: Path) -> list[str]:
    return [f.rule_id for f in scan(root)[0]]


def _write(tmp_path: Path, name: str, content: str) -> list[str]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return _ids(tmp_path)


def test_each_pin_carries_its_cves_and_severity() -> None:
    assert RULES[OBOT].cve_references == [
        "CVE-2026-101084", "CVE-2026-101062", "CVE-2026-103758", "CVE-2026-101064",
        "CVE-2026-101063",
    ]
    assert RULES[METAMCP].cve_references == ["CVE-2026-79538", "CVE-2026-79537"]
    assert RULES[HEYM].cve_references == ["CVE-2026-100858"]
    assert RULES[MARK3LABS_FS].cve_references == ["CVE-2026-79534"]
    assert [RULES[r].severity.value for r in (OBOT, METAMCP, HEYM, MARK3LABS_FS)] == [
        "critical", "critical", "medium", "medium",
    ]


def test_obot_registry_auth_cve_rides_the_existing_floor(tmp_path: Path) -> None:
    """CVE-2026-101063 (#882) is fixed in v0.23.0, below the pin's v0.25.0 floor, so
    every version it affects is already reported: it joins the rule, no new pin."""
    ids = _write(tmp_path, "compose.yaml", "services:\n  o:\n    image: ghcr.io/obot-platform/obot:v0.22.0\n")
    assert ids == [OBOT, OBOT_STATIC]


@pytest.mark.parametrize("case, line", [("vulnerable", 10), ("vulnerable-tagged", 5)])
def test_mark3labs_filesystem_fixtures_fire(case: str, line: int) -> None:
    """CVE-2026-79534 (#881): `latest` in an MCP config's docker args, and 0.11.1 in
    compose. The release workflow pushes `latest` only from tags, so it is 0.11.1."""
    root = FIXTURES / "cve-2026-79534-mark3labs-filesystem" / case
    findings = scan(root)[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(MARK3LABS_FS, line)]
    assert MARK3LABS_FS in {f.rule_id for f in run_scan(root).findings}


def test_mark3labs_filesystem_lookalike_and_interpolated_tag_are_quiet() -> None:
    root = FIXTURES / "cve-2026-79534-mark3labs-filesystem" / "negative"
    assert _ids(root) == []
    assert MARK3LABS_FS not in {f.rule_id for f in run_scan(root).findings}


@pytest.mark.parametrize(("tag", "fires"), [
    ("0.6.0", True),     # the oldest tag has the same fallback
    ("0.11.1", True),
    ("0.11.2", False),   # does not exist; stands for the first fixed tag
    ("main", False),
])
def test_mark3labs_filesystem_tag_reading(tmp_path: Path, tag: str, fires: bool) -> None:
    ids = _write(tmp_path, "compose.yaml", f"services:\n  f:\n    image: ghcr.io/mark3labs/mcp-filesystem-server:{tag}\n")
    assert (MARK3LABS_FS in ids) is fires


@pytest.mark.parametrize(
    "case, line",
    [
        ("vulnerable", 6),             # compose, v0.21.0: all four CVEs
        ("vulnerable-dcr", 20),        # Kubernetes manifest, v0.22.1
        ("vulnerable-composite", 7),   # Helm values, v0.24.1
        ("vulnerable-backport", 5),    # Dockerfile FROM, v0.24.2
    ],
)
def test_obot_fixtures_fire(case: str, line: int) -> None:
    findings = scan(FIXTURES / "cve-2026-101084-obot" / case)[0]
    # Every fixture here is also inside CVE-2026-105138's v0.12.0-v0.26.2 range.
    assert [(f.rule_id, f.line_number) for f in findings] == [(OBOT, line), (OBOT_STATIC, line)]
    assert OBOT in {f.rule_id for f in run_scan(FIXTURES / "cve-2026-101084-obot" / case).findings}


def test_obot_v0_25_0_latest_enterprise_and_empty_helm_tag_are_quiet() -> None:
    """Quiet for the CRITICAL pin. v0.25.0 is still inside CVE-2026-105138's range,
    so the compose file reports that rule once."""
    root = FIXTURES / "cve-2026-101084-obot" / "negative"
    assert _ids(root) == [OBOT_STATIC]
    assert OBOT not in {f.rule_id for f in run_scan(root).findings}


@pytest.mark.parametrize("case", ["vulnerable", "vulnerable-latest"])
def test_metamcp_fixtures_fire(case: str) -> None:
    root = FIXTURES / "cve-2026-79538-metamcp" / case
    assert _ids(root) == [METAMCP]
    assert METAMCP in {f.rule_id for f in run_scan(root).findings}


def test_metamcp_reference_without_a_version_is_quiet() -> None:
    """The npm client proxy, a digest, an interpolated tag, a comment and a
    sentence that names the image: none of them states a deployed version."""
    root = FIXTURES / "cve-2026-79538-metamcp" / "negative"
    assert _ids(root) == []
    assert METAMCP not in {f.rule_id for f in run_scan(root).findings}


def test_heym_fixtures_positive_and_negative() -> None:
    root = FIXTURES / "cve-2026-100858-heym"
    assert _ids(root / "vulnerable") == [HEYM]
    assert _ids(root / "negative") == []
    assert HEYM in {f.rule_id for f in run_scan(root / "vulnerable").findings}


@pytest.mark.parametrize(
    "tag, fires",
    [
        ("v0.20.3", True),
        ("v0.24.1-rc1", True),     # a suffix after the numbers is ignored
        ("v0.24", True),           # the whole 0.24 line is below v0.25.0
        ("v0.25", False),          # 0.25.x floats to fixed releases
        ("v0.25.0", False),
        ("v0.26.2", False),
        ("main", False),
        ("main-20250617", False),
    ],
)
def test_obot_tag_reading(tmp_path: Path, tag: str, fires: bool) -> None:
    ids = _write(tmp_path, "compose.yaml", f"services:\n  o:\n    image: ghcr.io/obot-platform/obot:{tag}\n")
    assert (OBOT in ids) is fires


def test_metamcp_untagged_image_slot_fires(tmp_path: Path) -> None:
    assert _write(tmp_path, "compose.yml", "services:\n  m:\n    image: ghcr.io/metatool-ai/metamcp\n") == [METAMCP]


def test_metamcp_two_part_tag_is_not_read_as_2_4_22(tmp_path: Path) -> None:
    """`2.4` would float to a 2.4.23 if one shipped, so it states no affected version."""
    assert _write(tmp_path, "compose.yml", "services:\n  m:\n    image: ghcr.io/metatool-ai/metamcp:2.4\n") == []


def test_metamcp_release_past_nvd_range_is_not_claimed(tmp_path: Path) -> None:
    assert _write(tmp_path, "compose.yml", "services:\n  m:\n    image: ghcr.io/metatool-ai/metamcp:2.5.0\n") == []


def test_helm_registry_and_repository_are_joined(tmp_path: Path) -> None:
    values = "image:\n  registry: ghcr.io\n  repository: obot-platform/obot\n  tag: v0.22.1\n"
    assert _write(tmp_path, "values.yaml", values) == [OBOT, OBOT_STATIC]


def test_helm_tag_is_read_as_written_not_as_a_float(tmp_path: Path) -> None:
    """`tag: 0.30` loads as the float 0.3, which would read as the 0.3 line and
    fire; composed, it stays "0.30", a line above the v0.25.0 floor."""
    values = "image:\n  repository: ghcr.io/obot-platform/obot\n  tag: %s\n"
    assert _write(tmp_path, "values.yaml", values % "0.30") == []
    assert _write(tmp_path, "values.yaml", values % "0.20") == [OBOT, OBOT_STATIC]


def test_helm_repository_with_a_fixed_tag_is_not_read_as_latest(tmp_path: Path) -> None:
    """MetaMCP fires on an untagged reference, so the Helm `repository:` value
    must be left to the mapping reader, which sees the tag beside it."""
    values = "image:\n  repository: ghcr.io/metatool-ai/metamcp\n  tag: \"2.5.0\"\n"
    assert _write(tmp_path, "values.yaml", values) == []


def test_unparseable_yaml_still_reads_inline_references(tmp_path: Path) -> None:
    template = "image: {{ .Values.x }}\n  bad: [\nimage: ghcr.io/heymrun/heym:0.0.100\n"
    assert _write(tmp_path, "templates/deploy.yaml", template) == [HEYM]


def test_recursive_alias_does_not_hang(tmp_path: Path) -> None:
    content = "a: &a\n  - *a\nimage: ghcr.io/heymrun/heym:0.0.100\n"
    assert _write(tmp_path, "x.yaml", content) == [HEYM]


def test_files_outside_the_reader_are_ignored(tmp_path: Path) -> None:
    """A README and a shell script can name an image; neither is read."""
    (tmp_path / "README.md").write_text("docker run ghcr.io/heymrun/heym:0.0.100\n", encoding="utf-8")
    (tmp_path / "run.sh").write_text("docker run ghcr.io/heymrun/heym:0.0.100\n", encoding="utf-8")
    findings, scanned = scan(tmp_path)
    assert findings == [] and scanned == set()


def test_skip_dirs_are_not_walked(tmp_path: Path) -> None:
    assert _write(tmp_path, "node_modules/x/compose.yml", "image: ghcr.io/heymrun/heym:0.0.100\n") == []


def test_one_finding_per_pin_per_file(tmp_path: Path) -> None:
    compose = (
        "services:\n"
        "  a:\n    image: ghcr.io/obot-platform/obot:v0.22.1\n"
        "  b:\n    image: ghcr.io/obot-platform/obot:v0.21.0\n"
        "  c:\n    image: ghcr.io/heymrun/heym:0.0.100\n"
    )
    findings = scan(_write_root(tmp_path, "compose.yml", compose))[0]
    assert sorted((f.rule_id, f.line_number) for f in findings) == [(HEYM, 7), (OBOT, 3), (OBOT_STATIC, 3)]


def test_every_read_file_counts_as_scanned(tmp_path: Path) -> None:
    (tmp_path / "compose.yml").write_text("services: {}\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
    (tmp_path / "claude_desktop_config.json").write_text("{}\n", encoding="utf-8")
    assert scan(tmp_path) == ([], {"compose.yml", "Dockerfile", "claude_desktop_config.json"})


def _write_root(tmp_path: Path, name: str, content: str) -> Path:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return tmp_path


def test_untagged_from_line_counts_as_an_image_slot(tmp_path: Path) -> None:
    dockerfile = "FROM --platform=linux/amd64 ghcr.io/metatool-ai/metamcp AS app\n"
    assert _write(tmp_path, "Dockerfile", dockerfile) == [METAMCP]
    assert _write(tmp_path, "Dockerfile", "COPY ghcr.io/metatool-ai/metamcp /x\n") == []


# --- 2026-10-06 wave (#906, #907): Docker Hub images by their bare name -------
DIFY = "AAK-MCP-DIFY-CVE-2026-105761-001"
K6 = "AAK-MCP-K6-CVE-2026-89039-001"


def test_dify_and_mcp_k6_pins_carry_their_cves_and_severity() -> None:
    assert RULES[DIFY].cve_references == ["CVE-2026-105761"]
    assert RULES[K6].cve_references == ["CVE-2026-89039"]
    assert [RULES[r].severity.value for r in (DIFY, K6)] == ["high", "medium"]


def test_dify_fixtures_positive_and_negative() -> None:
    """CVE-2026-105761 (#906): 1.15.0, as Dify's compose file pins it, fires on the
    API service's line; 1.16.0 (62cb5b5) does not, and dify-web is never read."""
    root = FIXTURES / "cve-2026-105761-dify"
    findings = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(DIFY, 5)]
    assert DIFY in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("ref", "fires"), [
    ("langgenius/dify-api:1.15.0", True),
    ("langgenius/dify-api:1.16.0", False),
    ("langgenius/dify-api:1.16.0-rc1", False),  # read as 1.16.0
    ("langgenius/dify-api:latest", False),      # 1.17.1 on 2026-10-06
    ("langgenius/dify-api", False),             # untagged is latest
    ("langgenius/dify-web:1.15.0", False),      # the endpoint is in the API server
])
def test_dify_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yaml", f"services:\n  api:\n    image: {ref}\n")
    assert (DIFY in ids) is fires


def test_mcp_k6_fixtures_positive_and_negative() -> None:
    """CVE-2026-89039 (#907): 0.6.1 in an MCP config's docker args fires; 0.7.0 and
    0.2.0 (before the prompt existed) do not."""
    root = FIXTURES / "cve-2026-89039-mcp-k6"
    assert _ids(root / "vulnerable") == [K6]
    assert K6 in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("tag", "fires"), [
    ("0.1.0", False),   # prompts/convert_playwright_script.go is absent
    ("0.2.0", False),
    ("0.2", False),     # the whole 0.2 line predates the prompt
    ("0.3.0", True),    # the prompt arrives
    ("0.6", True),
    ("0.6.1", True),
    ("0.7.0", False),   # grafana/mcp-k6#191
])
def test_mcp_k6_tag_reading_honours_the_introduced_bound(tmp_path: Path, tag: str, fires: bool) -> None:
    ids = _write(tmp_path, "compose.yaml", f"services:\n  k6:\n    image: grafana/mcp-k6:{tag}\n")
    assert (K6 in ids) is fires


def test_mcp_k6_untagged_reference_is_latest_and_affected(tmp_path: Path) -> None:
    """`latest` was the 0.6.1 digest on 2026-10-06, and Docker Hub had no 0.7.0 image."""
    content = '{"mcpServers": {"k6": {"command": "docker", "args": ["run", "-i", "--rm", "grafana/mcp-k6"]}}}'
    assert _write(tmp_path, ".mcp.json", content) == [K6]


def test_docker_io_spelling_is_not_read(tmp_path: Path) -> None:
    """Both projects document the bare Docker Hub name; the registry-prefixed
    spelling is a stated limitation, not a silent match."""
    ids = _write(tmp_path, "compose.yaml", "services:\n  k6:\n    image: docker.io/grafana/mcp-k6:0.6.1\n")
    assert K6 not in ids


# --- 2026-10-09 (#926): a second Obot pin, for CVE-2026-105138 -------------------


def test_obot_static_secret_pin_is_its_own_medium_rule() -> None:
    """The fix (v0.26.2) is above the CRITICAL pin's v0.25.0 floor, and raising that
    floor would report v0.25.0 to v0.26.1 as the critical bugs."""
    assert RULES[OBOT_STATIC].cve_references == ["CVE-2026-105138"]
    assert RULES[OBOT_STATIC].severity.value == "medium"
    assert "CVE-2026-105138" not in RULES[OBOT].cve_references


def test_obot_static_secret_fixtures_positive_and_negative() -> None:
    root = FIXTURES / "cve-2026-105138-obot"
    findings = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(OBOT_STATIC, 6)]
    assert OBOT_STATIC in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("tag", "static", "critical"), [
    ("v0.11.0", False, True),   # static configuration on catalog entries is absent
    ("0.11", False, True),
    ("v0.12.0", True, True),
    ("v0.24.2", True, True),
    ("0.25", True, False),      # the whole 0.25 line is inside 0.12.0-0.26.2
    ("v0.26.1", True, False),
    ("0.26", False, False),     # 0.26 has fixed releases
    ("v0.26.2", False, False),  # 644a1fd
    ("v0.26.3", False, False),  # latest on 2026-10-09
    ("latest", False, False),
])
def test_obot_pins_split_the_range(tmp_path: Path, tag: str, static: bool, critical: bool) -> None:
    ids = _write(tmp_path, "compose.yaml", f"services:\n  o:\n    image: ghcr.io/obot-platform/obot:{tag}\n")
    assert (OBOT_STATIC in ids, OBOT in ids) == (static, critical)


# --- 2026-10-11 (#957): Kortix's API image, for CVE-2026-108115 -----------------


def test_kortix_pin_carries_its_cve_and_severity() -> None:
    assert RULES[KORTIX].cve_references == ["CVE-2026-108115"]
    assert RULES[KORTIX].severity.value == "medium"


def test_kortix_fixtures_positive_and_negative() -> None:
    """0.13.51 fires once, on the first API service's line; 0.13.52 (9c949e4) does
    not, and the frontend image is never read."""
    root = FIXTURES / "cve-2026-108115-kortix"
    findings = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(KORTIX, 7)]
    assert KORTIX in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("ref", "fires"), [
    ("kortix/kortix-api:0.10.6", False),             # ssrf-guard.ts is absent
    ("kortix/kortix-api:0.10.7", True),              # the guard arrives
    ("kortix/kortix-api:0.12.0", True),
    ("kortix/kortix-api:0.13.51", True),
    ("kortix/kortix-api:0.13.52", False),            # 9c949e4
    ("kortix/kortix-api:0.13.53", False),
    ("kortix/kortix-api:stable", False),             # the 0.13.52 digest on 2026-10-11
    ("kortix/kortix-api:latest", False),             # the 0.13.53 digest on 2026-10-11
    ("kortix/kortix-api", False),                    # untagged is latest
    ("kortix/kortix-api:dev-452e3593", False),       # a commit tag states no version
    ("kortix/kortix-frontend:0.13.51", False),       # the guard is in the API server
    ("kortix/suna:0.1.3.31", False),                 # the image line before 0.10
    ("docker.io/kortix/kortix-api:0.13.51", False),  # the bare Docker Hub name only
])
def test_kortix_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yaml", f"services:\n  kortix-api:\n    image: {ref}\n")
    assert (KORTIX in ids) is fires


def test_kortix_self_host_compose_states_no_tag(tmp_path: Path) -> None:
    """The `kortix self-host` compose file names the image `${API_IMAGE}` and keeps
    the tag in its .env, which this reader does not read."""
    ids = _write(tmp_path, "docker-compose.yml", "services:\n  kortix-api:\n    image: ${API_IMAGE}\n")
    assert KORTIX not in ids


# --- 2026-10-13 (#973, #976): Unla and Trinity, neither with a fixed release ---


def test_unla_and_trinity_pins_carry_their_cve_and_severity() -> None:
    assert RULES[UNLA].cve_references == ["CVE-2026-108865"]
    assert RULES[TRINITY].cve_references == ["CVE-2026-108756"]
    assert (RULES[UNLA].severity.value, RULES[TRINITY].severity.value) == ("high", "medium")


def test_unla_fixtures_positive_and_negative() -> None:
    """The multi-container compose's `mcp-gateway:latest` (the v0.10.0 digest on
    2026-10-13) and a Kubernetes allinone at v0.9.2 fire; the web image and an
    interpolated tag are not read."""
    root = FIXTURES / "cve-2026-108865-unla"
    findings = scan(root / "vulnerable")[0]
    assert sorted((f.file_path, f.rule_id, f.line_number) for f in findings) == [
        ("docker-compose.yaml", UNLA, 7),
        ("k8s/deployment.yaml", UNLA, 10),
    ]
    assert UNLA in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("ref", "fires"), [
    ("ghcr.io/amoylab/unla/allinone:v0.7.0", True),     # the first amoylab/unla tag
    ("ghcr.io/amoylab/unla/allinone:v0.10.0", True),    # the newest release
    ("ghcr.io/amoylab/unla/allinone:latest", True),     # the v0.10.0 digest
    ("ghcr.io/amoylab/unla/allinone", True),            # untagged is latest
    ("ghcr.io/amoylab/unla/mcp-gateway:v0.9.2", True),
    ("registry.ap-southeast-1.aliyuncs.com/amoylab/unla-allinone:v0.10.0", True),
    ("ghcr.io/amoylab/unla/allinone:v0.10.1", False),   # past NVD's range; does not exist
    ("ghcr.io/amoylab/unla/allinone:main", False),      # a branch tag states no version
    ("ghcr.io/amoylab/unla/web:v0.10.0", False),        # the OAuth2 server is in the gateway
    ("ghcr.io/amoylab/unla/mock-server:v0.10.0", False),
])
def test_unla_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yaml", f"services:\n  unla:\n    image: {ref}\n")
    assert (UNLA in ids) is fires


def test_unla_allinone_compose_default_is_not_read(tmp_path: Path) -> None:
    """Unla's own all-in-one compose writes `${IMAGE:-ghcr.io/amoylab/unla/allinone:latest}`.
    The reference sits inside an interpolation default, which this reader does not
    resolve, so such an instance is reported only where a file states the image."""
    ids = _write(tmp_path, "docker-compose.yml",
                 "services:\n  unla:\n    image: ${IMAGE:-ghcr.io/amoylab/unla/allinone:latest}\n")
    assert UNLA not in ids


def test_trinity_fixtures_positive_and_negative() -> None:
    """A pinned 0.9.5 backend fires once; the hosted compose's
    `${TRINITY_IMAGE_TAG:-latest}` states no version, and the frontend image is not
    pinned."""
    root = FIXTURES / "cve-2026-108756-trinity"
    findings = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(TRINITY, 4)]
    assert TRINITY in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("ref", "fires"), [
    ("ghcr.io/abilityai/trinity-backend:0.9.5-rc1", True),   # the first image tag
    ("ghcr.io/abilityai/trinity-backend:v0.9.5", True),
    ("ghcr.io/abilityai/trinity-backend:0.9.5", True),       # the newest release
    ("ghcr.io/abilityai/trinity-backend:latest", True),      # the 0.9.5 digest on 2026-10-13
    ("ghcr.io/abilityai/trinity-backend", True),             # untagged is latest
    ("ghcr.io/abilityai/trinity-backend:0.9", False),        # a two-part tag floats over the line
    ("ghcr.io/abilityai/trinity-backend:1.0.0-rc2", False),  # reads as 1.0.0, past NVD's range
    ("ghcr.io/abilityai/trinity-frontend:0.9.5", False),     # the routes are in the backend
    ("ghcr.io/abilityai/trinity-mcp-server:0.9.5", False),
])
def test_trinity_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yaml", f"services:\n  backend:\n    image: {ref}\n")
    assert (TRINITY in ids) is fires
