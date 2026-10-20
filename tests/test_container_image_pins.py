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


# --- 2026-10-15 (#982-#986): Nginx UI's image, and obsidian-tc's beside its npm row ---

NGINXUI = "AAK-MCP-NGINXUI-CVE-2026-84317-001"
OBSIDIANTC = "AAK-MCP-OBSIDIANTC-CVE-2026-77366-001"


def test_nginx_ui_and_obsidian_tc_pins_carry_their_cves_and_severity() -> None:
    assert RULES[NGINXUI].cve_references == [
        "CVE-2026-84317", "CVE-2026-84318", "CVE-2026-84319", "CVE-2026-84360",
    ]
    assert (RULES[NGINXUI].severity.value, RULES[OBSIDIANTC].severity.value) == (
        "high", "critical",
    )


def test_nginx_ui_fixtures_positive_and_negative() -> None:
    """The README's compose service on v2.4.0 fires on its image line; on v2.4.1,
    which carries 23d1934, it does not."""
    root = FIXTURES / "cve-2026-84317-nginx-ui"
    findings = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(NGINXUI, 15)]
    assert NGINXUI in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("ref", "fires"), [
    ("uozi/nginx-ui:v1.9.9", False),           # before the MCP server existed
    ("uozi/nginx-ui:2.0.0-beta.42", False),    # reads as 2.0.0, and predates the MCP tools
    ("uozi/nginx-ui:2.0.0-rc.5", False),       # mcp/config/ is absent
    ("uozi/nginx-ui:2.0.0-rc.6", False),       # has the tools, but reads as 2.0.0: stated limitation
    ("uozi/nginx-ui:v2.0.0", False),           # affected, the same limitation
    ("uozi/nginx-ui:v2.0.1", True),
    ("uozi/nginx-ui:v2.1", True),              # the two-part tag floats over an affected line
    ("uozi/nginx-ui:2.3.8", True),             # before ValidateConfigFile existed at all
    ("uozi/nginx-ui:v2.3.11", True),           # where GHSA-76pm-mq2q-9gcr's range ends
    ("uozi/nginx-ui:2.4.0", True),             # still affected: 23d1934 is not in it
    ("uozi/nginx-ui:v2.4.0", True),
    ("uozi/nginx-ui:2.4.1", False),            # the fix
    ("uozi/nginx-ui:v2.4.1", False),
    ("uozi/nginx-ui:v2.8.4", False),           # the newest release on 2026-10-15
    ("uozi/nginx-ui:latest", False),           # the v2.8.4 digest on 2026-10-15
    ("uozi/nginx-ui", False),                  # untagged is latest
    ("uozi/nginx-ui:dev", False),              # a branch tag states no version
    ("uozi/nginx-ui:sha-7a9ad96", False),      # a commit tag states no version
    ("docker.io/uozi/nginx-ui:v2.4.0", False), # the bare Docker Hub name only
    ("uozi/nginx-ui-demo:v2.4.0", False),      # another image name
])
def test_nginx_ui_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yml", f"services:\n  nginx-ui:\n    image: {ref}\n")
    assert (NGINXUI in ids) is fires


def test_obsidian_tc_image_fixtures_positive_and_negative() -> None:
    """A client config that runs the GHCR image on 1.2.1, as the install docs run
    it, fires on the image argument; the same config on 1.3.1 does not."""
    root = FIXTURES / "cve-2026-77366-obsidian-tc"
    findings = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.file_path, f.line_number) for f in findings] == [
        (OBSIDIANTC, "claude_desktop_config.json", 9),
    ]
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("ref", "fires"), [
    ("ghcr.io/the-40-thieves/obsidian-tc:1.0.0", True),   # the tag the v1.2.1 install doc names
    ("ghcr.io/the-40-thieves/obsidian-tc:1.0.1", True),   # the first image tag
    ("ghcr.io/the-40-thieves/obsidian-tc:1.2.1", True),
    ("ghcr.io/the-40-thieves/obsidian-tc:1.3.1", False),
    ("ghcr.io/the-40-thieves/obsidian-tc:1.33.1", False),
    ("ghcr.io/the-40-thieves/obsidian-tc:latest", False),  # the 1.33.1 digest on 2026-10-15
    ("ghcr.io/the-40-thieves/obsidian-tc", False),
    ("ghcr.io/the-40-thieves/obsidian-tc:smoke-1.33.1", False),
])
def test_obsidian_tc_image_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yml", f"services:\n  vaults:\n    image: {ref}\n")
    assert (OBSIDIANTC in ids) is fires


# --- 2026-10-15 second batch (#995-#997): EdgeEver's and NullHub's images ---

EDGEEVER = "AAK-MCP-EDGEEVER-CVE-2026-109557-001"
NULLHUB = "AAK-MCP-NULLHUB-CVE-2026-110616-001"


def test_edgeever_and_nullhub_pins_carry_their_cves_and_severity() -> None:
    assert RULES[EDGEEVER].cve_references == ["CVE-2026-109557", "CVE-2026-109558"]
    assert RULES[NULLHUB].cve_references == ["CVE-2026-110616"]
    assert (RULES[EDGEEVER].severity.value, RULES[NULLHUB].severity.value) == ("high", "high")


def test_edgeever_fixtures_positive_and_negative() -> None:
    """The self-hosted service on v1.112.0 fires on its image line; on 1.113.0,
    which carries 6b5027e8, it does not."""
    root = FIXTURES / "cve-2026-109557-edgeever"
    findings = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(EDGEEVER, 6)]
    assert EDGEEVER in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("ref", "fires"), [
    ("ghcr.io/tianma-if/edgeever:1.33.0", True),     # the oldest image tag; both sinks are in it
    ("ghcr.io/tianma-if/edgeever:v1.33.0", True),    # GHCR tags each release both ways
    ("ghcr.io/tianma-if/edgeever:v1.104.0", True),
    ("ghcr.io/tianma-if/edgeever:1.112.0", True),    # the last release before the fix
    ("ghcr.io/tianma-if/edgeever:v1.112.0", True),
    ("ghcr.io/tianma-if/edgeever:1.113.0", False),   # 6b5027e8
    ("ghcr.io/tianma-if/edgeever:v1.113.0", False),
    ("ghcr.io/tianma-if/edgeever:v1.120.0", False),  # the newest release on 2026-10-15
    ("ghcr.io/tianma-if/edgeever:latest", False),    # the 1.120.0 digest on 2026-10-15
    ("ghcr.io/tianma-if/edgeever", False),           # untagged is latest
    ("ghcr.io/tianma-if/edgeever:main", False),      # a branch tag states no version
    ("ghcr.io/tianma-if/edgeever:sha-b83e99a9aced", False),
    # The project's own compose file: the tag comes from the environment.
    ('"${EDGE_EVER_IMAGE:-ghcr.io/tianma-if/edgeever}:${EDGE_EVER_VERSION:-latest}"', False),
    ("ghcr.io/tianma-if/edgeever-docs:v1.112.0", False),  # another image name
])
def test_edgeever_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yml", f"services:\n  edgeever:\n    image: {ref}\n")
    assert (EDGEEVER in ids) is fires


def test_nullhub_fixtures_positive_and_negative() -> None:
    """The published image on v2026.5.29, the newest release, fires; an
    interpolated tag and another image name do not."""
    root = FIXTURES / "cve-2026-110616-nullhub"
    findings = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(NULLHUB, 5)]
    assert NULLHUB in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("ref", "fires"), [
    ("ghcr.io/nullclaw/nullhub:v2026.3.2", True),    # the oldest image tag; auth_token unset there too
    ("ghcr.io/nullclaw/nullhub:v2026.4.17", True),
    ("ghcr.io/nullclaw/nullhub:v2026.5.29", True),   # the newest release
    ("ghcr.io/nullclaw/nullhub:latest", True),       # the v2026.5.29 digest on 2026-10-15
    ("ghcr.io/nullclaw/nullhub", True),              # untagged is latest
    ("ghcr.io/nullclaw/nullhub:v2026.5.30", False),  # past the record's range, not a fix
    ("ghcr.io/nullclaw/nullhub:${NULLHUB_VERSION}", False),
    ("ghcr.io/nullclaw/nullhub-docs:v2026.5.29", False),  # another image name
])
def test_nullhub_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yml", f"services:\n  hub:\n    image: {ref}\n")
    assert (NULLHUB in ids) is fires


# --- 2026-10-16 batch (#1001, #1004): NetLicensing's images and Conductor's ---

NETLICENSING = "AAK-MCP-NETLICENSING-CVE-2026-54446-001"
CONDUCTOR = "AAK-MCP-CONDUCTOR-CVE-2026-109402-001"


def test_netlicensing_image_fixtures_positive_and_negative() -> None:
    """The README's container on 0.1.7 fires on its image line; the Docker Hub image
    on 0.1.8 does not."""
    root = FIXTURES / "cve-2026-57496-netlicensing"
    findings = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.file_path, f.line_number) for f in findings] == [
        (NETLICENSING, "docker-compose.yml", 5),
    ]
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("ref", "fires"), [
    ("ghcr.io/labs64/netlicensing-mcp:0.1.3", True),   # the oldest GHCR tag
    ("ghcr.io/labs64/netlicensing-mcp:0.1.7", True),
    ("ghcr.io/labs64/netlicensing-mcp:0.1.8", False),  # b8fd0ea
    ("labs64/netlicensing-mcp:0.1.2", True),           # the oldest Docker Hub tag
    ("labs64/netlicensing-mcp:0.1.6", True),
    ("labs64/netlicensing-mcp:0.1.8", False),
    ("labs64/netlicensing-mcp:0.1.10", False),         # the newest release
    ("labs64/netlicensing-mcp:latest", False),         # the 0.1.10 digest on 2026-10-16
    ("ghcr.io/labs64/netlicensing-mcp", False),        # untagged is latest
    ("labs64/netlicensing-mcp:0.1", False),            # the two-part tag floats to 0.1.10
    ("labs64/netlicensing-mcp-proxy:0.1.7", False),    # another image name
])
def test_netlicensing_image_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yml", f"services:\n  nl:\n    image: {ref}\n")
    assert (NETLICENSING in ids) is fires


def test_conductor_pin_carries_its_cve_and_severity() -> None:
    assert RULES[CONDUCTOR].cve_references == ["CVE-2026-109402"]
    assert RULES[CONDUCTOR].severity.value == "medium"


def test_conductor_fixtures_positive_and_negative() -> None:
    root = FIXTURES / "cve-2026-109402-conductor"
    findings = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(CONDUCTOR, 5)]
    assert CONDUCTOR in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("ref", "fires"), [
    ("conductoross/conductor:3.21.24", False),       # before MCPService
    ("conductoross/conductor:3.22.0-beta", True),    # MCPService is in it (2026-02-19)
    ("conductoross/conductor:3.22.0", True),         # the release the record names
    ("conductoross/conductor:3.32.5", True),
    ("conductoross/conductor:3.33.0-rc13", True),    # no fixed release
    ("conductoross/conductor:4.0.0-alpha.1", True),  # the newest tag
    ("conductoross/conductor:latest", True),         # pushed 2026-10-14
    ("conductoross/conductor", True),                # untagged is latest
    ("conductoross/conductor:next", False),          # the README's tag states no version
    ("conductoross/conductor-standalone:3.22.0", False),  # another image name
    ("orkesio/orkes-conductor-community:3.22.0", False),  # another repository
])
def test_conductor_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yml", f"services:\n  conductor:\n    image: {ref}\n")
    assert (CONDUCTOR in ids) is fires


# --- 2026-10-16 second batch: Nezha's dashboard image (CVE-2026-111385) ---

NEZHA = "AAK-MCP-NEZHA-CVE-2026-111385-001"


def test_nezha_pin_carries_its_cve_and_severity() -> None:
    assert RULES[NEZHA].cve_references == ["CVE-2026-111385"]
    assert RULES[NEZHA].severity.value == "medium"


def test_nezha_fixtures_positive_and_negative() -> None:
    """The install script's compose file on v2.3.14 fires on its image line; v2.3.15
    and the untagged image the script writes do not."""
    root = FIXTURES / "cve-2026-111385-nezha"
    findings = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(NEZHA, 4)]
    assert NEZHA in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("ref", "fires"), [
    ("ghcr.io/nezhahq/nezha:v2.0.12", False),   # no MCP transfer tools yet
    ("ghcr.io/nezhahq/nezha:v2.1.0", True),     # mcp_transfer.go arrives
    ("ghcr.io/nezhahq/nezha:v2.2", True),       # the whole v2.2 line is affected
    ("ghcr.io/nezhahq/nezha:v2.3.14", True),
    ("ghcr.io/nezhahq/nezha:v2.3.15", False),   # 36b742a7 validates the host
    ("ghcr.io/nezhahq/nezha:v2.3.18", False),   # the newest release
    ("ghcr.io/nezhahq/nezha:v2.3", False),      # the two-part tag floats to v2.3.18
    ("ghcr.io/nezhahq/nezha:latest", False),    # the v2.3.18 digest on 2026-10-16
    ("ghcr.io/nezhahq/nezha", False),           # untagged, as the install script writes it
    ("ghcr.io/nezhahq/nezha:v1.1", False),      # the v1 line, before the MCP endpoint
    ("ghcr.io/nezhahq/nezha:dev", False),       # states no version
    ("ghcr.io/nezhahq/agent:v2.3.14", False),   # another image name
])
def test_nezha_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yml", f"services:\n  dashboard:\n    image: {ref}\n")
    assert (NEZHA in ids) is fires


# --- A reference inside a JSONC comment is not a deployment ---
#
# MCP clients read their configs as JSONC, and the inline reader matched the raw
# text, so an image named in a `//` or `/* */` comment of `.vscode/mcp.json` was
# reported. Comments are blanked before matching; offsets and lines are kept.

VSCODE_IMAGES = FIXTURES.parent / "vscode_servers" / "image-pins"


def test_an_image_in_a_jsonc_comment_is_not_reported() -> None:
    assert _ids(VSCODE_IMAGES / "commented") == []


def test_an_image_in_a_vscode_servers_map_is_still_reported_on_its_line() -> None:
    findings = scan(VSCODE_IMAGES / "detecting")[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(NULLHUB, 7)]


def test_a_config_that_does_not_parse_even_as_jsonc_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text(
        '{"servers": {"hub": {"args": ["ghcr.io/nullclaw/nullhub:v2026.5.29"]}}} /* never closed',
        encoding="utf-8",
    )
    assert _ids(tmp_path) == []


# --- Item 39: the images of two servers that also have package pins ---
#
# n8n-mcp and mcp-atlassian publish a GHCR image beside their npm and PyPI
# releases, tagged with the package version (no `v`), and their docs run it with
# `docker run` from an MCP config. The package pins never read an image, so a
# config on a vulnerable tag was silent. These rows read a version tag only: an
# untagged or `latest` reference is not reported, whatever `latest` is today,
# because the State of MCP v1.1 corpus carries both images on `:latest` and a
# report over it must not move.

N8NMCP = "AAK-MCP-N8NMCP-CVE-2026-54052-001"
ATL_27825 = "AAK-MCP-ATLASSIAN-CVE-2026-27825-001"
ATL_27826 = "AAK-MCP-ATLASSIAN-CVE-2026-27826-001"
ATL_73498 = "AAK-MCP-ATLASSIAN-CVE-2026-73498-001"


def _docker_config(tmp_path: Path, image: str) -> list:
    import json

    config = {"mcpServers": {"s": {"command": "docker", "args": ["run", "-i", "--rm", image]}}}
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / ".mcp.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return scan(tmp_path)[0]


@pytest.mark.parametrize(("ref", "fires"), [
    ("ghcr.io/czlonkowski/n8n-mcp:2.40.0", True),
    ("ghcr.io/czlonkowski/n8n-mcp:2.56.0", True),    # CVE-2026-54052's last affected tag
    ("ghcr.io/czlonkowski/n8n-mcp:2.57.3", True),    # CVE-2026-55608's last affected tag
    ("ghcr.io/czlonkowski/n8n-mcp:2.56", True),      # the whole 2.56 line is affected
    ("ghcr.io/czlonkowski/n8n-mcp:2.57.4", False),   # the fix
    ("ghcr.io/czlonkowski/n8n-mcp:2.57", False),     # floats to 2.57.4 or later
    ("ghcr.io/czlonkowski/n8n-mcp:2.94.0", False),
    ("ghcr.io/czlonkowski/n8n-mcp:latest", False),   # not judged, whatever it is
    ("ghcr.io/czlonkowski/n8n-mcp", False),          # untagged is latest
    ("ghcr.io/czlonkowski/n8n-mcp:2", False),        # one part states no release
    ("ghcr.io/czlonkowski/n8n-mcp:main", False),
    ("ghcr.io/czlonkowski/n8n-mcp:sha-2a1b3c4", False),
    ("ghcr.io/czlonkowski/n8n-mcp-railway:2.57.3", True),   # the same server, Dockerfile.railway
    ("ghcr.io/czlonkowski/n8n-mcp-railway:2.57.4", False),
    ("ghcr.io/czlonkowski/n8n-mcp-railway:latest", False),
    ("ghcr.io/czlonkowski/n8n-mcp-docs:2.40.0", False),     # another image name
    ("czlonkowski/n8n-mcp:2.40.0", False),                  # not on Docker Hub
])
def test_n8n_mcp_image_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    findings = _docker_config(tmp_path, ref)
    assert ([f.rule_id for f in findings] == [N8NMCP]) is fires
    if fires:
        assert findings[0].line_number == 9   # the image argument


@pytest.mark.parametrize(("ref", "expected"), [
    ("ghcr.io/sooperset/mcp-atlassian:0.11.9", {ATL_27825, ATL_27826, ATL_73498}),
    ("ghcr.io/sooperset/mcp-atlassian:0.16.1", {ATL_27825, ATL_27826, ATL_73498}),
    ("ghcr.io/sooperset/mcp-atlassian:0.16", {ATL_27825, ATL_27826, ATL_73498}),
    ("ghcr.io/sooperset/mcp-atlassian:0.17.0", {ATL_73498}),   # fixes 27825 and 27826
    ("ghcr.io/sooperset/mcp-atlassian:0.21.0", {ATL_73498}),
    ("ghcr.io/sooperset/mcp-atlassian:0.21", {ATL_73498}),
    ("ghcr.io/sooperset/mcp-atlassian:0.22.0", set()),          # fixes 73498
    ("ghcr.io/sooperset/mcp-atlassian:0.22", set()),
    ("ghcr.io/sooperset/mcp-atlassian:0.23.1", set()),
    ("ghcr.io/sooperset/mcp-atlassian:latest", set()),
    ("ghcr.io/sooperset/mcp-atlassian", set()),
    ("ghcr.io/sooperset/mcp-atlassian:0", set()),
    # A digest names one release, but not which: the 0.21.0 digest is not read.
    ("ghcr.io/sooperset/mcp-atlassian@sha256:"
     "6c4f96725b0e775a014a0b3016d358efdab58efd57c37ad7c2050136545b0e00", set()),
    ("sooperset/mcp-atlassian:0.16.1", set()),                  # not on Docker Hub
])
def test_mcp_atlassian_image_tag_reading(tmp_path: Path, ref: str, expected: set[str]) -> None:
    assert {f.rule_id for f in _docker_config(tmp_path, ref)} == expected


def test_the_image_rows_carry_the_package_pins_cves() -> None:
    from agent_audit_kit.scanners.container_image_pins import _PINS

    for pin in _PINS:
        if pin.rule_id in (N8NMCP, ATL_27825, ATL_27826, ATL_73498, CONTEXTFORGE):
            assert set(pin.cves) <= set(RULES[pin.rule_id].cve_references), pin
            assert pin.floating_affected is False, "a floating tag must not move v1.1"


def test_the_corpus_latest_references_stay_quiet(tmp_path: Path) -> None:
    """The two v1.1 corpus configs run these images on `:latest`."""
    assert _docker_config(tmp_path / "a", "ghcr.io/czlonkowski/n8n-mcp:latest") == []
    assert _docker_config(tmp_path / "b", "ghcr.io/sooperset/mcp-atlassian:latest") == []


# --- 2026-10-19 (#1049): Apache Answer's image (CVE-2026-71563) ---

ANSWER = "AAK-MCP-APACHEANSWER-CVE-2026-71563-001"


def test_apache_answer_pin_carries_its_cve_and_severity() -> None:
    """MEDIUM is the ASF's own rating, moderate; the record has no CVSS score."""
    assert RULES[ANSWER].cve_references == ["CVE-2026-71563"]
    assert RULES[ANSWER].severity.value == "medium"


def test_apache_answer_fixtures_positive_and_negative() -> None:
    """Answer's compose file on 2.0.2 fires on its image line; 2.0.3, the untagged
    image the compose file runs, 1.7.1 and the pre-Apache image do not."""
    root = FIXTURES / "cve-2026-71563-apache-answer"
    findings = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(ANSWER, 7)]
    assert ANSWER in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("ref", "fires"), [
    ("apache/answer:1.7.1", False),       # mcp_controller.go is absent
    ("apache/answer:2.0.0-RC1", True),    # the MCP tools arrive
    ("apache/answer:2.0.0", True),
    ("apache/answer:2.0.1", True),
    ("apache/answer:2.0.2-RC3", True),    # read as 2.0.2, before the fix
    ("apache/answer:2.0.2", True),
    ("apache/answer:2.0.3-RC1", False),   # the 2.0.3 commit, 6744295f
    ("apache/answer:2.0.3", False),       # 63a67542 checks the question
    ("apache/answer:latest", False),      # a 2.0.3 build on 2026-10-19
    ("apache/answer", False),             # untagged is latest
    ("apache/answer:test", False),        # states no version
    ("answerdev/answer:1.2.0", False),    # the pre-Apache image, before MCP
    ("docker.io/apache/answer:2.0.2", False),  # the registry-prefixed spelling
])
def test_apache_answer_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yaml", f"services:\n  answer:\n    image: {ref}\n")
    assert (ANSWER in ids) is fires


@pytest.mark.parametrize(("tag", "fires"), [('"2.0.2"', True), ('"2.0.3"', False), ('"latest"', False)])
def test_apache_answer_chart_values_are_read(tmp_path: Path, tag: str, fires: bool) -> None:
    """The chart in Answer's repository sets `tag: "latest"`; a values file that
    overrides it with a release is read through the Helm reader."""
    values = f"image:\n  repository: apache/answer\n  pullPolicy: Always\n  tag: {tag}\n"
    assert (ANSWER in _write(tmp_path, "values.yaml", values)) is fires


# --- The prefilter keeps a Docker Hub name whole ---
#
# `scan` opens the YAML reader only for a file that contains a pinned image's
# name. It dropped the first part of every name, meant as the registry, so for a
# Docker Hub name it dropped the namespace and kept a bare word: `answer` would
# have sent every YAML file containing it through `yaml.compose_all`.


@pytest.mark.parametrize(("image", "needle"), [
    ("ghcr.io/obot-platform/obot", "obot-platform/obot"),
    ("registry.ap-southeast-1.aliyuncs.com/amoylab/unla-allinone", "amoylab/unla-allinone"),
    ("localhost:5000/team/app", "team/app"),
    ("localhost/team/app", "team/app"),
    ("apache/answer", "apache/answer"),
    ("conductoross/conductor", "conductoross/conductor"),
])
def test_the_prefilter_drops_only_a_registry(image: str, needle: str) -> None:
    from agent_audit_kit.scanners.container_image_pins import _needle

    assert _needle(image) == needle


def test_a_yaml_file_that_only_says_answer_is_not_composed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_audit_kit.scanners import container_image_pins

    def _composed(text: str) -> list:
        raise AssertionError("composed a YAML file that names no pinned image")

    monkeypatch.setattr(container_image_pins, "_helm_refs", _composed)
    assert _write(tmp_path, "faq.yaml", "- question: What is MCP?\n  answer: A protocol.\n") == []


# --- 2026-10-20 (#1054): IBM ContextForge's image, on the package pin's rule ---
#
# The pin table reads `mcp-contextforge-gateway` below 1.0.9. The README and the
# Helm chart run `ghcr.io/ibm/mcp-context-forge`, tagged with the release tag, so
# the same rule reads the image too, version tags only.

CONTEXTFORGE = "AAK-MCP-CONTEXTFORGE-CVE-2026-77822-001"


@pytest.mark.parametrize(("ref", "fires"), [
    ("ghcr.io/ibm/mcp-context-forge:0.9.0", True),       # a 0.x tag without the `v`
    ("ghcr.io/ibm/mcp-context-forge:v0.9.0", True),
    ("ghcr.io/ibm/mcp-context-forge:1.0.0-RC-2", True),   # read as 1.0.0
    ("ghcr.io/ibm/mcp-context-forge:v1.0.5", True),       # CVE-2026-8355's last affected release
    ("ghcr.io/ibm/mcp-context-forge:v1.0.7-20260921", True),  # the 1.0.7 support line
    ("ghcr.io/ibm/mcp-context-forge:v1.0.8", True),
    ("ghcr.io/ibm/mcp-context-forge:v1.0.9", False),      # the floor
    ("ghcr.io/ibm/mcp-context-forge:v1.0.11", False),
    ("ghcr.io/ibm/mcp-context-forge:latest", False),      # the v1.0.11 digest on 2026-10-20
    ("ghcr.io/ibm/mcp-context-forge", False),             # untagged is latest
    ("ghcr.io/ibm/mcp-context-forge-wheels:amd64-latest", False),  # the build's wheel image
])
def test_contextforge_image_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yml", f"services:\n  gateway:\n    image: {ref}\n")
    assert (CONTEXTFORGE in ids) is fires


def test_a_chart_with_two_image_blocks_is_reported_on_the_first(tmp_path: Path) -> None:
    """ContextForge's chart runs the image twice, for the gateway and for its
    migration job. The Helm walk pops from the end of the document, so it met the
    migration block first; the finding belongs on the gateway's own block."""
    block = "  image:\n    repository: ghcr.io/ibm/mcp-context-forge\n    tag: v1.0.5\n"
    (tmp_path / "values.yaml").write_text(
        "mcpContextForge:\n" + block + "migration:\n" + block, encoding="utf-8",
    )
    findings = scan(tmp_path)[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(CONTEXTFORGE, 3)]


# --- 2026-10-20 (#1055): Langchain-Chatchat's images (CVE-2026-75128) ---
#
# The pin table's presence-only row reads the PyPI package. The images are built
# from `master` and tagged `<version>-<commit>-<date>`, and no release fixes the
# route, so every tag on Docker Hub and the Tencent mirror is reported.

CHATCHAT = "AAK-CHATCHAT-CVE-2026-75128-001"


def test_chatchat_image_fixtures_positive_and_negative() -> None:
    """Chatchat's own compose file fires on the chatchat service; the model
    server it runs beside it does not."""
    root = FIXTURES / "cve-2026-75128-langchain-chatchat"
    findings = scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.line_number) for f in findings] == [(CHATCHAT, 12)]
    assert _ids(root / "negative") == []


@pytest.mark.parametrize(("ref", "fires"), [
    ("chatimage/chatchat:0.3.0-0622", True),                     # the oldest tag
    ("chatimage/chatchat:0.3.1.1-2024-0714", True),              # a four-part version
    ("chatimage/chatchat:0.3.1-b108c1a-20240728-1", True),
    ("chatimage/chatchat:0.3.1.3-93e2c87-20240829", True),       # what the compose file runs
    ("chatimage/chatchat:0.3.1.3-717e03e-20241109", True),       # the newest release build
    ("chatimage/chatchat:0.3.2-dev-d15fcd4-20241014", True),     # the dev build
    ("ccr.ccs.tencentyun.com/langchain-chatchat/chatchat:0.3.1.3-717e03e-20241109", True),
    ("chatimage/chatchat", False),                               # neither registry has `latest`
    ("ccr.ccs.tencentyun.com/chatchat/chatchat:0.3.1.2-2024-0720", False),  # an older namespace
    ("xprobe/xinference:v0.12.3", False),
])
def test_chatchat_image_tag_reading(tmp_path: Path, ref: str, fires: bool) -> None:
    ids = _write(tmp_path, "docker-compose.yaml", f"services:\n  chatchat:\n    image: {ref}\n")
    assert (CHATCHAT in ids) is fires
