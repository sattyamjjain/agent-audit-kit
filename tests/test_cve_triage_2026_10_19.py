"""The two out-of-scope dispositions of the 2026-10-19 batch, pinned as facts.

* CVE-2026-102503 (#1047) and CVE-2026-103091 (#1048) are in Google's Agent Mesh,
  called SAM until October 2026. Below 0.1.0-alpha.3 the ``/libp2p-http`` ingress
  reached registered backends without a Biscuit check; below 0.1.0-alpha.9 any
  OIDC token holder could enrol, and the default policy gave every enrolled member
  every service. SAM is a Go program (``github.com/google/sam``, renamed
  ``github.com/google/agentmesh`` after 0.1.0-rc.9), shipped as release binaries
  and as ``ghcr.io/google/sam-*`` images. Nothing in AAK reads a ``go.mod`` or a
  binary. The images that carried the affected tags are gone from GHCR: GitHub's
  packages API answers 404 for every ``sam-*`` name and the registry refuses an
  anonymous pull, and the ``ghcr.io/google/agentmesh-*`` images that replaced
  them start at 0.1.0-rc.10, fixed. Every SAM tag was a 0.1.0 prerelease as
  well, which the image reader reads as 0.1.0, so no floor could tell alpha.2
  from alpha.9.

If a ``go.mod`` reader, a SAM image pin or prerelease ordering in the image
reader is ever added, these tests fail and both CVEs become re-triageable. That
is the intent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.scanners import container_image_pins

_SAM_CVES = {"CVE-2026-102503", "CVE-2026-103091"}


def _write(root: Path, name: str, body: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _sam_findings(root: Path) -> list[str]:
    return [f.rule_id for f in run_scan(root).findings if _SAM_CVES & set(f.cve_references)]


def test_a_sam_go_module_states_no_version_aak_reads(tmp_path: Path) -> None:
    _write(tmp_path, "go.mod",
           "module example.com/meshtool\n\ngo 1.25\n\n"
           "require github.com/google/sam v0.1.0-alpha.2\n")
    assert _sam_findings(tmp_path) == []


def test_a_deployment_on_the_deleted_sam_images_draws_no_finding(tmp_path: Path) -> None:
    """The tags the deploy workflow pushed for the affected releases, and the MCP
    endpoint SAM's own `.vscode/mcp.json` registers, which states no version."""
    _write(tmp_path, "docker-compose.yml",
           "services:\n"
           "  hub:\n    image: ghcr.io/google/sam-hub:v0.1.0-alpha.2\n"
           "  node:\n    image: ghcr.io/google/sam-node:v0.1.0-alpha.2\n"
           "  control-plane:\n    image: ghcr.io/google/sam-control-plane:v0.1.0-alpha.8\n"
           "  router:\n    image: ghcr.io/google/sam-router:v0.1.0-alpha.8\n")
    _write(tmp_path, ".vscode/mcp.json",
           '{"servers": {"sam-mesh": {"type": "http", "url": "http://localhost:8080/mcp"}}}\n')
    assert _sam_findings(tmp_path) == []


def test_no_image_pin_names_sam_or_agent_mesh() -> None:
    assert not any(
        "google/sam" in pin.image or "google/agentmesh" in pin.image
        for pin in container_image_pins._PINS
    )


@pytest.mark.parametrize("floor", [(0, 1, 0), (0, 1, 1), (0, 2, 0)])
def test_no_floor_separates_an_affected_sam_tag_from_a_fixed_one(floor: tuple[int, int, int]) -> None:
    pin = container_image_pins._ImagePin(
        "AAK-TEST", "SAM", "ghcr.io/google/sam-node", floor, "", "", (),
    )
    tags = ("v0.1.0-alpha.2", "v0.1.0-alpha.3", "v0.1.0-alpha.8", "v0.1.0-alpha.9", "v0.1.0-rc.9")
    assert len({container_image_pins._affected(tag, pin) for tag in tags}) == 1
