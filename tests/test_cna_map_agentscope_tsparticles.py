"""Two reviewed rows of `data/cna_package_map.json`, against NVD's records of what they map.

The three records are under tests/fixtures/nvd_cna, read from NVD's API on 2026-11-07
and unedited. Neither CNA names a packageURL or a collectionURL, so a row is the only
way these records reach the advisory feed. Nothing here touches the network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit import nvd_feed

NVD_CNA = Path(__file__).parent / "fixtures" / "nvd_cna"
MCP_SERVER = "@tsparticles/mcp-server"


def _record(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _packages(cve: str) -> list[tuple[str, str, str]]:
    return nvd_feed.record_packages(_record(cve), nvd_feed.load_package_map())


def test_the_agentscope_row_maps_its_record() -> None:
    assert _packages("CVE-2026-123022") == [("PyPI", "agentscope", "map")]


@pytest.mark.parametrize("cve", ["CVE-2026-76892", "CVE-2026-76893"])
def test_the_tsparticles_row_maps_only_the_mcp_server(cve: str) -> None:
    """The record's second block names the umbrella `tsparticles` project, which maps to nothing."""
    assert _packages(cve) == [("npm", MCP_SERVER, "map")]


def test_the_tsparticles_row_does_not_claim_the_whole_monorepo() -> None:
    """A CNA record naming only that repository could be about any package it publishes."""
    affected = {"vendor": "tsparticles", "product": "tsparticles",
                "repo": "https://github.com/tsparticles/tsparticles"}
    assert nvd_feed.map_package(affected, nvd_feed.load_package_map()) is None
