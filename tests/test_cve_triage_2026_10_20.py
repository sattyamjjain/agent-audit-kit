"""The 2026-10-20 batch's dispositions that are not new pin rows, pinned as facts.

* CVE-2026-8355 (#1054) joins ``AAK-MCP-CONTEXTFORGE-CVE-2026-77822-001``. IBM's
  bulletin scopes it to ContextForge 0.1.0 through 1.0.5 and names 1.0.6 as the
  fix: dc429d9 (#5601) stops token requests following redirects and checks
  ``redirect_uri`` and ``jwks_uri``, where 1.0.1 had begun checking ``token_url``
  itself. 1.0.6 is below the rule's 1.0.9 floor, so every affected release already
  fires and the pin table's row does not change. The GHCR image the README and the
  Helm chart run gets a row on the same rule, tested in
  ``tests/test_container_image_pins.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_cve_pins_2026_07 as pins

FIXTURES = Path(__file__).parent / "fixtures" / "cves"
CONTEXTFORGE = "AAK-MCP-CONTEXTFORGE-CVE-2026-77822-001"


def _write(root: Path, name: str, body: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _pin_ids(root: Path) -> set[str]:
    return {f.rule_id for f in pins.scan(root)[0]}


def test_contextforge_carries_the_token_url_cve_on_the_same_row() -> None:
    assert "CVE-2026-8355" in RULES[CONTEXTFORGE].cve_references
    rows = [p for p in pins._PINS if p.rule_id == CONTEXTFORGE]
    assert [(p.floor, p.introduced) for p in rows] == [((1, 0, 9), None)]
    assert not any("8355" in p.rule_id for p in pins._PINS)


def test_contextforge_fixtures() -> None:
    """The package at 1.0.5 and the chart's values pinned to v1.0.5 fire, each on
    its own line; 1.0.9, `latest` and the floor's image tag do not."""
    root = FIXTURES / "cve-2026-8355-contextforge"
    hits = sorted(
        (f.file_path, f.line_number)
        for f in run_scan(root / "vulnerable").findings
        if f.rule_id == CONTEXTFORGE
    )
    assert hits == [("requirements.txt", 3), ("values.yaml", 7)]
    assert not any(f.rule_id == CONTEXTFORGE for f in run_scan(root / "negative").findings)


@pytest.mark.parametrize(("version", "fires"), [
    ("0.1.0", True),   # where IBM's range starts
    ("1.0.0", True),   # nothing checks `token_url`
    ("1.0.1", True),   # `token_url` is checked; token requests still follow redirects
    ("1.0.5", True),   # the last release before dc429d9
    ("1.0.6", True),   # fixed for this CVE, still below the floor for the others
    ("1.0.9", False),
])
def test_contextforge_versions(tmp_path: Path, version: str, fires: bool) -> None:
    _write(tmp_path, "requirements.txt", f"mcp-contextforge-gateway=={version}\n")
    assert (CONTEXTFORGE in _pin_ids(tmp_path)) is fires
