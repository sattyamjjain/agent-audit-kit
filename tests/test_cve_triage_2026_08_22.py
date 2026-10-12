"""Dispositions for the 2026-08-21 CVE pair.

One new pin and one that needed no code at all, which is the more interesting
half: `AAK-MCP-CKAN-CVE-2026-73846-001` has carried a floor of 0.4.112 since
2026-08-15, and CVE-2026-53509 is fixed in 0.4.106, so every affected version
already fires. Adding a second CKAN pin would report one dependency twice, which
is the trap that rule was created to avoid when it absorbed three CVEs at once.

The property worth guarding is that the free coverage stays free: if the CKAN
floor is ever lowered below 0.4.106, the claim in the ledger silently stops being
true, and nothing else in the tree would notice.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _PINS, scan

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER = REPO_ROOT / "CHANGELOG.cves.md"

OMNIGENT_RULE = "AAK-MCP-OMNIGENT-CVE-2026-62674-001"
CKAN_RULE = "AAK-MCP-CKAN-CVE-2026-73846-001"

# npm `omnigent` is a different project (Paparusi/omniagent, published only at
# 2.0.0). A pin keyed on the bare name across ecosystems would be the Onyx shape.
COLLIDING_NAMES = ("omnigent-platform", "omniagent")


def _ids(tmp_path: Path, name: str, content: str) -> set[str]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    findings, _ = scan(tmp_path)
    return {f.rule_id for f in findings}


def test_omnigent_rule_carries_its_cve() -> None:
    assert OMNIGENT_RULE in RULES
    assert "CVE-2026-62674" in RULES[OMNIGENT_RULE].cve_references


def test_omnigent_below_floor_fires(tmp_path: Path) -> None:
    assert OMNIGENT_RULE in _ids(tmp_path, "requirements.txt", "omnigent==0.2.9\n")


def test_omnigent_at_floor_is_quiet(tmp_path: Path) -> None:
    assert OMNIGENT_RULE not in _ids(tmp_path, "requirements.txt", "omnigent==0.3.0\n")


def test_omnigent_matches_the_whole_name(tmp_path: Path) -> None:
    """The 0.3.82 `cline` lesson, and the npm collision."""
    assert OMNIGENT_RULE not in _ids(
        tmp_path, "requirements.txt", "omnigent-extras==1.0.0\nsub-omnigent==2.0.0\n"
    )


def test_omnigent_remediation_does_not_stop_at_upgrade() -> None:
    """The payload persists in shared state, so upgrading does not undo it.

    A remediation that said only "upgrade to 0.3.0" would leave a reader with a
    patched runner still launching a command an attacker wrote into a shared
    agent bundle last week.
    """
    remediation = RULES[OMNIGENT_RULE].remediation.lower()
    assert "upgrade" in remediation
    assert "audit" in remediation and "shared" in remediation


@pytest.mark.parametrize("name", COLLIDING_NAMES)
def test_no_pin_keyed_on_a_colliding_name(name: str) -> None:
    hits = sorted(p.rule_id for p in _PINS if any(n.lower() == name for n in p.names))
    assert not hits, f"pin(s) {hits} keyed on {name!r}"


# ---------------------------------------------------------------------------
# The already-covered case
# ---------------------------------------------------------------------------


def test_ckan_rule_records_the_newly_covered_cve() -> None:
    """Coverage that exists but is not written down cannot be audited."""
    assert "CVE-2026-53509" in RULES[CKAN_RULE].cve_references


def test_ckan_floor_still_sits_above_the_new_cves_fix(tmp_path: Path) -> None:
    """The load-bearing assertion.

    The ledger claims CVE-2026-53509 needs no rule change because the CKAN floor
    (0.4.112) is already above its fix (0.4.106). Lower that floor and the claim
    silently becomes false, so it is asserted rather than trusted -- including on
    the exact version the new advisory fixes.
    """
    pin = next(p for p in _PINS if p.rule_id == CKAN_RULE)
    assert pin.floor is not None and pin.floor >= (0, 4, 112), (
        f"CKAN floor {pin.floor} no longer covers CVE-2026-53509 (fixed 0.4.106); "
        "the ledger's 'already covered' row is now false"
    )
    assert CKAN_RULE in _ids(
        tmp_path, "package.json",
        '{"dependencies":{"@aborruso/ckan-mcp-server":"0.4.105"}}',
    )


def test_no_second_ckan_pin_was_added() -> None:
    """One package, one pin. A second would report one dependency twice."""
    ckan = [p for p in _PINS if any("ckan" in n.lower() for n in p.names)]
    assert len(ckan) == 1, f"expected one CKAN pin, found {[p.rule_id for p in ckan]}"


@pytest.mark.parametrize("cve", ["CVE-2026-62674", "CVE-2026-53509"])
def test_disposition_is_recorded_in_the_ledger(cve: str) -> None:
    assert cve in LEDGER.read_text(encoding="utf-8")
