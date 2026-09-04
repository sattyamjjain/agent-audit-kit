"""The nine CVEs that sat under ``cve-deferred`` until 2026-09-04.

Three pins, nine watcher-filed issues, and each of the three has one detail that
a version floor gets wrong if nobody writes it down:

* **n8n CVE-2026-85166** is "before 2.35.4 **and** 2.36.x before 2.36.2". A lone
  2.35.4 floor clears 2.36.0 and 2.36.1 — versions that sort above it and are
  still vulnerable. Two arms, one rule id, exactly as CVE-2026-65594 already does.
* **MCPHub** publishes as npm ``@samanhappy/mcphub``. PyPI ``mcphub`` is a
  different project, by a different author, on a 0.1.x line whose latest release
  (0.1.11) is below every fix version here — so a bare-token pin would flag every
  one of its dependents forever, for somebody else's CVE. That is the identity
  question the deferral was held open on.
* **mcp-sequential-thinking** is the simple one, and is here so the batch has a
  control that is simple.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_cve_pins_2026_07 as pins

N8N = "AAK-MCP-N8N-CVE-2026-72768-001"
HUB = "AAK-MCP-MCPHUB-CVE-2026-79748-001"
SEQ = "AAK-MCP-SEQTHINKING-CVE-2026-81845-001"


def _fired(tmp_path: Path) -> set[str]:
    return {f.rule_id for f in pins.scan(tmp_path)[0]}


def _npm(tmp_path: Path, **deps: str) -> set[str]:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": deps}), encoding="utf-8"
    )
    return _fired(tmp_path)


def _pypi(tmp_path: Path, line: str) -> set[str]:
    (tmp_path / "requirements.txt").write_text(line + "\n", encoding="utf-8")
    return _fired(tmp_path)


# ---------------------------------------------------------------------------
# n8n CVE-2026-85166 — the two-arm floor
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version,fires,why", [
    ("2.34.1", True, "the previous floor is now below the new one"),
    ("2.35.3", True, "just below the mainline fix"),
    ("2.35.4", False, "mainline fix clears"),
    ("2.36.0", True, "ABOVE 2.35.4 and still vulnerable — the whole reason for arm two"),
    ("2.36.1", True, "same branch, still vulnerable"),
    ("2.36.2", False, "branch fix clears"),
    ("2.37.10", False, "current npm latest clears"),
])
def test_n8n_two_arm_floor(tmp_path: Path, version: str, fires: bool, why: str) -> None:
    assert (N8N in _npm(tmp_path, n8n=version)) is fires, why


def test_a_single_floor_would_have_missed_the_2_36_branch(tmp_path: Path) -> None:
    """States the bug in the form it would have shipped in.

    If someone later "simplifies" this pin back to one arm, every n8n 2.36.0 and
    2.36.1 install goes quiet while remaining exposed to CVE-2026-85166. This test
    is the tripwire for that edit, and it fails loudly rather than by omission.
    """
    assert N8N in _npm(tmp_path, n8n="2.36.0")
    arms = [p for p in pins._PINS if p.rule_id == N8N]
    assert len(arms) == 2, "the 2.36.x line needs its own arm"
    assert {a.floor for a in arms} == {(2, 35, 4), (2, 36, 2)}
    branch = next(a for a in arms if a.floor == (2, 36, 2))
    assert branch.introduced == (2, 36, 0), (
        "the branch arm must be introduced-bounded, or it re-flags everything "
        "below 2.36.0 that the mainline arm already cleared"
    )


def test_branch_fixture_on_the_2_36_line_fires() -> None:
    """A committed fixture for the case a single floor reads as patched.

    Kept as a fixture rather than only as a parametrised string so the shape is
    visible to somebody browsing tests/fixtures/cves/ and wondering why n8n has
    two directories.
    """
    from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import scan

    base = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-85166-n8n-branch"
    assert N8N in {f.rule_id for f in scan(base / "vulnerable")[0]}


def test_n8n_pin_stays_off_the_distinct_n8n_mcp_package(tmp_path: Path) -> None:
    """`n8n-mcp` is a different package with its own pin and its own floor."""
    fired = _npm(tmp_path, **{"n8n-mcp": "2.57.4"})
    assert N8N not in fired


# ---------------------------------------------------------------------------
# MCPHub — the identity question
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version,fires", [
    ("0.12.12", True), ("0.12.14", True), ("1.0.28", True),
    ("1.0.31", True), ("1.0.32", False), ("1.0.34", False),
])
def test_mcphub_floor(tmp_path: Path, version: str, fires: bool) -> None:
    assert (HUB in _npm(tmp_path, **{"@samanhappy/mcphub": version})) is fires


def test_pypi_mcphub_is_a_different_project_and_must_stay_silent(tmp_path: Path) -> None:
    """The negative this pin was deferred for a week to get right.

    npm ``@samanhappy/mcphub`` is a self-hosted MCP gateway on 1.0.x (latest
    1.0.34). PyPI ``mcphub`` is Cognitive-Stack's framework-integration library on
    0.1.x (latest 0.1.11), by a different author, in a different repository. Its
    highest release will never reach a 1.0.32 floor, so a bare-token pin does not
    flag it *sometimes* — it flags every dependent, permanently, for a CVE in
    software they do not run.
    """
    assert _pypi(tmp_path, "mcphub==0.1.11") == set(), (
        "PyPI `mcphub` is not the vulnerable package; nothing may fire on it"
    )


def test_mcphub_pin_is_keyed_on_the_scoped_name() -> None:
    arms = [p for p in pins._PINS if p.rule_id == HUB]
    assert len(arms) == 1
    assert arms[0].names == ("@samanhappy/mcphub",), (
        "keying this on a bare `mcphub` token would match the unrelated PyPI project"
    )


def test_mcphub_covers_all_eight_advisories() -> None:
    """One floor, eight CVEs — so the rule has to cite eight."""
    cves = set(RULES[HUB].cve_references)
    assert cves == {f"CVE-2026-797{n}" for n in range(43, 51)}, cves


# ---------------------------------------------------------------------------
# mcp-sequential-thinking — the control
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version,fires", [
    ("0.4.0", True), ("0.5.0", True), ("0.6.0", False), ("0.6.1", False),
])
def test_sequential_thinking_floor(tmp_path: Path, version: str, fires: bool) -> None:
    assert (SEQ in _pypi(tmp_path, f"mcp-sequential-thinking=={version}")) is fires


# ---------------------------------------------------------------------------
# Shared invariants
# ---------------------------------------------------------------------------

def test_a_clean_manifest_stays_silent(tmp_path: Path) -> None:
    """No pin fires on a project that depends on none of them."""
    assert _npm(tmp_path, express="4.19.2", react="18.3.1") == set()


@pytest.mark.parametrize("rule_id", [N8N, HUB, SEQ])
def test_each_rule_is_registered_and_remediable(rule_id: str) -> None:
    rule = RULES.get(rule_id)
    assert rule is not None, f"{rule_id} fires but is not in the registry"
    assert rule.remediation.strip(), "a finding without remediation is half a finding"
    assert rule.cve_references, "a CVE pin must cite its CVEs"
