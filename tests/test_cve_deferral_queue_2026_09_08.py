"""The seven CVEs that sat under ``cve-deferred`` until 2026-09-08.

Five new pins plus one raised floor, closing #656, #690, #691, #692, #695,
#696, #697, #698 and #703. Every one of them had been dispositioned as "a bug
inside a third-party server's binary, no consumer-side signal" — which is true
of the *defect* and false of the *dependency*. What actually released them was
checking the registries, and in three cases the check changed the fix:

* **postgres-mcp CVE-2026-85620** has no fixed release at all. Upstream's newest
  tag is v0.3.0 and the security issue (#178) is still open, so the deferral's
  "version floor to 0.3.1+" pointed at a version that does not exist. npm also
  carries an unrelated ``postgres-mcp`` on 1.0.x, so presence-only would flag
  that project's dependents forever — the MCPHub trap. The 0.4.0 floor separates
  the two by version line and is asserted here in both directions.
* **ContextForge CVE-2026-77822** has no CPE range in NVD and no GitHub advisory;
  the project's advisory list stops at a v1.0.8 patched-version. IBM's own
  bulletin says affected ``<= v1.0.8``, fixed ``v1.0.9``. A floor taken from
  either open source alone ships one release short, so 1.0.8 is asserted to fire.
* **langflow CVE-2026-9186** affects 1.0.0–1.11.2, and the rule already carried a
  1.11.0 floor for CVE-2026-12940. Left alone it would have called 1.11.0, 1.11.1
  and 1.11.2 patched. The regression is stated below in the form it would have
  shipped in, so a later "simplification" back to 1.11.0 fails loudly.

``knowns`` is the control that is nearly simple: its only wrinkle is a one-version
name collision with a PyPI stub, resolved by an ``introduced`` bound.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_cve_pins_2026_07 as pins

TOOLUNIVERSE = "AAK-MCP-TOOLUNIVERSE-CVE-2026-81096-001"
CONTEXTFORGE = "AAK-MCP-CONTEXTFORGE-CVE-2026-77822-001"
POSTGRES_MCP = "AAK-MCP-POSTGRESMCP-CVE-2026-85620-001"
AWS_POSTGRES = "AAK-MCP-AWSPOSTGRES-CVE-2026-85787-001"
KNOWNS = "AAK-MCP-KNOWNS-CVE-2026-86439-001"
LANGFLOW = "AAK-MCP-LANGFLOW-CVE-2026-12940-001"

WAVE = (TOOLUNIVERSE, CONTEXTFORGE, POSTGRES_MCP, AWS_POSTGRES, KNOWNS)


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
# Registration
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id", WAVE)
def test_rule_is_registered(rule_id: str) -> None:
    assert rule_id in RULES, f"{rule_id} pinned but never registered"


@pytest.mark.parametrize("rule_id", WAVE)
def test_rule_cites_its_cve(rule_id: str) -> None:
    assert RULES[rule_id].cve_references, f"{rule_id} cites no CVE"


def test_contextforge_rule_cites_all_four_cves() -> None:
    """One floor closes four issues; the rule has to say so, or three of the
    four disclosures have no rule that names them."""
    cves = set(RULES[CONTEXTFORGE].cve_references)
    assert cves == {
        "CVE-2026-77822", "CVE-2026-18905", "CVE-2026-18486", "CVE-2026-18489",
    }


# ---------------------------------------------------------------------------
# ToolUniverse — CVE-2026-81096 (the CRITICAL 10.0 that opened the queue)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version,fires", [
    ("1.2.6", True),    # the newest affected release
    ("1.2.1", True),
    ("1.0.0", True),
    ("1.3.0", False),   # bearer auth + loopback bind + hardened attribute checks
    ("1.4.1", False),
])
def test_tooluniverse_floor(tmp_path: Path, version: str, fires: bool) -> None:
    assert (TOOLUNIVERSE in _pypi(tmp_path, f"tooluniverse=={version}")) is fires


def test_tooluniverse_unpinned_fires(tmp_path: Path) -> None:
    assert TOOLUNIVERSE in _pypi(tmp_path, "tooluniverse")


def test_tooluniverse_rule_is_critical() -> None:
    assert RULES[TOOLUNIVERSE].severity.value == "critical"


def test_tooluniverse_rule_states_it_is_a_pin_not_a_sandbox_detector() -> None:
    """The pin closes the CVE; it does not detect deny-list sandboxes. Saying so
    in `limitations` is what keeps the coverage claim honest."""
    assert "sandbox-escape pattern" in RULES[TOOLUNIVERSE].limitations


# ---------------------------------------------------------------------------
# ContextForge — the floor NVD and GitHub both under-report
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version,fires,why", [
    ("1.0.6", True, "CVE-2026-18905 range"),
    ("1.0.7", True, "CVE-2026-18486 range"),
    ("1.0.8", True, "CVE-2026-77822 / CVE-2026-18489 — the release the GitHub "
                    "advisory list would have made us call patched"),
    ("1.0.9", False, "IBM's stated fix"),
    ("1.0.10", False, "above the fix"),
])
def test_contextforge_floor(tmp_path: Path, version: str, fires: bool, why: str) -> None:
    assert (CONTEXTFORGE in _pypi(
        tmp_path, f"mcp-contextforge-gateway=={version}")) is fires, why


# ---------------------------------------------------------------------------
# postgres-mcp — no fix upstream, and a same-name project on npm
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version", ["0.1.0", "0.2.1", "0.3.0"])
def test_every_published_postgres_mcp_release_fires(tmp_path: Path, version: str) -> None:
    """There is no patched release: upstream issue #178 is open and v0.3.0 is
    still the newest tag, so the whole published 0.x line is affected."""
    assert POSTGRES_MCP in _pypi(tmp_path, f"postgres-mcp=={version}")


@pytest.mark.parametrize("version", ["1.0.0", "1.0.4"])
def test_unrelated_npm_postgres_mcp_never_fires(tmp_path: Path, version: str) -> None:
    """npm `postgres-mcp` is a different project — a type-safe multi-database MCP
    server on the 1.0.x line. A presence-only pin would flag its dependents
    permanently for someone else's CVE. This is the MCPHub failure mode."""
    assert POSTGRES_MCP not in _npm(tmp_path, **{"postgres-mcp": version})


def test_postgres_mcp_does_not_fire_on_the_server_packages(tmp_path: Path) -> None:
    """`postgres-mcp-server` and `awslabs.postgres-mcp-server` are distinct
    packages that merely share a prefix."""
    fired = _pypi(tmp_path, "awslabs.postgres-mcp-server==1.1.7")
    assert POSTGRES_MCP not in fired


def test_postgres_mcp_remediation_does_not_recommend_the_unverified_twin() -> None:
    """PyPI `postgres-mcp-pro` (0.4.0-0.4.2) shares the product's marketing name
    and summary but declares no repository and is not referenced upstream.
    Recommending it would be recommending a package we have not identified —
    the exact failure this scanner exists to catch."""
    rule = RULES[POSTGRES_MCP]
    assert "postgres-mcp-pro" not in rule.remediation
    assert "least-privilege" in rule.remediation


# ---------------------------------------------------------------------------
# awslabs postgres-mcp-server — the straightforward one
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version,fires", [
    ("1.1.6", True), ("1.1.2", True), ("1.1.7", False), ("1.2.0", False),
])
def test_awslabs_postgres_floor(tmp_path: Path, version: str, fires: bool) -> None:
    assert (AWS_POSTGRES in _pypi(
        tmp_path, f"awslabs.postgres-mcp-server=={version}")) is fires


# ---------------------------------------------------------------------------
# knowns — the one-version name collision
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version,fires", [
    ("0.29.1", True),   # the release the advisory cites
    ("0.8.3", True),
    ("0.1.1", True),    # lowest npm release the introduced bound still covers
    ("0.30.0", False),  # the fix
    ("0.33.0", False),
])
def test_knowns_floor(tmp_path: Path, version: str, fires: bool) -> None:
    assert (KNOWNS in _npm(tmp_path, knowns=version)) is fires


def test_knowns_does_not_fire_on_the_pypi_stub(tmp_path: Path) -> None:
    """PyPI `knowns` has exactly one release, 0.1.0, described "Add your
    description here". npm's history starts at 0.1.0 too, so the two identities
    overlap at exactly one version; `introduced=(0, 1, 1)` trades npm's single
    0.1.0 release for never flagging the stub."""
    assert KNOWNS not in _pypi(tmp_path, "knowns==0.1.0")


def test_knowns_stays_off_prefixed_siblings(tmp_path: Path) -> None:
    assert KNOWNS not in _npm(tmp_path, **{"knowns-cli": "0.1.0"})


# ---------------------------------------------------------------------------
# langflow — the raised floor, stated as the regression it prevents
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version", ["1.11.0", "1.11.1", "1.11.2"])
def test_langflow_versions_the_old_floor_called_patched(tmp_path: Path, version: str) -> None:
    """CVE-2026-9186 affects 1.0.0-1.11.2. The rule's previous 1.11.0 floor —
    correct for CVE-2026-12940 — marks all three of these patched. If anyone
    lowers the floor back to 1.11.0 to "simplify", this fails rather than
    going quiet."""
    assert LANGFLOW in _pypi(tmp_path, f"langflow=={version}")


@pytest.mark.parametrize("version,fires", [
    ("1.10.1", True), ("1.11.3", False), ("1.12.0", False), ("0.9.9", False),
])
def test_langflow_floor_bounds(tmp_path: Path, version: str, fires: bool) -> None:
    assert (LANGFLOW in _pypi(tmp_path, f"langflow=={version}")) is fires


def test_langflow_rule_cites_the_new_cve() -> None:
    assert "CVE-2026-9186" in RULES[LANGFLOW].cve_references


# ---------------------------------------------------------------------------
# Cross-cutting: a clean project stays clean
# ---------------------------------------------------------------------------

def test_no_wave_rule_fires_on_a_patched_project(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "tooluniverse==1.4.1\n"
        "mcp-contextforge-gateway==1.0.10\n"
        "awslabs.postgres-mcp-server==1.2.0\n"
        "langflow==1.12.0\n",
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"knowns": "0.33.0"}}), encoding="utf-8"
    )
    assert not (_fired(tmp_path) & set(WAVE) | (_fired(tmp_path) & {LANGFLOW}))
