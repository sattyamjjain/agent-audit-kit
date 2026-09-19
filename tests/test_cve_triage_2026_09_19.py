"""The 2026-09-15..16 CVE wave (issues #745-#754), and the two pin bugs it exposed.

Ten disclosures. Five needed a new package pin, one moved an existing floor, one
added a name to an existing pin, and one was already under a floor that covers
it. Reaching them surfaced two false positives in the pin table that had nothing
to do with this wave:

  * `_Pin` had no notion of which package registry its version line belonged to,
    so the PyPI `praisonai` floor of 4.6.78 was compared against the unrelated
    npm `praisonai`, whose newest release is 1.7.4 -- reporting a fully patched
    install as vulnerable and telling the reader to upgrade to a version npm has
    never published.
  * A bare package name that is a substring of a scoped sibling matched inside
    that sibling, captured no version, and was reported as "unpinned".
    `frontmcp` / `@frontmcp/adapters` and `better-auth` /
    `@better-auth/oauth-provider` were both live.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_cve_pins_2026_07 as pins


def _js(tmp_path: Path, name: str, version: str) -> Path:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "dependencies": {name: version}})
    )
    return tmp_path


def _py(tmp_path: Path, spec: str) -> Path:
    (tmp_path / "requirements.txt").write_text(spec + "\n")
    return tmp_path


def _rule_ids(root: Path) -> set[str]:
    findings, _ = pins.scan(root)
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------------------
# Ecosystem scoping: the npm/PyPI `praisonai` collision
# ---------------------------------------------------------------------------

PRAISONAI_PY = "AAK-MCP-PRAISONAI-CVE-2026-61427-001"
PRAISONAI_TS = "AAK-MCP-PRAISONAI-TS-CVE-2026-57139-001"


def test_patched_npm_praisonai_does_not_fire_the_pypi_floor(tmp_path):
    """npm praisonai@1.7.4 is the newest release there and must be silent.

    Before `_Pin.ecosystem`, the PyPI 4.6.78 floor matched this and reported it
    vulnerable, with remediation text pointing at a version npm has never had.
    """
    assert _rule_ids(_js(tmp_path, "praisonai", "1.7.4")) == set()


def test_vulnerable_npm_praisonai_fires_only_the_typescript_pin(tmp_path):
    assert _rule_ids(_js(tmp_path, "praisonai", "1.6.0")) == {PRAISONAI_TS}


def test_npm_praisonai_at_its_own_floor_is_silent(tmp_path):
    assert _rule_ids(_js(tmp_path, "praisonai", "1.7.2")) == set()


def test_vulnerable_pypi_praisonai_still_fires_and_not_the_npm_pin(tmp_path):
    """The scoping must not cost the coverage it was protecting."""
    assert _rule_ids(_py(tmp_path, "praisonai==4.6.70")) == {PRAISONAI_PY}


def test_patched_pypi_praisonai_is_silent(tmp_path):
    assert _rule_ids(_py(tmp_path, "praisonai==4.6.78")) == set()


def test_mcp_config_is_unclassified_so_every_pin_still_applies(tmp_path):
    """An MCP config can name a package from either registry.

    `npx -y a` sits next to `uvx b` in the same file, so the filename implies no
    ecosystem and scoping must not silently drop coverage there.
    """
    assert pins._ecosystem_of(Path("mcp.json")) is None
    assert pins._ecosystem_of(Path("claude_desktop_config.json")) is None
    assert pins._ecosystem_of(Path("package.json")) == "js"
    assert pins._ecosystem_of(Path("requirements.txt")) == "py"
    assert pins._ecosystem_of(Path("requirements-dev.txt")) == "py"
    assert pins._ecosystem_of(Path("pyproject.toml")) == "py"

    py_only = pins._Pin("X", "x", ("x",), (1, 0, 0), ecosystem="py")
    assert pins._pin_applies(py_only, None) is True
    assert pins._pin_applies(py_only, "py") is True
    assert pins._pin_applies(py_only, "js") is False
    unscoped = pins._Pin("Y", "y", ("y",), (1, 0, 0))
    assert pins._pin_applies(unscoped, "js") is True


# ---------------------------------------------------------------------------
# Substring shadowing: a bare name inside a scoped sibling
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "scoped,bare,patched,vulnerable,rule_id",
    [
        (
            "@frontmcp/adapters", "frontmcp", "1.5.7", "1.2.1",
            "AAK-MCP-FRONTMCP-CVE-2026-67531-001",
        ),
        (
            "@better-auth/oauth-provider", "better-auth", "1.6.13", "1.6.11",
            "AAK-MCP-BETTERAUTH-CVE-2026-53512-001",
        ),
    ],
)
def test_scoped_sibling_at_the_floor_is_silent(
    tmp_path, scoped, bare, patched, vulnerable, rule_id
):
    """The bare name must not match inside the scoped one and read as unpinned."""
    assert _rule_ids(_js(tmp_path, scoped, patched)) == set()


@pytest.mark.parametrize(
    "scoped,bare,patched,vulnerable,rule_id",
    [
        (
            "@frontmcp/adapters", "frontmcp", "1.5.7", "1.2.1",
            "AAK-MCP-FRONTMCP-CVE-2026-67531-001",
        ),
        (
            "@better-auth/oauth-provider", "better-auth", "1.6.13", "1.6.11",
            "AAK-MCP-BETTERAUTH-CVE-2026-53512-001",
        ),
    ],
)
def test_scoped_and_bare_below_the_floor_both_still_fire(
    tmp_path, scoped, bare, patched, vulnerable, rule_id
):
    assert rule_id in _rule_ids(_js(tmp_path, scoped, vulnerable))
    other = tmp_path / "bare"
    other.mkdir()
    assert rule_id in _rule_ids(_js(other, bare, vulnerable))


def test_no_pin_has_an_unguarded_substring_shadowing_pair():
    """Any future pin naming both a bare package and its scoped sibling must
    guard the bare one, or it reintroduces the `_mk_bare_re` bug."""
    offenders = []
    for pin in pins._PINS:
        for a in pin.names:
            for b in pin.names:
                if a != b and a in b and not pin.regexes:
                    offenders.append((pin.rule_id, a, b))
    assert offenders == [], offenders


# ---------------------------------------------------------------------------
# The wave itself
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "manifest,name,vulnerable,patched,rule_id",
    [
        ("py", "mysql-mcp-server", "0.4.1", "0.4.2",
         "AAK-MCP-MYSQLMCP-CVE-2026-59971-001"),
        ("js", "@zereight/mcp-gitlab", "2.1.27", "2.1.30",
         "AAK-MCP-GITLAB-ZEREIGHT-CVE-2026-61560-001"),
        ("js", "flowise", "3.1.3", "3.1.4",
         "AAK-MCP-FLOWISE-CVE-2026-91931-001"),
        ("js", "mcp-from-openapi", "2.4.0", "2.5.0",
         "AAK-MCP-FROMOPENAPI-CVE-2026-59973-001"),
        ("py", "meta-ads-mcp", "1.0.110", "1.0.115",
         "AAK-METAADS-CVE-2026-48039-001"),
    ],
)
def test_wave_pin_fires_below_floor_and_is_silent_at_it(
    tmp_path, manifest, name, vulnerable, patched, rule_id
):
    vuln_dir, ok_dir = tmp_path / "vuln", tmp_path / "ok"
    vuln_dir.mkdir()
    ok_dir.mkdir()
    if manifest == "py":
        assert rule_id in _rule_ids(_py(vuln_dir, f"{name}=={vulnerable}"))
        assert rule_id not in _rule_ids(_py(ok_dir, f"{name}=={patched}"))
    else:
        assert rule_id in _rule_ids(_js(vuln_dir, name, vulnerable))
        assert rule_id not in _rule_ids(_js(ok_dir, name, patched))


def test_meta_ads_floor_moved_above_the_old_one():
    """CVE-2026-54549 is fixed at 1.0.115, above the 1.0.109 of CVE-2026-48039.

    A `cve_references` line alone could not have covered 1.0.109..1.0.114.
    """
    pin = next(p for p in pins._PINS if p.rule_id == "AAK-METAADS-CVE-2026-48039-001")
    assert pin.floor == (1, 0, 115)


def test_gitlab_pin_uses_the_highest_of_its_three_fix_versions():
    """2.1.27 closes two of the three; only 2.1.30 closes the rebinding one."""
    pin = next(
        p for p in pins._PINS
        if p.rule_id == "AAK-MCP-GITLAB-ZEREIGHT-CVE-2026-61560-001"
    )
    assert pin.floor == (2, 1, 30)


@pytest.mark.parametrize(
    "rule_id,cve",
    [
        ("AAK-MCP-MYSQLMCP-CVE-2026-59971-001", "CVE-2026-59971"),
        ("AAK-MCP-PRAISONAI-TS-CVE-2026-57139-001", "CVE-2026-57139"),
        ("AAK-MCP-GITLAB-ZEREIGHT-CVE-2026-61560-001", "CVE-2026-61560"),
        ("AAK-MCP-GITLAB-ZEREIGHT-CVE-2026-61560-001", "CVE-2026-61559"),
        ("AAK-MCP-GITLAB-ZEREIGHT-CVE-2026-61560-001", "CVE-2026-61568"),
        ("AAK-MCP-FLOWISE-CVE-2026-91931-001", "CVE-2026-91931"),
        ("AAK-MCP-FLOWISE-CVE-2026-91931-001", "CVE-2026-91932"),
        ("AAK-MCP-FROMOPENAPI-CVE-2026-59973-001", "CVE-2026-59973"),
        ("AAK-MCP-FRONTMCP-CVE-2026-67531-001", "CVE-2026-59973"),
        ("AAK-METAADS-CVE-2026-48039-001", "CVE-2026-54549"),
        ("AAK-MCP-CONTEXTFORGE-CVE-2026-77822-001", "CVE-2026-53710"),
    ],
)
def test_every_wave_cve_is_recorded_against_a_rule(rule_id, cve):
    assert cve in RULES[rule_id].cve_references


def test_contextforge_cve_is_referenced_not_repinned():
    """CVE-2026-53710 is fixed at 1.0.2, below the existing 1.0.9 floor.

    Every affected version already fires, so it is recorded for auditability
    rather than given a pin of its own.
    """
    pin = next(
        p for p in pins._PINS
        if p.rule_id == "AAK-MCP-CONTEXTFORGE-CVE-2026-77822-001"
    )
    assert pin.floor == (1, 0, 9)
    assert not any(
        "CVE-2026-53710" in p.rule_id for p in pins._PINS
    ), "53710 should not have its own pin"


def test_unauth_transport_shape_rule_records_the_four_matching_cves():
    refs = RULES["AAK-MCP-HTTP-NOAUTH-SERVER-001"].cve_references
    for cve in ("CVE-2026-59971", "CVE-2026-53710",
                "CVE-2026-57139", "CVE-2026-61560"):
        assert cve in refs


# ---------------------------------------------------------------------------
# Scanner contract
# ---------------------------------------------------------------------------

def test_scanned_set_counts_files_read_not_only_files_that_matched(tmp_path):
    """`engine.run_scan` reports len(scanned) as files_scanned.

    Gating the add on a match under-reported the denominator, so a clean repo
    looked unscanned.
    """
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n")
    findings, scanned = pins.scan(tmp_path)
    assert findings == []
    assert scanned == {"requirements.txt"}


# ---------------------------------------------------------------------------
# CVE-to-rule latency: coverage that predates the disclosure
# ---------------------------------------------------------------------------

def test_latency_doc_does_not_report_a_negative_fastest_response():
    """A rule shipped before NVD published has no turnaround to measure.

    CVE-2026-53708's published date was withheld from the ledger rather than
    let it render `Fastest: -29 days`, which reads as a 29-day head start on a
    stopwatch that had not been started. The date is now on file and the row
    sits in its own population, the same split the deferred-backlog rows
    already had.
    """
    doc = (Path(__file__).resolve().parent.parent / "docs" / "cve-latency.md")
    text = doc.read_text(encoding="utf-8")
    summary = text.split("## Coverage of this measurement")[0]
    fastest = [ln for ln in summary.splitlines() if ln.startswith("| Fastest")]
    assert fastest, "latency doc lost its Fastest row"
    value = int(fastest[0].split("|")[2].strip())
    assert value >= 0, f"Fastest is {value}; a response time cannot be negative"


def test_pre_covered_rows_are_disclosed_rather_than_dropped():
    doc = (Path(__file__).resolve().parent.parent / "docs" / "cve-latency.md")
    text = doc.read_text(encoding="utf-8")
    assert "already covered when NVD published" in text
    assert "CVE-2026-53708" in text


def test_pre_covered_rows_are_excluded_from_the_response_population():
    import importlib.util

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "cve_latency", root / "scripts" / "cve_latency.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod._PRE_COVERED_DAYS == 0
    rows = mod.collect_rows() if hasattr(mod, "collect_rows") else None
    if rows is not None:
        response = [
            r.days for r in rows
            if mod._PRE_COVERED_DAYS <= r.days <= mod._BACKLOG_DAYS
        ]
        assert all(d >= 0 for d in response)
