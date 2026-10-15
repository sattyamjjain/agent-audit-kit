"""The 2026-10-15 batch's dispositions that are not new pin rows, pinned as facts.

#982 to #986, plus the records the watcher had not filed yet:

* CVE-2026-53709 (#983) and CVE-2026-53711 join the ContextForge pin, whose 1.0.9
  floor sits above both fixes (1.0.2 and 0.3.1). The 1.0.1 wheel defaults
  ``JWT_SECRET_KEY`` to a published string with ``require_user_in_db=False``; the
  Admin UI writes a saved prompt template into ``innerHTML`` up to 0.3.0.
* CVE-2026-55786 joins the Flyto2 Core pin (floor 2.26.6): the HTTP MCP route takes
  ``tools/call`` without ``require_auth`` from 2.26.2 to 2.26.3, fixed in 2.26.4.
* CVE-2026-77363 (#984) is also on ``AAK-DNS-REBIND-001``. The fixture pair is
  written for these tests, not copied from obsidian-tc (AGPL-3.0-only): it keeps
  only the constructs that decide the rule, the transport construction and, in the
  patched shape, the ``allowedHosts`` setting threaded through the CLI and schema.
* Out of scope, recorded so the watcher does not file them: mac-shell-mcp
  (CVE-2026-108953), whose only registry release is the fix; Wanwu
  (CVE-2026-108855, CVE-2026-108856), on the #977 basis; phpMyFAQ
  (CVE-2026-108851), a Composer project.

If a reader for one of those artifacts is ever added, the boundary tests fail and
the CVE becomes re-triageable. That is the intent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import container_image_pins, dns_rebind
from agent_audit_kit.scanners import mcp_cve_pins_2026_07 as pins

FIXTURES = Path(__file__).parent / "fixtures" / "cves"
CONTEXTFORGE = "AAK-MCP-CONTEXTFORGE-CVE-2026-77822-001"
FLYTO = "AAK-MCP-FLYTO-CVE-2026-67425-001"
REBIND = "AAK-DNS-REBIND-001"
OBSIDIANTC = "AAK-MCP-OBSIDIANTC-CVE-2026-77366-001"


def _write(root: Path, name: str, body: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _pin_ids(root: Path) -> set[str]:
    return {f.rule_id for f in pins.scan(root)[0]}


# --- ContextForge: CVE-2026-53709 and CVE-2026-53711 ---------------------------------


def test_contextforge_carries_both_and_no_new_row() -> None:
    refs = RULES[CONTEXTFORGE].cve_references
    assert {"CVE-2026-53709", "CVE-2026-53711"} <= set(refs)
    rows = [p for p in pins._PINS if p.rule_id == CONTEXTFORGE]
    assert [(p.floor, p.introduced) for p in rows] == [((1, 0, 9), None)]
    assert not any("53709" in p.rule_id or "53711" in p.rule_id for p in pins._PINS)


def test_contextforge_rule_maps_the_authentication_cves() -> None:
    """CVE-2026-78573 and CVE-2026-53709 are authentication failures."""
    assert "MCP07:2025" in RULES[CONTEXTFORGE].owasp_mcp_references
    assert "ASI03" in RULES[CONTEXTFORGE].owasp_agentic_references


def test_contextforge_fixtures() -> None:
    root = FIXTURES / "cve-2026-53709-contextforge"
    assert CONTEXTFORGE in _pin_ids(root / "vulnerable")
    assert CONTEXTFORGE not in _pin_ids(root / "negative")


@pytest.mark.parametrize(("version", "fires"), [
    ("0.1.0", True),   # already ships `my-test-key`, and the prompt sink
    ("0.2.0", True),   # where CVE-2026-53711's record starts
    ("0.3.0", True),   # the last release that writes the template as HTML
    ("1.0.1", True),   # the last release with the published key and the bootstrap
    ("1.0.2", True),   # fixed for CVE-2026-53709, still inside the 1.0.8 CVEs
    ("1.0.9", False),
])
def test_contextforge_versions(tmp_path: Path, version: str, fires: bool) -> None:
    _write(tmp_path, "requirements.txt", f"mcp-contextforge-gateway=={version}\n")
    assert (CONTEXTFORGE in _pin_ids(tmp_path)) is fires


# --- Flyto2 Core: CVE-2026-55786 -----------------------------------------------------


def test_flyto_carries_the_mcp_route_cve_on_the_same_row() -> None:
    assert RULES[FLYTO].cve_references == ["CVE-2026-67425", "CVE-2026-55786"]
    rows = [p for p in pins._PINS if p.rule_id == FLYTO]
    assert [(p.floor, p.introduced) for p in rows] == [((2, 26, 6), None)]
    assert {"MCP05:2025", "MCP07:2025"} <= set(RULES[FLYTO].owasp_mcp_references)
    assert "ASI05" in RULES[FLYTO].owasp_agentic_references


def test_flyto_fixtures() -> None:
    root = FIXTURES / "cve-2026-55786-flyto-core"
    assert FLYTO in _pin_ids(root / "vulnerable")
    assert FLYTO not in _pin_ids(root / "negative")


@pytest.mark.parametrize(("version", "fires"), [
    ("2.26.2", True),   # where the record starts
    ("2.26.3", True),   # `routes/mcp.py` POST has no require_auth
    ("2.26.4", True),   # fixed for this CVE (db7f116), still below CVE-2026-67425's fix
    ("2.26.7", False),  # the first published release past the 2.26.6 floor
])
def test_flyto_versions(tmp_path: Path, version: str, fires: bool) -> None:
    _write(tmp_path, "requirements.txt", f"flyto-core=={version}\n")
    assert (FLYTO in _pin_ids(tmp_path)) is fires


# --- CVE-2026-77363 on the DNS-rebinding shape rule ----------------------------------


def test_rebind_rule_fires_on_the_affected_shape_and_clears_on_the_fix() -> None:
    root = FIXTURES / "cve-2026-77363-obsidian-tc-rebind"
    findings = dns_rebind.scan(root / "vulnerable")[0]
    assert [(f.rule_id, f.file_path) for f in findings] == [
        (REBIND, "packages/server/src/transports/http.ts"),
    ]
    assert dns_rebind.scan(root / "patched")[0] == []
    assert "CVE-2026-77363" in RULES[REBIND].cve_references


def test_the_patched_shape_clears_through_its_settings_wiring(tmp_path: Path) -> None:
    """The 1.3.1 shape's check lives in the transport, written as `allowedHosts?:`
    and `opts.allowedHosts ?? []`, which the rule's mitigation pattern does not
    read. What clears the project is the setting threaded through the CLI and the
    config schema, as in the release, so the negative fixture has to keep both."""
    patched = FIXTURES / "cve-2026-77363-obsidian-tc-rebind" / "patched"
    transport = patched / "packages/server/src/transports/http.ts"
    _write(tmp_path, "src/transports/http.ts", transport.read_text(encoding="utf-8"))
    assert [f.rule_id for f in dns_rebind.scan(tmp_path)[0]] == [REBIND]


# --- One rule, two readers -----------------------------------------------------------


def test_obsidian_tc_rule_has_an_npm_row_and_an_image_row() -> None:
    npm_rows = [p for p in pins._PINS if p.rule_id == OBSIDIANTC]
    image_rows = [p for p in container_image_pins._PINS if p.rule_id == OBSIDIANTC]
    assert [(p.names, p.floor, p.introduced, p.requires_version) for p in npm_rows] == [
        (("obsidian-tc",), (1, 3, 1), (1, 0, 0), True),
    ]
    assert [(p.image, p.floor) for p in image_rows] == [
        ("ghcr.io/the-40-thieves/obsidian-tc", (1, 3, 1)),
    ]
    assert image_rows[0].cves == tuple(RULES[OBSIDIANTC].cve_references)


# --- Out of scope: the boundaries the dispositions rest on ---------------------------


def test_no_pin_names_mac_shell_mcp() -> None:
    names = {n for p in pins._PINS for n in p.names}
    assert not {"mac-shell-mcp", "@the_cfdude/mac-shell-mcp"} & names


def test_a_mac_shell_mcp_clone_states_no_version_aak_reads(tmp_path: Path) -> None:
    """Before 2.0.0 the README started the server from a git clone by path."""
    _write(tmp_path, ".mcp.json",
           '{"mcpServers": {"mac-shell": {"command": "node", '
           '"args": ["/Users/me/mac-shell-mcp/build/index.js"]}}}')
    findings = run_scan(tmp_path).findings
    assert not any("CVE-2026-108953" in f.cve_references for f in findings)


def test_no_reader_opens_a_composer_manifest(tmp_path: Path) -> None:
    readable = {n.lower() for n in pins._CANDIDATE_NAMES}
    assert not {"composer.json", "composer.lock"} & readable
    _write(tmp_path, "composer.json", '{"require": {"thorsten/phpmyfaq": "4.1.10"}}')
    findings = run_scan(tmp_path).findings
    assert not any("CVE-2026-108851" in f.cve_references for f in findings)


@pytest.mark.parametrize("cve", [
    "CVE-2026-108953", "CVE-2026-108855", "CVE-2026-108856", "CVE-2026-108851",
])
def test_out_of_scope_cves_are_on_no_rule(cve: str) -> None:
    assert not any(cve in r.cve_references for r in RULES.values())
