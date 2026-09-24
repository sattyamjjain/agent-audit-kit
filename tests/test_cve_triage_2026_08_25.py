"""Disposition for CVE-2026-19801 (BetterLinks), pinned so it is not re-litigated.

This one is worth a test because the obvious reasons to dismiss it are all wrong,
and the real reason is narrow.

The plugin is named "BetterLinks - Link Shortener, Link Cloaking, Redirects,
Affiliate Link Manager & MCP", and the tempting call is that "MCP" is marketing.
It is not: the plugin ships a genuine MCP implementation under ``includes/Mcp/``
- ``Mcp_Server.php``, ``Mcp_Tools.php``, ``Mcp_OAuth.php``, ``Mcp_Pairing.php``,
``Mcp_Rate_Limiter.php``, ``Mcp_Self_Test.php``. So this is not the Splunkbase
name-collision shape, and dismissing it on that basis would have been wrong.

It is out of scope for a different and much more specific reason: **the
vulnerability is not in that MCP surface**. NVD points at
``includes/Admin/Ajax.php`` and ``betterlinks.php``. The defect is that three
WordPress ``wp_ajax_*`` handlers (``create_fbs_link`` / ``check_fbs_link`` /
``update_fbs_link``) gate on ``check_ajax_referer`` (a nonce, i.e. session
origin) and ``defined('FLUENT_BOARDS')`` (a companion plugin being active), and
on nothing that authorizes the *caller* - while sibling handlers in the same file
call ``current_user_can('manage_options')``. CWE-862, in PHP, reached over
admin-ajax. Nothing under ``includes/Mcp/`` references those handlers.

Three boundaries then close it, and each is checkable:

1. It is a WordPress plugin, distributed through wordpress.org. ``betterlinks``
   resolves on neither npm nor PyPI (both 404), so no artifact
   ``_CANDIDATE_NAMES`` opens carries its version.
2. AgentAuditKit has no PHP semantic analysis and no WordPress awareness. The
   only ``.php`` in the package is an entry in a source-extension list in
   ``stainless_lineage.py``.
3. The vulnerable path is not an MCP path, so even a PHP-reading MCP scanner
   would not be looking at it.

Fixed upstream in 3.1.1 - verified by diffing the plugin zips rather than taken
from the advisory: 3.1.0 contains zero occurrences of the guard, 3.1.1 defines
``current_user_can_manage_fbs_link()`` and calls it from all three handlers.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import (
    _CANDIDATE_GLOBS,
    _CANDIDATE_NAMES,
    _PINS,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER = REPO_ROOT / "CHANGELOG.cves.md"

SECTION_DATE, SECTION_TITLE = (
    "2026-08-25",
    "a real MCP server, and a bug that is not in it",
)

def _section_body(date: str, title_prefix: str) -> str:
    """The body of the ledger section headed `date` whose title starts as given.

    Matched on the date plus the title, tolerating any parenthesised label
    between them. The title is what disambiguates two sections dated the same
    day; the label is release metadata a section gains when it ships, and
    twenty-two of them were backfilled at once, so pinning the whole heading
    string made this test fail on a labelling change it has no stake in.
    """
    text = LEDGER.read_text(encoding="utf-8")
    pattern = re.compile(
        r"^##\s+"
        + re.escape(date)
        + r"(?:\s*\([^)]*\))?\s*[:\u2014-]?\s*"
        + re.escape(title_prefix),
        re.M,
    )
    match = pattern.search(text)
    assert match, f"ledger has no {date} section titled {title_prefix!r}"
    return text[match.end():].split("\n## ", 1)[0]

CVE = "CVE-2026-19801"

# Spellings a pin must never be keyed on. Neither resolves on a registry the pin
# detector reads, so a pin here would key on nothing and never fire at all.
COLLIDING_NAMES = ("betterlinks", "better-links", "betterlinks-mcp")


def _row() -> str:
    section = _section_body(SECTION_DATE, SECTION_TITLE)
    rows = [ln for ln in section.splitlines() if ln.startswith("|") and CVE in ln]
    assert rows, f"{CVE} has no row in its ledger section"
    return rows[0]


# ---------------------------------------------------------------------------
# Out of scope
# ---------------------------------------------------------------------------


def test_no_rule_claims_this_cve() -> None:
    claiming = sorted(
        rid for rid, rule in RULES.items() if CVE in (rule.cve_references or [])
    )
    assert not claiming, (
        f"{CVE} is recorded out of scope but rule(s) {claiming} reference it"
    )


@pytest.mark.parametrize("name", COLLIDING_NAMES)
def test_no_pin_is_keyed_on_a_betterlinks_name(name: str) -> None:
    hits = sorted(p.rule_id for p in _PINS if any(n.lower() == name for n in p.names))
    assert not hits, f"pin(s) {hits} are keyed on {name!r}, which is on no registry"


def test_the_detector_reads_no_wordpress_manifest() -> None:
    """Reason 1, as a fact about the code rather than a claim in prose.

    If a WordPress plugin manifest is ever added to the candidate set, this fails
    and the CVE becomes re-triageable — which is the intent.
    """
    readable = {n.lower() for n in _CANDIDATE_NAMES} | {
        g.lower() for g in _CANDIDATE_GLOBS
    }
    for wp in ("style.css", "composer.json", "plugin.php", "readme.txt"):
        assert wp not in readable


def test_the_package_has_no_php_analysis() -> None:
    """Reason 2. `.php` appears once, as a file extension in a list.

    Asserted rather than described, because "we do not read PHP" is the kind of
    claim that quietly stops being true.
    """
    scanners = REPO_ROOT / "agent_audit_kit" / "scanners"
    php_aware = []
    for path in scanners.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if ".php" in text and path.name != "stainless_lineage.py":
            php_aware.append(path.name)
    assert not php_aware, (
        f"{php_aware} now reference .php; if PHP analysis has landed, {CVE} is "
        "re-triageable"
    )


# ---------------------------------------------------------------------------
# The ledger row has to carry the reasoning, not just the verdict
# ---------------------------------------------------------------------------


def test_disposition_is_recorded_in_the_ledger() -> None:
    assert CVE in LEDGER.read_text(encoding="utf-8")


def test_row_says_the_mcp_server_is_real() -> None:
    """The trap this row exists to document.

    A future reader who assumes "MCP" was branding would re-triage it wrongly in
    the other direction, and might dismiss a genuine MCP CVE in this plugin later.
    """
    row = _row()
    assert "Out of scope" in row
    assert "includes/Mcp" in row or "Mcp_Server" in row


def test_row_names_the_surface_the_bug_is_actually_in() -> None:
    row = _row()
    assert "Ajax.php" in row
    assert "wp_ajax" in row or "admin-ajax" in row


def test_row_records_the_fix_version_as_verified_not_quoted() -> None:
    """3.1.1, established by diffing the zips.

    The advisory says "up to and including 3.1.0", which implies the fix without
    naming it; the row should say which release actually carries the guard.
    """
    row = _row()
    assert "3.1.1" in row
    assert "current_user_can_manage_fbs_link" in row


def test_row_does_not_reduce_the_fix_to_a_capability_check() -> None:
    """Upstream deliberately did NOT gate on `manage_options`.

    Board membership in FluentBoards is orthogonal to the WordPress role, so that
    gate would lock out the low-role board members the feature exists for. A row
    that said "add current_user_can" would be recommending the wrong fix.
    """
    row = _row()
    assert "PermissionManager" in row or "board" in row.lower()
