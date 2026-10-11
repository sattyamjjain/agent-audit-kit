"""Every rule has a help page, and the SARIF "more info" link lands on it.

``helpUri`` is the one URL this project hands to other people's tooling. For a
long time only 13 of the rules had a page behind it, and a frozen set
(``_rule_doc_pages.py``) recorded which; the rest were sent to the rules index.
The docs build now generates a page per rule from the registry
(``scripts/rule_pages.py``, added to the MkDocs build by
``scripts/mkdocs_hooks.py``), so the questions worth testing changed. They are
no longer "does the frozen set match the docs tree" but:

* is there a page for every registered rule, whatever lands in the registry;
* does it sit exactly where ``helpUri`` points, on the published site layout
  (``site_url``, the ``/docs/`` prefix, directory URLs, the trailing slash);
* is it correct (the scanner is read from the code, the text survives rendering,
  a hand-written deep dive is never altered);
* is anything generated committed (it must not be, or it would drift).

Everything here is offline. The tests that need MkDocs skip without it, as
``tests/test_docs_research_publishing.py`` does; CI installs it through the
``dev`` extra, so they run there.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import logging
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest
import yaml

from agent_audit_kit.models import Category, Severity
from agent_audit_kit.output.sarif import _HELP_URI_BASE, _help_uri
from agent_audit_kit.rules.builtin import RULES, RuleDefinition

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = REPO_ROOT / "docs"
SCRIPTS = REPO_ROOT / "scripts"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve their own module while being defined
    spec.loader.exec_module(module)
    return module


rp = _load("rule_pages", "rule_pages.py")


def _site_url() -> str:
    text = (REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8")
    match = re.search(r"^site_url:\s*(\S+)\s*$", text, re.M)
    assert match, "mkdocs.yml has no site_url"
    return match.group(1).rstrip("/") + "/"


def _rule(**overrides) -> RuleDefinition:
    fields = dict(
        rule_id="AAK-TEST-001",
        title="A test rule",
        description="It finds a thing.",
        severity=Severity.HIGH,
        category=Category.MCP_CONFIG,
        remediation="Fix the thing.",
    )
    fields.update(overrides)
    return RuleDefinition(**fields)


_TITLES = {
    "owasp_mcp_references": {"MCP01:2025": "Token Mismanagement"},
    "owasp_agentic_references": {"ASI03": "Identity and Privilege Abuse"},
    "owasp_ast_references": {"AST02": "Supply Chain Compromise"},
    "adversa_references": {"ADV-AUTH-01": "Missing Authentication"},
}


@pytest.fixture(scope="module")
def pages() -> dict[str, str]:
    return rp.build_pages(DOCS)


# --------------------------------------------------------------------------
# One page per rule
# --------------------------------------------------------------------------


def test_every_registered_rule_gets_a_page_and_the_index_lists_it(pages: dict[str, str]) -> None:
    expected = {rp.page_uri(rule_id) for rule_id in RULES} | {rp.INDEX_URI}
    assert set(pages) == expected
    index = pages[rp.INDEX_URI]
    unlisted = [rule_id for rule_id in RULES if f"[{rule_id}]({rule_id}.md)" not in index]
    assert not unlisted, f"rules missing from the generated index: {unlisted}"


def test_each_page_carries_its_own_rules_text(pages: dict[str, str]) -> None:
    """Description and remediation land on the right page, untruncated."""
    wrong = []
    for rule_id, rule in RULES.items():
        text = pages[rp.page_uri(rule_id)]
        for needed in (
            rule_id,
            rule.severity.value.upper(),
            rp.markdown_text(rule.description),
            rp.markdown_text(rule.remediation),
        ):
            if needed not in text:
                wrong.append((rule_id, needed[:60]))
    assert not wrong, f"pages missing their own rule's text: {wrong[:5]}"


def test_a_known_page_reads_as_expected(pages: dict[str, str]) -> None:
    """One page pinned in full outline, so a renderer regression cannot hide behind
    the loop above agreeing with itself."""
    text = pages["rules/AAK-MCP-003.md"]
    assert text.startswith('---\ntitle: "AAK-MCP-003: ')
    assert "\n# AAK-MCP-003\n" in text
    assert "| Severity | HIGH |" in text
    assert "| Category | MCP Configuration (`mcp-config`) |" in text
    assert (
        "[`agent_audit_kit/scanners/mcp_config.py`]"
        "(https://github.com/sattyamjjain/agent-audit-kit/blob/main/agent_audit_kit/scanners/mcp_config.py)"
    ) in text
    for heading in ("## What it detects", "## How to fix", "## Limitations", "## References", "## Deep dive"):
        assert heading in text
    assert "agent-audit-kit scan . --rules AAK-MCP-003" in text


def test_pages_are_deterministic(pages: dict[str, str]) -> None:
    """No clock, no dict-order accident: a docs build is byte-stable."""
    assert rp.build_pages(DOCS) == pages


def test_rule_ids_are_safe_file_and_url_segments() -> None:
    """A rule id becomes a file name, a directory and a URL segment. MkDocs on a
    case-insensitive filesystem would also collapse two ids differing only in case."""
    bad = [rule_id for rule_id in RULES if not re.fullmatch(r"[A-Za-z0-9-]+", rule_id)]
    assert not bad, f"ids that are not URL- and file-safe: {bad}"
    folded = [rule_id.casefold() for rule_id in RULES]
    assert len(folded) == len(set(folded)), "two rule ids differ only in case"


# --------------------------------------------------------------------------
# Hand-written pages stay authoritative
# --------------------------------------------------------------------------


def _own_page_ids() -> list[str]:
    return sorted(p.stem for p in (DOCS / "rules").glob("AAK-*.md"))


def test_hand_written_pages_are_published_verbatim_with_the_registry_appended(
    pages: dict[str, str],
) -> None:
    own = _own_page_ids()
    assert own, "no hand-written rule pages found; the glob stopped matching"
    for rule_id in own:
        written = (DOCS / "rules" / f"{rule_id}.md").read_text(encoding="utf-8")
        published = pages[rp.page_uri(rule_id)]
        assert published.startswith(written.rstrip("\n") + "\n\n---\n\n## Registry reference"), (
            f"{rule_id}: the hand-written text was altered or no longer comes first"
        )
        assert published.count("## Registry reference") == 1
        assert f"| Severity | {RULES[rule_id].severity.value.upper()} |" in published
        assert "### What it detects" in published  # one level down, so the outline stays a tree


def test_building_never_writes_into_the_docs_tree() -> None:
    def snapshot() -> dict[str, bytes]:
        return {str(p): p.read_bytes() for p in (DOCS / "rules").rglob("*") if p.is_file()}

    before = snapshot()
    rp.build_pages(DOCS)
    assert snapshot() == before


def test_no_generated_page_is_committed() -> None:
    """Generated text on disk would be embedded a second time and then drift.

    Both markers are in every generated page and in nothing a person would write.
    """
    offenders = []
    for path in (DOCS / "rules").glob("*.md"):
        text = path.read_text(encoding="utf-8")
        if "This page is generated from the rule registry" in text or "\n## Registry reference\n" in text:
            offenders.append(path.name)
    assert not offenders, (
        f"{offenders} contain generated output. Pages under docs/rules/ are the "
        f"hand-written deep dives; the registry reference is appended at build time."
    )


def test_every_rule_page_on_disk_names_a_real_rule() -> None:
    """A misspelt filename publishes a page for a rule that does not exist and
    leaves the real one with only the generated page.

    Rules are never deleted in this project (docs/rule-schema.md: retire via a shim and
    keep the old id firing), so a miss here is a typo and not a departed rule.
    """
    unknown = [stem for stem in _own_page_ids() if stem not in RULES]
    assert not unknown, f"docs/rules/ pages naming no registered rule: {unknown}"


def test_hand_written_scanner_claims_agree_with_the_derived_scanner() -> None:
    """The mechanical attribution is checked against thirteen independent human claims.

    Each hand-written page states `Scanner | agent_audit_kit/scanners/x.py`. The
    derivation reads the code and never sees those pages, so agreement is evidence
    it is right, and a disagreement means either the derivation or the page is stale.
    """
    mentions = rp.named_in_code(REPO_ROOT / "agent_audit_kit", RULES)
    checked = 0
    for rule_id in _own_page_ids():
        text = (DOCS / "rules" / f"{rule_id}.md").read_text(encoding="utf-8")
        match = re.search(r"\|\s*Scanner\s*\|\s*`(agent_audit_kit/scanners/[a-z0-9_]+\.py)`", text)
        if not match:
            continue
        checked += 1
        assert match.group(1) in mentions.get(rule_id, ()), (
            f"{rule_id}: hand-written page says {match.group(1)}, "
            f"the code names it in {mentions.get(rule_id)}"
        )
    assert checked >= 10, f"only {checked} hand-written scanner claims could be compared"


# --------------------------------------------------------------------------
# Which scanner: read from the code
# --------------------------------------------------------------------------


def _package(tmp_path: Path) -> Path:
    pkg = tmp_path / "pkg"
    (pkg / "scanners").mkdir(parents=True)
    (pkg / "rules").mkdir()
    (pkg / "rules" / "builtin.py").write_text('_r("AAK-A-001")\n_r("AAK-B-001")\n_r("AAK-C-001")\n')
    (pkg / "scanners" / "alpha.py").write_text(
        '"""Fires AAK-DOC-001 and AAK-B-001."""\n'
        "# AAK-COMMENT-001 is only a comment.\n"
        "def scan():\n"
        '    """Docstring: AAK-FUNCDOC-001."""\n'
        '    return make_finding("AAK-A-001", "f", "e")\n'
    )
    (pkg / "scanners" / "beta.py").write_text(
        'RULE = "AAK-A-001"\n'
        'ATTR = "AAK-ATTR-001"\n'
        '"""AAK-ATTR-001 in an attribute docstring."""\n'
    )
    (pkg / "engine.py").write_text('rule = get_rule("AAK-C-001")\n')
    return pkg


def test_the_scanner_is_read_from_code_not_from_prose(tmp_path: Path) -> None:
    pkg = _package(tmp_path)
    ids = ["AAK-A-001", "AAK-B-001", "AAK-C-001", "AAK-DOC-001", "AAK-COMMENT-001", "AAK-FUNCDOC-001", "AAK-ATTR-001"]
    found = rp.named_in_code(pkg, ids)
    assert found["AAK-A-001"] == ("pkg/scanners/alpha.py", "pkg/scanners/beta.py")
    # Named only in a module docstring, a comment, a function docstring, an attribute
    # docstring or the registry: none of those is evidence of a detector.
    for prose_only in ("AAK-B-001", "AAK-DOC-001", "AAK-COMMENT-001", "AAK-FUNCDOC-001"):
        assert prose_only not in found
    assert found["AAK-ATTR-001"] == ("pkg/scanners/beta.py",)  # the assignment, not its docstring
    assert found["AAK-C-001"] == ("pkg/engine.py",)


def test_a_scanner_module_is_told_apart_from_other_modules() -> None:
    scanners, elsewhere = rp.split_scanners(
        ["pkg/engine.py", "pkg/scanners/a.py", "pkg/output/compliance.py", "pkg/scanners/b.py"], "pkg"
    )
    assert scanners == ("pkg/scanners/a.py", "pkg/scanners/b.py")
    assert elsewhere == ("pkg/engine.py", "pkg/output/compliance.py")


def test_the_scanner_row_says_what_was_found() -> None:
    none = rp.render_scanner_row(rp.Sources())
    assert none.startswith("None found.") and "no detector in this release is known to emit it" in none
    other = rp.render_scanner_row(rp.Sources(elsewhere=("agent_audit_kit/engine.py",)))
    assert other.startswith("No scanner module.") and "agent_audit_kit/engine.py" in other
    two = rp.render_scanner_row(
        rp.Sources(scanners=("agent_audit_kit/scanners/a.py", "agent_audit_kit/scanners/b.py"))
    )
    assert two.count("](https://github.com/sattyamjjain/agent-audit-kit/blob/main/agent_audit_kit/scanners/") == 2


def test_real_attribution_spot_checks() -> None:
    mentions = rp.named_in_code(REPO_ROOT / "agent_audit_kit", RULES)
    assert "agent_audit_kit/scanners/mcp_config.py" in mentions["AAK-MCP-001"]
    # One rule, three languages, three scanners.
    taint = {m for m in mentions["AAK-TAINT-001"] if "/scanners/" in m}
    assert {
        "agent_audit_kit/scanners/taint_analysis.py",
        "agent_audit_kit/scanners/typescript_pattern_scan.py",
        "agent_audit_kit/scanners/rust_pattern_scan.py",
    } <= taint
    # Raised by the engine, not by any scanner.
    scanners, elsewhere = rp.split_scanners(mentions["AAK-INTERNAL-SCANNER-FAIL"], "agent_audit_kit")
    assert not scanners and "agent_audit_kit/engine.py" in elsewhere
    for modules in mentions.values():
        for module in modules:
            assert (REPO_ROOT / module).is_file(), f"{module} named but not on disk"


def test_the_registry_is_never_evidence_of_a_scanner() -> None:
    assert not any(
        module.startswith("agent_audit_kit/rules/")
        for modules in rp.named_in_code(REPO_ROOT / "agent_audit_kit", RULES).values()
        for module in modules
    )


# --------------------------------------------------------------------------
# The card
# --------------------------------------------------------------------------


def test_a_fully_populated_rule_shows_every_field() -> None:
    rule = _rule(
        sarif_name="TestRule",
        cve_references=["CVE-2026-12345"],
        owasp_mcp_references=["MCP01:2025"],
        owasp_agentic_references=["ASI03"],
        owasp_ast_references=["AST02"],
        adversa_references=["ADV-AUTH-01"],
        incident_references=["GHSA-abcd-efgh-ijkl", "ARXIV-2604.20994", "OX-MCP-2026-04-15"],
        aicm_references=["IAM-01"],
        auto_fixable=True,
        limitations="Reads one file at a time.",
    )
    text = rp.render_page(
        rule,
        rp.Sources(scanners=("agent_audit_kit/scanners/x.py",)),
        category_display={"MCP_CONFIG": "MCP Configuration"},
        names=_TITLES,
    )
    for needed in (
        "# AAK-TEST-001",
        "**A test rule**",
        "| Severity | HIGH |",
        "| Category | MCP Configuration (`mcp-config`) |",
        "blob/main/agent_audit_kit/scanners/x.py",
        "| Auto-fixable | Yes. `agent-audit-kit fix` can apply it. |",
        "| SARIF name | `TestRule` |",
        "It finds a thing.",
        "Fix the thing.",
        "`--dry-run`",
        "Reads one file at a time.",
        "[CVE-2026-12345](https://nvd.nist.gov/vuln/detail/CVE-2026-12345)",
        "MCP01:2025 (Token Mismanagement)",
        "ASI03 (Identity and Privilege Abuse)",
        "AST02 (Supply Chain Compromise)",
        "ADV-AUTH-01 (Missing Authentication)",
        "[GHSA-abcd-efgh-ijkl](https://github.com/advisories/GHSA-abcd-efgh-ijkl)",
        "[ARXIV-2604.20994](https://arxiv.org/abs/2604.20994)",
        "IAM-01",
        "agent-audit-kit scan . --rules AAK-TEST-001",
    ):
        assert needed in text, needed
    assert "[OX-MCP-2026-04-15](" not in text  # no canonical page, so shown as text
    assert "OX-MCP-2026-04-15" in text


def test_a_rule_without_limitations_says_none_stated() -> None:
    text = rp.render_page(_rule(), rp.Sources(), names=_TITLES, category_display={})
    assert "## Limitations\n\nNone stated." in text
    stated = rp.render_page(_rule(limitations="Misses a thing."), rp.Sources(), names=_TITLES, category_display={})
    assert "## Limitations\n\nMisses a thing." in stated
    assert "None stated" not in stated


def test_a_rule_with_no_references_says_so() -> None:
    text = rp.render_page(_rule(), rp.Sources(), names=_TITLES, category_display={})
    assert "No external references are recorded for this rule." in text


def test_a_fixable_rule_in_the_registry_says_so(pages: dict[str, str]) -> None:
    fixable = [r for r in RULES.values() if r.auto_fixable]
    assert fixable, "no auto-fixable rules; the assertion below would be vacuous"
    for rule in fixable:
        assert "| Auto-fixable | Yes." in pages[rp.page_uri(rule.rule_id)]
    other = next(r for r in RULES.values() if not r.auto_fixable)
    assert "| Auto-fixable | No. |" in pages[rp.page_uri(other.rule_id)]


@pytest.mark.parametrize(
    ("value", "url"),
    [
        ("CVE-2026-32211", "https://nvd.nist.gov/vuln/detail/CVE-2026-32211"),
        ("GHSA-fv5p-p927-qmxr", "https://github.com/advisories/GHSA-fv5p-p927-qmxr"),
        ("ARXIV-2604.20994", "https://arxiv.org/abs/2604.20994"),
        ("arXiv:2605.24248", "https://arxiv.org/abs/2605.24248"),
        ("CERT-CC-VU-221883", "https://www.kb.cert.org/vuls/id/221883"),
        ("VULDB-360544", "https://vuldb.com/?id.360544"),
        (
            "platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/reference",
            "https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/reference",
        ),
        ("OX-MCP-2026-04-15", None),
        ("Anthropic MCP Tunnels 2026-05-19", None),
        ("MCPWN-2026-04-16", None),
    ],
)
def test_only_references_with_a_canonical_page_are_linked(value: str, url: str | None) -> None:
    assert rp.reference_url(value) == url


def test_every_reference_in_the_registry_renders(pages: dict[str, str]) -> None:
    """No reference value is dropped between the registry and its page."""
    missing = []
    for rule_id, rule in RULES.items():
        text = pages[rp.page_uri(rule_id)]
        for field_name in rp.reference_fields(RuleDefinition):
            for value in getattr(rule, field_name):
                if rp.escape_markdown(value) not in text:
                    missing.append((rule_id, field_name, value))
    assert not missing, f"references missing from their page: {missing[:5]}"


def test_a_category_the_display_table_does_not_know_is_still_labelled() -> None:
    """A new Category lands in the registry before anyone edits a display table.

    `scripts/sync_rule_count.py` fails loudly on it, but the docs build must not: the
    page and the index fall back to the category's own value.
    """
    from types import SimpleNamespace

    category = SimpleNamespace(name="NEW_AREA", value="new-area")
    rule = _rule(category=category)
    assert rp.category_label(category, {}) == "New Area (`new-area`)"
    listing = rp.render_index_listing({rule.rule_id: rule}, {})
    assert "### New Area" in listing and "[AAK-TEST-001](AAK-TEST-001.md)" in listing


def test_a_title_full_of_markdown_cannot_break_the_page_or_the_index_table() -> None:
    """Titles reach a table cell, a bold line and YAML. None of them may be torn open."""
    markdown = pytest.importorskip("markdown")
    meta = pytest.importorskip("mkdocs.utils.meta")
    title = 'Reads `a|b` and <script>x</script> "quoted": C:\\temp | & more'
    rule = _rule(title=title, description="d", remediation="r")
    text = rp.render_page(rule, rp.Sources(), names={}, category_display={})
    body, front = meta.get_data(text)
    assert front["title"] == f"AAK-TEST-001: {rp.plain_text(title)}"
    assert "<script>" not in markdown.Markdown(extensions=["tables"]).convert(body)

    listing = rp.render_index_listing({rule.rule_id: rule}, {})
    html = markdown.Markdown(extensions=["tables"]).convert(listing)
    row = next(line for line in listing.splitlines() if line.startswith("| [AAK-TEST-001]"))
    assert "<script>" not in html and row.count(" | ") == 2, row


def test_an_unknown_references_field_is_rendered_not_dropped() -> None:
    """A framework added to the registry later reaches every page without an edit here."""

    @dataclasses.dataclass
    class Extended(RuleDefinition):
        nist_ai_rmf_references: list[str] = dataclasses.field(default_factory=list)

    rule = Extended(
        rule_id="AAK-TEST-002",
        title="t",
        description="d",
        severity=Severity.LOW,
        category=Category.MCP_CONFIG,
        remediation="r",
        nist_ai_rmf_references=["GOVERN-1.1"],
    )
    assert rp.reference_fields(Extended)[-1] == "nist_ai_rmf_references"
    text = rp.render_page(rule, rp.Sources(), names={}, category_display={})
    assert "**Nist Ai Rmf:** GOVERN-1.1" in text


def test_every_rule_definition_field_is_rendered_or_acknowledged() -> None:
    """A new RuleDefinition field must reach the pages, or be a deliberate omission.

    `*_references` fields are rendered whatever they are called. Anything else is
    named here, which is the prompt to decide whether readers should see it.
    """
    handled = {
        "rule_id", "title", "description", "severity", "category", "remediation",
        "sarif_name", "auto_fixable", "limitations",
    }
    unhandled = sorted(
        f.name
        for f in dataclasses.fields(RuleDefinition)
        if f.name not in handled and not f.name.endswith("_references")
    )
    assert not unhandled, (
        f"RuleDefinition grew {unhandled}, which scripts/rule_pages.py does not render. "
        f"Render it in render_card, or add it to `handled` here with a reason."
    )
    tokens = {name: f"TOKEN-{name}" for name in rp.reference_fields(RuleDefinition)}
    rule = _rule(**{name: [token] for name, token in tokens.items()}, limitations="TOKEN-limitations", sarif_name="TokenSarif")
    text = rp.render_page(rule, rp.Sources(), names={}, category_display={})
    for token in [*tokens.values(), "TOKEN-limitations", "TokenSarif"]:
        assert token in text, token


# --------------------------------------------------------------------------
# Shared deep dives
# --------------------------------------------------------------------------


def test_a_shared_page_is_found_by_its_headings(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "shared.md").write_text(
        "# Shared page title\n\n"
        "## The check: `AAK-X-001`\n\n"
        "### `AAK-X-002` — second rule (HIGH)\n\n"
        "### Notes on AAK-X-001 and AAK-X-002\n\n"
        "```\n# AAK-X-003 inside a code block is not a heading\n```\n"
    )
    (rules / "AAK-Y-001.md").write_text("# AAK-Y-001\n\n## Sister rule AAK-Z-001\n")
    (rules / "index.md").write_text("# Index\n\n## AAK-X-001\n")
    found = rp.shared_deep_dives(rules, {"AAK-X-001", "AAK-X-002", "AAK-X-003", "AAK-Y-001", "AAK-Z-001"})
    assert found["AAK-X-001"] == ("shared", "Shared page title", "the-check-aak-x-001")
    # A heading that starts with the id beats an earlier one that only mentions it.
    assert found["AAK-X-002"] == ("shared", "Shared page title", "aak-x-002-second-rule-high")
    assert "AAK-X-003" not in found  # only inside a code fence
    # A page named for one rule cannot adopt another rule by mentioning it, and the index
    # is not a deep dive.
    assert "AAK-Z-001" not in found and "AAK-Y-001" not in found


def test_the_real_shared_deep_dive_is_linked_from_the_composition_rules(pages: dict[str, str]) -> None:
    index = (DOCS / "rules" / "index.md").read_text(encoding="utf-8")
    for rule_id in ("AAK-COMPOSE-001", "AAK-COMPOSE-002", "AAK-COMPOSE-003"):
        text = pages[rp.page_uri(rule_id)]
        link = re.search(r"\]\(skill-composition\.md#([a-z0-9-]+)\)", text)
        assert link, f"{rule_id} does not link its shared deep dive"
        # The hand-written index already links the same sections; the two must agree.
        assert f"skill-composition.md#{link.group(1)})" in index
    assert "skill-composition.md#" in pages[rp.page_uri("AAK-AGENT-COMPOSE-001")]


# --------------------------------------------------------------------------
# Text -> Markdown
# --------------------------------------------------------------------------


def test_code_spans_are_found_by_scanning() -> None:
    assert rp.split_code_spans("a `b` c") == [(False, "a "), (True, "`b`"), (False, " c")]
    assert rp.split_code_spans("``a`b`` and `c`") == [(True, "``a`b``"), (False, " and "), (True, "`c`")]
    assert rp.split_code_spans("no closer `here") == [(False, "no closer `here")]
    assert rp.split_code_spans("") == []


def test_angle_brackets_are_escaped_outside_code_and_left_inside_it() -> None:
    assert rp.escape_markdown("A UPI VPA (<handle>@<psp>) & more") == "A UPI VPA (&lt;handle&gt;@&lt;psp&gt;) &amp; more"
    assert rp.escape_markdown("run `curl <url> | bash` first") == "run `curl <url> | bash` first"


def test_a_glob_is_not_taken_for_emphasis() -> None:
    assert rp.escape_markdown("(*.pem, *.key, id_rsa)") == "(\\*.pem, \\*.key, id_rsa)"
    assert rp.escape_markdown("ghp_*, glpat-*") == "ghp_\\*, glpat-\\*"
    assert rp.escape_markdown("the X-*-Key / *-API-Key family") == "the X-\\*-Key / \\*-API-Key family"
    assert rp.escape_markdown("wildcards (*, **)") == "wildcards (\\*, \\*\\*)"
    assert rp.escape_markdown("a `*.json` glob and *.yml") == "a `*.json` glob and \\*.yml"


def test_real_emphasis_survives() -> None:
    assert rp.escape_markdown("to *do* something") == "to *do* something"
    assert rp.escape_markdown("**No allowlist applies here, deliberately.** Next") == (
        "**No allowlist applies here, deliberately.** Next"
    )
    assert rp.escape_markdown("**Note on `a` / `b`:** body") == "**Note on `a` / `b`:** body"
    assert rp.escape_markdown("*see `x` here*") == "*see `x` here*"
    assert rp.escape_markdown("\\*already escaped\\*") == "\\*already escaped\\*"


def test_a_leading_star_bullet_is_a_list_marker_not_a_stray() -> None:
    assert rp.escape_markdown("* one\n* two") == "* one\n* two"


def test_dunder_names_are_not_read_as_bold() -> None:
    assert rp.escape_dunders("tokens (__route__=, __init__.py)") == "tokens (\\_\\_route\\_\\_=, \\_\\_init\\_\\_.py)"
    for untouched in ("snake_case_name", "a__b", "__private", "trailing__", "___x___"):
        assert rp.escape_dunders(untouched) == untouched


def test_a_list_after_a_sentence_gets_its_blank_lines() -> None:
    text = "four CVEs:\n  - one: `a`\n  - two\nThe floor is set."
    assert rp.separate_lists(text) == "four CVEs:\n\n  - one: `a`\n  - two\n\nThe floor is set."
    assert rp.separate_lists("no list\nhere") == "no list\nhere"
    assert rp.separate_lists("a\n\n- already\n\nb") == "a\n\n- already\n\nb"


class _Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list) -> None:
        self.tags.add(tag)


_PAGE_TAGS = {
    "h1", "h2", "p", "table", "thead", "tbody", "tr", "th", "td", "a", "code", "pre",
    "strong", "em", "ul", "ol", "li", "hr",
}


def test_rendering_keeps_the_words_and_invents_no_tags(pages: dict[str, str]) -> None:
    """Render every generated page and fail on any tag the page structure does not own.

    `<handle>` in a rule description used to render as an unknown HTML element and
    the words disappeared; any such tag now shows up here as an unexpected one.
    """
    markdown = pytest.importorskip("markdown")
    meta = pytest.importorskip("mkdocs.utils.meta")
    own = set(_own_page_ids())
    stray: dict[str, list[str]] = {}
    bad_front_matter: list[str] = []
    for rule_id in RULES:
        if rule_id in own:
            continue
        body, front = meta.get_data(pages[rp.page_uri(rule_id)])
        # The title and description are YAML written by hand-rolled quoting; a title with a
        # quote, a colon or a backslash must still parse to exactly the plain-text title.
        title = rp.plain_text(RULES[rule_id].title)
        if front.get("title") != f"{rule_id}: {title}" or front.get("description") != title:
            bad_front_matter.append(rule_id)
        html = markdown.Markdown(extensions=["tables", "fenced_code", "toc"]).convert(body)
        parser = _Tags()
        parser.feed(html)
        extra = parser.tags - _PAGE_TAGS
        if extra:
            stray[rule_id] = sorted(extra)
    assert not stray, f"rule text produced HTML elements: {stray}"
    assert not bad_front_matter, f"front matter did not parse back to the title: {bad_front_matter[:5]}"
    body, _front = meta.get_data(pages["rules/AAK-INDIA-PII-003.md"])
    html = markdown.Markdown(extensions=["tables", "fenced_code"]).convert(body)
    assert "(&lt;handle&gt;@&lt;psp&gt;)" in html
    body, _front = meta.get_data(pages["rules/AAK-SECRET-005.md"])
    html = markdown.Markdown(extensions=["tables", "fenced_code"]).convert(body)
    assert "(*.pem, *.key, id_rsa, etc.)" in html and "<em>" not in html


def test_the_slug_matches_the_anchors_the_renderer_generates() -> None:
    """Deep links into the shared page only work if our anchor is the real one."""
    markdown = pytest.importorskip("markdown")
    source = (DOCS / "rules" / "skill-composition.md").read_text(encoding="utf-8")
    html = markdown.Markdown(extensions=["toc", "fenced_code", "tables"]).convert(source)
    ids = set(re.findall(r'<h[1-6] id="([^"]+)"', html))
    for level, heading in rp._headings(source):
        assert rp.slugify(heading) in ids or level > 4, f"no anchor for heading {heading!r}"
    shared = rp.shared_deep_dives(DOCS / "rules", RULES)
    assert shared, "no shared deep dive found; the vacuous case would pass"
    for rule_id, (_stem, _title, anchor) in shared.items():
        assert anchor in ids, f"{rule_id} links #{anchor}, which the page does not have"


# --------------------------------------------------------------------------
# The published layout
# --------------------------------------------------------------------------


def test_help_uri_is_the_page_url_of_every_rule() -> None:
    """`helpUri` = site_url + rules/<id>/, with MkDocs directory URLs and a slash."""
    text = (REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8")
    assert not re.search(r"^use_directory_urls:\s*false", text, re.M | re.I), (
        "use_directory_urls is off, so pages publish as <id>.html and every helpUri moves"
    )
    site = _site_url()
    assert _HELP_URI_BASE == site + rp.RULES_DIR, "sarif._HELP_URI_BASE and mkdocs.yml site_url disagree"
    wrong = [rule_id for rule_id in RULES if _help_uri(rule_id) != f"{site}rules/{rule_id}/"]
    assert not wrong, f"helpUri is not <site_url>rules/<id>/ for: {wrong[:5]}"
    nav = _load("nav_liveness", "nav_liveness.py")
    assert nav.source_to_url(rp.page_uri("AAK-MCP-003"), site) == _help_uri("AAK-MCP-003")


def _mkdocs_config(site_dir: Path):
    pytest.importorskip("mkdocs.config")
    from mkdocs.config import load_config

    return load_config(
        config_file=str(REPO_ROOT / "mkdocs.yml"),
        site_dir=str(site_dir),
        # The deployed site uses Material; the layout does not depend on a theme, and CI
        # installs MkDocs alone (the `dev` extra), so build with the built-in one.
        theme="mkdocs",
        markdown_extensions=["tables", "admonition"],
        validation={"anchors": "warn"},
    )


def test_the_hook_adds_every_page_outside_the_nav_and_keeps_the_index_in_it(tmp_path: Path) -> None:
    pytest.importorskip("mkdocs.structure.files")
    from mkdocs.structure.files import InclusionLevel, get_files

    config = _mkdocs_config(tmp_path / "site")
    files = get_files(config)
    index_before = files.get_file_from_path(rp.INDEX_URI)
    assert index_before is not None
    # Through the plugin collection, as `mkdocs build` does: the hook is the module
    # MkDocs loaded from `hooks:` in mkdocs.yml, and `File.generated` needs the event
    # context (`plugins._current_plugin`) that only `run_event` sets.
    files = config.plugins.on_files(files, config=config)

    for rule_id in RULES:
        page = files.get_file_from_path(rp.page_uri(rule_id))
        assert page is not None, rule_id
        assert page.dest_uri == f"rules/{rule_id}/index.html"
        assert page.url == f"rules/{rule_id}/"
        assert page.inclusion == InclusionLevel.NOT_IN_NAV
    index = files.get_file_from_path(rp.INDEX_URI)
    assert index is not None and index.inclusion == index_before.inclusion
    assert "[AAK-MCP-003](AAK-MCP-003.md)" in index.content_string
    toxic = files.get_file_from_path("rules/AAK-TOXICFLOW-001.md")
    written = (DOCS / "rules" / "AAK-TOXICFLOW-001.md").read_text(encoding="utf-8")
    assert toxic is not None and toxic.content_string.startswith(written.rstrip("\n"))
    assert len({f.src_uri for f in files}) == len(list(files)), "duplicate src_uri after the hook"


def test_building_the_site_puts_every_help_page_where_its_helpuri_points(tmp_path: Path) -> None:
    """The check the whole design rests on: build the docs, then follow every helpUri."""
    pytest.importorskip("mkdocs.commands.build")
    from mkdocs.commands import build

    site_dir = tmp_path / "site"
    config = _mkdocs_config(site_dir)
    records: list[logging.LogRecord] = []

    class _Grab(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Grab()
    logger = logging.getLogger("mkdocs")
    logger.addHandler(handler)
    try:
        build.build(config)
    finally:
        logger.removeHandler(handler)

    site = _site_url()
    missing = []
    for rule_id in RULES:
        uri = _help_uri(rule_id)
        assert uri.startswith(site)
        if not (site_dir / uri[len(site):] / "index.html").is_file():
            missing.append(rule_id)
    assert not missing, f"helpUri targets with no built page: {missing[:5]} ({len(missing)})"

    # A hand-written page, a generated one, a shared-deep-dive one and the index.
    toxic = (site_dir / "rules" / "AAK-TOXICFLOW-001" / "index.html").read_text(encoding="utf-8")
    assert "Feature-flag status" in toxic and "Registry reference" in toxic
    generated = (site_dir / "rules" / "AAK-MCP-003" / "index.html").read_text(encoding="utf-8")
    assert "<title>AAK-MCP-003: " in generated and "What it detects" in generated
    compose = (site_dir / "rules" / "AAK-COMPOSE-001" / "index.html").read_text(encoding="utf-8")
    assert 'href="../skill-composition/#aak-compose-001' in compose
    index = (site_dir / "rules" / "index.html").read_text(encoding="utf-8")
    assert all(f'href="{rule_id}/"' in index for rule_id in RULES)

    # No generated page may add a MkDocs warning: a dead link or anchor in a page nobody
    # reads by hand is exactly what goes unnoticed. (Hand-written pages carry old ones.)
    own = set(_own_page_ids())
    names = {rp.page_uri(rule_id) for rule_id in RULES if rule_id not in own} | {rp.INDEX_URI}
    noisy = [
        record.getMessage()
        for record in records
        if record.levelno >= logging.WARNING
        and any(f"'{name}'" in record.getMessage() for name in names)
    ]
    assert not noisy, f"warnings raised by generated pages: {noisy[:3]}"


# --------------------------------------------------------------------------
# Keeping the pages published
# --------------------------------------------------------------------------


def test_the_docs_redeploy_when_a_rule_page_input_changes() -> None:
    """A rule has no page until the docs are rebuilt, so the deploy must see its inputs.

    Without `agent_audit_kit/**` here a rule merged on a Tuesday would 404 from its own
    "more info" link until the Monday run.
    """
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "mcp-security-index.yml").read_text(encoding="utf-8")
    )
    triggers = workflow.get("on") or workflow.get(True)  # PyYAML reads the bare `on` key as True
    paths = triggers["push"]["paths"]
    for needed in ("docs/**", "mkdocs.yml", "agent_audit_kit/**", "scripts/rule_pages.py", "scripts/mkdocs_hooks.py"):
        assert needed in paths, f"mcp-security-index.yml does not redeploy on {needed}"
    # Overlapping runs race for a force-pushed branch; they must queue, not cancel a crawl.
    assert workflow["concurrency"]["cancel-in-progress"] is False


def test_the_commands_a_page_tells_the_reader_to_run_exist() -> None:
    from agent_audit_kit.cli import cli

    def options(name: str) -> set[str]:
        return {opt for param in cli.commands[name].params for opt in getattr(param, "opts", [])}

    assert "--rules" in options("scan")
    assert "--dry-run" in options("fix")
