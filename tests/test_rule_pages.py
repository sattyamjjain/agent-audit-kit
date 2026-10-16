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
from agent_audit_kit.rules.builtin import RETIRED_RULE_IDS, RULES, RuleDefinition

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
    expected = (
        {rp.page_uri(rule_id) for rule_id in RULES}
        | {rp.page_uri(rule_id) for rule_id in RETIRED_RULE_IDS}  # see the retired-rule test below
        | {rp.INDEX_URI}
    )
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
    # The title is in the h1 (WCAG 2.4.6), and there is no second line repeating it.
    assert re.search(r"\n# AAK-MCP-003: \S[^\n]*\n\nSeverity\n", text)
    assert "\n**" not in text.split("\n## ")[0]
    # The facts are a description list: a term, then its definition, a blank line between pairs.
    assert "\nSeverity\n:   HIGH\n\nCategory\n:   MCP Configuration (`mcp-config`)\n\nScanner\n:   [" in text
    assert "| Field |" not in text
    assert (
        "[`agent_audit_kit/scanners/mcp_config.py`]"
        "(https://github.com/sattyamjjain/agent-audit-kit/blob/main/agent_audit_kit/scanners/mcp_config.py)"
    ) in text
    for heading in ("## What it detects", "## How to fix", "## Limitations", "## References"):
        assert heading in text
    assert "## Deep dive" not in text  # nothing to dive into: no shared page covers this rule
    assert "[All rules](index.md#all-rules)" in text
    assert "agent-audit-kit scan . --rules AAK-MCP-003" in text


class _Text(HTMLParser):
    """The text of rendered HTML, entities decoded, read by the parser rather than a pattern."""

    def __init__(self) -> None:
        super().__init__()
        self.chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        self.chunks.append(data)


def _visible_text(html_text: str) -> str:
    """What a reader sees of rendered HTML, spaces collapsed.

    A tag adds no space of its own, so `(<code>x</code>)` reads `(x)`; blocks stay
    apart because the renderer writes a newline between them.
    """
    parser = _Text()
    parser.feed(html_text)
    return " ".join("".join(parser.chunks).split())


def test_every_retired_rule_keeps_a_page_where_its_helpuri_pointed(pages: dict[str, str]) -> None:
    """A code-scanning alert raised before a rule was retired keeps that rule's helpUri.

    So the address must keep answering: with what the rule was, that it is retired and
    after which release, why, and what covers it now, every rule it names linked by its
    id and title. The status leads the title and the h1 ("Retired rule <ID>: <title>"): a
    trailing "(retired)" was read as part of the rule's own name, since live titles end
    in parentheticals too. The index lists the retired rules under their own heading,
    and the footer leads to both lists.
    """
    assert RETIRED_RULE_IDS
    index = pages[rp.INDEX_URI]
    assert "\n## Retired rules\n" in index
    for rule_id, retired in RETIRED_RULE_IDS.items():
        text = pages[rp.page_uri(rule_id)]
        html_text, page, front = _render(text)
        heading = f"Retired rule {rule_id}: {rp.plain_text(retired.title)}"
        assert page.titles("h1") == [heading] and front["title"] == heading, rule_id
        assert page.titles("h2") == ["Why it was retired", "What covers it now"], rule_id
        assert page.terms == ["Status"], rule_id
        assert not page.tags - _PAGE_TAGS, (rule_id, sorted(page.tags - _PAGE_TAGS))
        seen = _visible_text(html_text)
        assert f"Retired in the release after {retired.last_release}." in seen, rule_id
        for words in (retired.reason, retired.replacement):
            assert words.strip(), (rule_id, "a blank field would pass the check below vacuously")
            assert rp.plain_text(rp.link_rule_ids(words, RULES)) in seen, (rule_id, words[:60])
        for named in retired.covered_by:
            assert f"[{named}: " in text and f"]({named}.md)" in text, (rule_id, named)
            assert f"{named}: {rp.plain_text(RULES[named].title)}" in seen, (rule_id, named)
        assert f"[{rule_id}]({rule_id}.md)" in index, rule_id
        assert "[All rules](index.md#all-rules)" in text
        assert "[Retired rules](index.md#retired-rules)" in text


def test_the_retired_rules_table_names_itself_and_says_last_shipped_in(pages: dict[str, str]) -> None:
    """Every table on the index starts with "Rule", so this one says which table it is,
    and "Last release, 0.6.22" sounded like the release that removed the rule."""
    index = pages[rp.INDEX_URI]
    assert "| Retired rule | Last shipped in | Title |" in index
    assert "| Rule | Last release | Title |" not in index


def test_the_rules_index_leads_to_both_lists_without_saying_where_they_sit(pages: dict[str, str]) -> None:
    """The intro said the full list "closes this page", which stopped being true when the
    retired list followed it, and a position means nothing to a screen reader or search."""
    intro = pages[rp.INDEX_URI].split("\n## ", 1)[0]
    assert "[All rules](#all-rules)" in intro and "[Retired rules](#retired-rules)" in intro
    positional = [word for word in ("above", "below", "closes this page", "at the end") if word in intro.lower()]
    assert not positional, positional


def test_a_rule_id_is_linked_only_outside_code_and_only_when_registered() -> None:
    rules = {"AAK-A-001": _rule(rule_id="AAK-A-001")}
    linked = rp.link_rule_ids("AAK-A-001 and `AAK-A-001` and AAK-B-001.", rules)
    assert linked == "[AAK-A-001: A test rule](AAK-A-001.md) and `AAK-A-001` and AAK-B-001."


def test_a_linked_rule_id_says_its_title_with_the_markup_kept_safe() -> None:
    """Four ids that differ only in the last digit are four identical links out of
    context (WCAG 2.4.9), so the link text carries the title, escaped as titles are."""
    rules = {"AAK-A-001": _rule(rule_id="AAK-A-001", title="Uses `x` < 2 [beta]")}
    assert rp.link_rule_ids("See AAK-A-001.", rules) == (
        "See [AAK-A-001: Uses `x` &lt; 2 \\[beta\\]](AAK-A-001.md)."
    )


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("See [AAK-A-001](AAK-A-001.md).", id="already a link"),
        pytest.param("See [the rule](https://example.test/rules/AAK-A-001/).", id="inside a link target"),
        pytest.param("See https://example.test/rules/AAK-A-001/ for more.", id="inside a bare URL"),
        pytest.param("See <https://example.test/AAK-A-001>.", id="inside an autolink"),
    ],
)
def test_a_rule_id_already_in_a_link_or_a_url_is_left_alone(text: str) -> None:
    """Wrapping it again built `[AAK-A-001](AAK-A-001.md).md` as a link target, and an id
    in a URL broke the URL: neither MkDocs nor lychee would have noticed."""
    rules = {"AAK-A-001": _rule(rule_id="AAK-A-001")}
    assert rp.link_rule_ids(text, rules) == text


@pytest.mark.parametrize("field", ["title", "last_release", "reason", "replacement"])
def test_a_retired_page_with_a_blank_field_is_refused(field: str) -> None:
    sample = next(iter(RETIRED_RULE_IDS.values()))
    blank = dataclasses.replace(sample, **{field: "  "})
    with pytest.raises(ValueError, match=field):
        rp.render_retired_page("AAK-X-001", blank, RULES)


def test_a_retired_page_naming_an_unregistered_rule_is_refused() -> None:
    sample = next(iter(RETIRED_RULE_IDS.values()))
    with pytest.raises(ValueError, match="AAK-NOT-A-RULE-001"):
        rp.render_retired_page("AAK-X-001", dataclasses.replace(sample, covered_by=("AAK-NOT-A-RULE-001",)), RULES)


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


def _strip_front_matter(text: str) -> str:
    """A page's body as MkDocs reads it: the YAML block removed, and the blank lines after it."""
    lines = text.split("\n")
    if lines[0].rstrip() != "---":
        return text
    for index, line in enumerate(lines[1:], start=1):
        if line.rstrip() in {"---", "..."}:
            return "\n".join(lines[index + 1 :]).lstrip("\n")
    return text


def test_hand_written_pages_are_published_verbatim_with_the_registry_appended(
    pages: dict[str, str],
) -> None:
    own = _own_page_ids()
    assert own, "no hand-written rule pages found; the glob stopped matching"
    for rule_id in own:
        written = (DOCS / "rules" / f"{rule_id}.md").read_text(encoding="utf-8")
        published = pages[rp.page_uri(rule_id)]
        # Only a `title:` block is put in front, and MkDocs removes it before rendering, so what
        # the reader gets of the page's own text is still exactly what was written.
        assert published.startswith(f'---\ntitle: "{rule_id}: '), f"{rule_id}: no title in front"
        assert _strip_front_matter(published).startswith(
            written.rstrip("\n") + "\n\n---\n\n## Registry reference"
        ), f"{rule_id}: the hand-written text was altered or no longer comes first"
        assert published.count("## Registry reference") == 1
        assert f"\nSeverity\n:   {RULES[rule_id].severity.value.upper()}\n" in published
        assert "### What it detects" in published  # one level down, so the outline stays a tree


def test_a_hand_written_page_gets_a_title_unless_it_brings_its_own() -> None:
    """MkDocs titles a page from front matter, else its first h1: which is only the rule id here."""
    rule = _rule(title="Readable title")
    plain = rp.render_page(rule, rp.Sources(), "# AAK-TEST-001\n\nWords.\n", names={}, category_display={})
    assert plain.startswith('---\ntitle: "AAK-TEST-001: Readable title"\ndescription: "Readable title"\n---\n\n# AAK-TEST-001\n')
    own = "---\ntitle: Mine\n---\n\n# AAK-TEST-001\n\nWords.\n"
    kept = rp.render_page(rule, rp.Sources(), own, names={}, category_display={})
    assert kept.startswith(own.rstrip("\n")) and kept.count("title:") == 1


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("---\ntitle: x\n---\n\nbody", True),
        ("---  \ntitle: x\n...\nbody", True),
        ("# Heading\n\n---\n\ntext", False),
        ("---\nno closing delimiter", False),
        ("", False),
    ],
)
def test_front_matter_is_recognised_the_way_mkdocs_reads_it(text: str, expected: bool) -> None:
    assert rp.has_front_matter(text) is expected
    meta = pytest.importorskip("mkdocs.utils.meta")
    assert bool(meta.get_data(text)[1]) is expected


def test_a_card_heading_a_hand_written_page_already_uses_is_qualified(pages: dict[str, str]) -> None:
    """Two headings both called "References" are indistinguishable in a screen reader's heading list."""
    own = rp.render_page(
        _rule(), rp.Sources(), "# AAK-TEST-001\n\n## References\n\n- a\n\n## `Limitations`\n", names={}, category_display={}
    )
    assert "### References (registry)" in own and "### Limitations (registry)" in own
    assert "### What it detects" in own and "### How to fix" in own  # no clash, no suffix
    published = pages[rp.page_uri("AAK-MCP-AUTH-PATHTRAVERSAL-001")]
    assert "\n## References\n" in published and "\n### References (registry)\n" in published
    assert "\n### References\n" not in published


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
        "\n# AAK-TEST-001: A test rule\n",
        "\nSeverity\n:   HIGH\n",
        "\nCategory\n:   MCP Configuration (`mcp-config`)\n",
        "blob/main/agent_audit_kit/scanners/x.py",
        "\nAuto-fixable\n:   Yes. `agent-audit-kit fix` can apply it.\n",
        "\nSARIF name\n:   `TestRule`\n",
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
        assert "\nAuto-fixable\n:   Yes." in pages[rp.page_uri(rule.rule_id)]
    other = next(r for r in RULES.values() if not r.auto_fixable)
    assert "\nAuto-fixable\n:   No.\n" in pages[rp.page_uri(other.rule_id)]


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
    assert "<script>" not in markdown.Markdown(extensions=_RENDER_EXTENSIONS).convert(body)

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


def test_a_deep_dive_section_appears_only_where_there_is_something_to_dive_into(
    pages: dict[str, str],
) -> None:
    """An empty "Deep dive" heading is one more stop for a screen reader user to hear and skip."""
    shared = rp.Sources(shared=("skill-composition", "Skill composition", "aak-compose-001"))
    with_page = rp.render_page(_rule(), shared, names={}, category_display={})
    assert "\n## Deep dive\n\nThis rule is written up in [Skill composition](skill-composition.md#aak-compose-001).\n" in with_page
    without = rp.render_page(_rule(), rp.Sources(), names={}, category_display={})
    assert "Deep dive" not in without and "no hand-written page" not in without

    with_section = {rule_id for rule_id in RULES if "\n## Deep dive\n" in pages[rp.page_uri(rule_id)]}
    assert with_section == set(rp.shared_deep_dives(DOCS / "rules", RULES)) - set(_own_page_ids())
    assert {"AAK-COMPOSE-001", "AAK-AGENT-COMPOSE-001"} <= with_section


def test_the_footer_says_how_to_add_a_hand_written_page_and_it_is_true(tmp_path: Path) -> None:
    """The old note said a hand-written file would be "shown here automatically". It
    replaces the generated layout instead, and the generated part is appended to it."""
    pkg = _package(tmp_path)
    docs = tmp_path / "docs"
    (docs / "rules").mkdir(parents=True)
    rules = {"AAK-A-001": _rule(rule_id="AAK-A-001")}

    generated = rp.build_pages(docs, rules, pkg)["rules/AAK-A-001.md"]
    footer = generated.split("\n---\n")[-1]
    assert "[All rules](index.md#all-rules)" in footer
    assert "`docs/rules/AAK-A-001.md`" in footer and "shown here automatically" not in generated

    (docs / "rules" / "AAK-A-001.md").write_text("# AAK-A-001\n\nWritten by hand.\n", encoding="utf-8")
    written = _strip_front_matter(rp.build_pages(docs, rules, pkg)["rules/AAK-A-001.md"])
    assert written.startswith("# AAK-A-001\n\nWritten by hand.\n\n---\n\n## Registry reference")
    assert "# AAK-A-001: A test rule" in generated and "# AAK-A-001: A test rule" not in written  # layout replaced
    assert "### What it detects" in written  # and the registry reference is appended, one level down


def test_both_footers_lead_to_the_list_of_all_rules(pages: dict[str, str]) -> None:
    """`index.md#all-rules` is the generated listing's heading; the link must reach it."""
    for rule_id in ("AAK-MCP-003", "AAK-TOXICFLOW-001"):  # a generated page, a hand-written one
        assert "[All rules](index.md#all-rules)" in pages[rp.page_uri(rule_id)]
    listing = rp.render_index_listing(RULES, {})
    assert "\n## All rules\n" in "\n" + listing and rp.slugify("All rules") == "all-rules"


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


#: What the rule pages are rendered with in these tests: the extensions they rely on.
#: `test_the_site_enables_the_extensions_the_pages_rely_on` holds mkdocs.yml to the same
#: list, so a page cannot pass here and print `:   HIGH` as text on the real site.
_RENDER_EXTENSIONS = ["tables", "fenced_code", "toc", "def_list"]

_FIXED_SECTIONS = ["What it detects", "How to fix", "Limitations", "References"]


class _Page(HTMLParser):
    """What a rendered page is made of: its tags, its headings in order, its fact terms."""

    def __init__(self) -> None:
        super().__init__()
        self.tags: set[str] = set()
        self.counts: dict[str, int] = {}
        self.headings: list[tuple[str, str]] = []
        self.terms: list[str] = []
        self._tag: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        self.tags.add(tag)
        self.counts[tag] = self.counts.get(tag, 0) + 1
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6", "dt"}:
            self._tag, self._text = tag, []

    def handle_data(self, data: str) -> None:
        if self._tag:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag != self._tag:
            return
        text = "".join(self._text).strip()
        if tag == "dt":
            self.terms.append(text)
        else:
            self.headings.append((tag, text))
        self._tag = None

    def titles(self, tag: str) -> list[str]:
        return [text for name, text in self.headings if name == tag]


def _render(markdown_source: str) -> tuple[str, _Page, dict]:
    """A page's Markdown through the renderer: (html, what it contains, its front matter)."""
    markdown = pytest.importorskip("markdown")
    meta = pytest.importorskip("mkdocs.utils.meta")
    body, front = meta.get_data(markdown_source)
    html = markdown.Markdown(extensions=_RENDER_EXTENSIONS).convert(body)
    page = _Page()
    page.feed(html)
    return html, page, front


_PAGE_TAGS = {
    "h1", "h2", "p", "dl", "dt", "dd", "a", "code", "pre", "strong", "em", "ul", "ol", "li", "hr",
}


def test_rendering_keeps_the_words_and_invents_no_tags(pages: dict[str, str]) -> None:
    """Render every generated page and fail on any tag the page structure does not own.

    `<handle>` in a rule description used to render as an unknown HTML element and
    the words disappeared; any such tag now shows up here as an unexpected one. A
    generated page has no table at all: its facts are a description list.
    """
    own = set(_own_page_ids())
    stray: dict[str, list[str]] = {}
    bad_front_matter: list[str] = []
    for rule_id in RULES:
        if rule_id in own:
            continue
        _html, page, front = _render(pages[rp.page_uri(rule_id)])
        # The title and description are YAML written by hand-rolled quoting; a title with a
        # quote, a colon or a backslash must still parse to exactly the plain-text title.
        title = rp.plain_text(RULES[rule_id].title)
        if front.get("title") != f"{rule_id}: {title}" or front.get("description") != title:
            bad_front_matter.append(rule_id)
        extra = page.tags - _PAGE_TAGS
        if extra:
            stray[rule_id] = sorted(extra)
    assert not stray, f"rule text produced HTML elements: {stray}"
    assert not bad_front_matter, f"front matter did not parse back to the title: {bad_front_matter[:5]}"
    html, _page, _front = _render(pages["rules/AAK-INDIA-PII-003.md"])
    assert "(&lt;handle&gt;@&lt;psp&gt;)" in html
    html, _page, _front = _render(pages["rules/AAK-SECRET-005.md"])
    assert "(*.pem, *.key, id_rsa, etc.)" in html and "<em>" not in html


def test_the_facts_are_a_description_list_with_a_term_for_every_definition(
    pages: dict[str, str],
) -> None:
    """WCAG 1.3.1: a `Field | Value` table has no row headers, so a screen reader read the
    value ("HIGH") without saying which fact it was. A `dl` names each one."""
    own = set(_own_page_ids())
    for rule_id, rule in RULES.items():
        _html, page, _front = _render(pages[rp.page_uri(rule_id)])
        expected = ["Severity", "Category", "Scanner", "Auto-fixable"] + (
            ["SARIF name"] if rule.sarif_name else []
        )
        assert page.terms == expected, rule_id
        assert page.counts.get("dd") == len(expected) and page.counts.get("dl") == 1, rule_id
        if rule_id not in own:
            assert "table" not in page.tags, f"{rule_id}: a generated page has a table"


def test_a_page_never_gets_a_second_field_value_table(pages: dict[str, str]) -> None:
    """The hand-written pages carry a `Field | Value` table of their own; the registry
    reference appended under it must not add a second one with the same header."""
    for rule_id in _own_page_ids():
        written = (DOCS / "rules" / f"{rule_id}.md").read_text(encoding="utf-8")
        assert pages[rp.page_uri(rule_id)].count("| Field | Value |") == written.count("| Field | Value |")


def test_every_page_has_one_h1_and_the_expected_h2s(pages: dict[str, str]) -> None:
    """The outline is how a screen reader user finds their way around, so it is pinned.

    A generated page is one h1 (the rule id and title, which is also its `<title>`) over
    four h2 sections, plus "Deep dive" when a shared hand-written page covers the rule.
    A hand-written page keeps whatever outline it has, and gains one h2, "Registry
    reference", with the four sections as h3 under it.
    """
    own = set(_own_page_ids())
    shared = rp.shared_deep_dives(DOCS / "rules", RULES)
    wrong: dict[str, object] = {}
    for rule_id in RULES:
        _html, page, front = _render(pages[rp.page_uri(rule_id)])
        h1 = page.titles("h1")
        if len(h1) != 1:
            wrong[rule_id] = ("h1", h1)
        elif rule_id in own:
            at = [i for i, (tag, text) in enumerate(page.headings) if (tag, text) == ("h2", "Registry reference")]
            tail = (
                [(tag, re.sub(r" \(registry\)$", "", text)) for tag, text in page.headings[at[0] + 1 :]]
                if len(at) == 1
                else None
            )
            if tail != [("h3", name) for name in _FIXED_SECTIONS]:
                wrong[rule_id] = ("registry reference", tail)
        else:
            sections = _FIXED_SECTIONS + (["Deep dive"] if rule_id in shared else [])
            if page.titles("h2") != sections or len(page.headings) != 1 + len(sections):
                wrong[rule_id] = ("h2", page.titles("h2"), len(page.headings))
            elif h1 != [front["title"]]:
                wrong[rule_id] = ("h1 is not the tab title", h1, front["title"])
    assert not wrong, f"{len(wrong)} pages with an unexpected outline, e.g. {dict(list(wrong.items())[:3])}"


def test_registry_text_cannot_add_headings_to_the_outline() -> None:
    """A line starting `#` or an underline of `---` or `===` is a heading to the renderer."""
    nasty = "\n".join(
        [
            "Intro line",
            "# Injected h1",
            "#nospace",
            "- # in a list item",
            "Setext text",
            "---",
            "More text",
            "===",
            "```bash",
            "# a comment inside a fence stays code",
            "---",
            "```",
            "tail",
        ]
    )
    rule = _rule(title="Ends with a hash #", description=nasty, remediation=nasty, limitations=nasty)
    html, page, front = _render(rp.render_page(rule, rp.Sources(), names={}, category_display={}))
    assert page.titles("h1") == ["AAK-TEST-001: Ends with a hash #"] == [front["title"]]
    assert page.titles("h2") == _FIXED_SECTIONS
    assert len(page.headings) == 1 + len(_FIXED_SECTIONS), page.headings
    # Nothing was dropped to get there: the words, the fenced code, the underlines as text.
    for kept in ("Injected h1", "nospace", "in a list item", "Setext text", "More text"):
        assert kept in html, kept
    assert html.count("# a comment inside a fence stays code") == 3  # description, remediation, limitations
    assert "\\#" not in html and "\\-" not in html
    assert html.count("<hr") == 1  # the footer's rule, and none made out of the text


def test_headings_are_neutralised_only_where_the_renderer_would_make_one() -> None:
    assert rp.neutralize_headings("a\n# b") == "a\n\\# b"
    assert rp.neutralize_headings("#b") == "\\#b"
    assert rp.neutralize_headings("- # b\n  * ## c\n1. # d") == "- \\# b\n  * \\## c\n1. \\# d"
    assert rp.neutralize_headings("a\n---") == "a\n\\---"
    assert rp.neutralize_headings("a\n===") == "a\n&#61;=="
    assert rp.neutralize_headings("a\n-") == "a\n\\-"
    assert rp.neutralize_headings("- item\n---") == "- item\n\\---"
    # Not an underline: nothing above it, or a blank line between, or part of a longer line.
    for untouched in ("---", "a\n\n---", "a\n--- b", "issue #22 and `# x` mid-line", "\\# already escaped"):
        assert rp.neutralize_headings(untouched) == untouched
    # A fenced block is code, whichever fence opens it; an unclosed fence is not a fence.
    fenced = "```bash\n# c\n---\n```"
    assert rp.neutralize_headings(fenced) == fenced
    assert rp.neutralize_headings("~~~sh\n# c\n~~~\n# d") == "~~~sh\n# c\n~~~\n\\# d"
    assert rp.neutralize_headings("```bash\n# not closed") == "```bash\n\\# not closed"
    assert rp.neutralize_headings("a ```x``` span\n# d") == "a ```x``` span\n\\# d"
    assert rp.neutralize_headings("```x``` then\n# d") == "```x``` then\n\\# d"


def test_a_title_keeps_its_trailing_hash_and_stays_on_one_line() -> None:
    assert rp.heading_text("Ends in #") == "Ends in \\#"
    assert rp.heading_text("Ends in ##") == "Ends in \\#\\#"
    assert rp.heading_text("Has # inside") == "Has # inside"
    assert rp.heading_text("A  title\nover two lines") == "A title over two lines"
    assert rp.heading_text("Uses `*.pem` and <angle>") == "Uses `*.pem` and &lt;angle&gt;"


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


def _declared_extensions() -> list[str]:
    """`markdown_extensions` as mkdocs.yml lists them, in order."""
    text = (REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8")
    assert "\nmarkdown_extensions:\n" in text, "mkdocs.yml has no markdown_extensions"
    names: list[str] = []
    for line in text.split("\nmarkdown_extensions:\n", 1)[1].splitlines():
        if line.strip() and not line.startswith((" ", "\t", "#")):
            break  # the next top-level key
        match = re.match(r"\s+-\s+(\S+)\s*$", line)
        if match:
            names.append(match.group(1))
    return names


def test_the_site_enables_the_extensions_the_pages_rely_on() -> None:
    """The facts are a `dl`, which needs `def_list`; without it they print as `:   HIGH` text."""
    declared = _declared_extensions()
    for needed in ("tables", "def_list", "admonition"):
        assert needed in declared, f"mkdocs.yml does not enable {needed}"
    # MkDocs switches the other two on by itself, which is why the site does not list them.
    assert set(_RENDER_EXTENSIONS) <= set(declared) | {"fenced_code", "toc"}


def _mkdocs_config(site_dir: Path, **overrides: object):
    pytest.importorskip("mkdocs.config")
    from mkdocs.config import load_config

    return load_config(
        config_file=str(REPO_ROOT / "mkdocs.yml"),
        site_dir=str(site_dir),
        # The deployed site uses Material; the layout does not depend on a theme, and CI
        # installs MkDocs alone (the `dev` extra), so build with the built-in one.
        theme="mkdocs",
        markdown_extensions=["tables", "admonition", "def_list"],
        validation={"anchors": "warn"},
        **overrides,
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

    for rule_id in [*RULES, *RETIRED_RULE_IDS]:
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
    assert toxic is not None
    # What MkDocs renders of a hand-written page is its own text; the title block in front
    # of it is stripped by the same function MkDocs uses, and becomes the page title.
    meta = pytest.importorskip("mkdocs.utils.meta")
    body, front = meta.get_data(toxic.content_string)
    assert body.startswith(written.rstrip("\n"))
    assert front["title"].startswith("AAK-TOXICFLOW-001: ")
    assert len({f.src_uri for f in files}) == len(list(files)), "duplicate src_uri after the hook"


def _hooked_files(tmp_path: Path):
    """The file collection as the build gets it: from the docs directory, then through the hook."""
    pytest.importorskip("mkdocs.structure.files")
    from mkdocs.structure.files import get_files

    config = _mkdocs_config(tmp_path / "site")
    return config, config.plugins.on_files(get_files(config), config=config)


def test_no_two_built_files_share_a_destination(tmp_path: Path) -> None:
    """`docs/rules.md` and `docs/rules/index.md` were both `rules/index.html`, and one
    silently won: the nav's "Rule reference" never reached the site (WCAG 2.4.4: every
    link to it landed on the per-rule index)."""
    _config, files = _hooked_files(tmp_path)
    by_destination: dict[str, list[str]] = {}
    for file in files:
        if file.inclusion.is_included():  # a file left out of the build cannot clash
            by_destination.setdefault(file.dest_uri, []).append(file.src_uri)
    clashes = {dest: sources for dest, sources in by_destination.items() if len(sources) > 1}
    assert not clashes, f"files built to the same page: {clashes}"
    # The clash that used to exist is settled by leaving the summary out, not the per-rule
    # index: SARIF results already uploaded point at `rules/`.
    summary = files.get_file_from_path("rules.md")
    assert summary is not None and summary.inclusion.is_excluded()
    index = files.get_file_from_path(rp.INDEX_URI)
    assert index is not None and index.inclusion.is_included()


def test_the_nav_offers_only_pages_that_are_built(tmp_path: Path) -> None:
    _config, files = _hooked_files(tmp_path)
    nav = _load("nav_liveness", "nav_liveness.py")
    sources = nav.nav_sources()
    assert sources and "rules.md" not in sources
    unbuilt = []
    for source in sources:
        page = files.get_file_from_path(source)
        if page is None or page.inclusion.is_excluded():
            unbuilt.append(source)
    assert not unbuilt, f"nav entries that are not part of the built site: {unbuilt}"


def test_no_page_links_to_the_summary_the_site_leaves_out() -> None:
    """With `docs/rules.md` excluded, a relative link to it is rewritten to the address it
    would have had, which is the per-rule index, and MkDocs only says so at INFO level."""
    summary = (DOCS / "rules.md").resolve()
    link = re.compile(r"\]\(((?:\./|\.\./)[^)\s#]*)")
    offenders = []
    for page in sorted(DOCS.rglob("*.md")):
        for target in link.findall(page.read_text(encoding="utf-8", errors="ignore")):
            if (page.parent / target).resolve() == summary:
                offenders.append(f"{page.relative_to(REPO_ROOT)}: {target}")
    assert not offenders, f"links to the excluded rule summary: {offenders}"


def _hooks():
    pytest.importorskip("mkdocs.structure.files")
    return _load("mkdocs_hooks_under_test", "mkdocs_hooks.py")


def test_a_file_left_out_of_the_build_cannot_clash_but_two_built_files_do() -> None:
    from mkdocs.structure.files import File, Files, InclusionLevel

    hooks = _hooks()

    def make(src: str, level) -> File:
        file = File(src, "docs", "site", True)
        file.inclusion = level
        return file

    kept = make("rules/index.md", InclusionLevel.INCLUDED)
    assert hooks.colliding_destinations(Files([kept, make("rules.md", InclusionLevel.EXCLUDED)])) == {}
    assert hooks.colliding_destinations(Files([kept, make("rules.md", InclusionLevel.DRAFT)])) == {}
    clash = hooks.colliding_destinations(Files([kept, make("rules.md", InclusionLevel.INCLUDED)]))
    assert clash == {"rules/index.html": ["rules/index.md", "rules.md"]}
    assert hooks.colliding_destinations(Files([kept, make("other.md", InclusionLevel.INCLUDED)])) == {}


def test_the_hook_refuses_a_build_in_which_two_files_share_a_page(tmp_path: Path) -> None:
    """Not just a test failure: `mkdocs build` itself stops, so the deploy cannot publish it."""
    pytest.importorskip("mkdocs.structure.files")
    from mkdocs.structure.files import File, get_files

    config = _mkdocs_config(tmp_path / "site")
    files = get_files(config)
    # `cli.md` and `cli/index.md` would both be `cli/index.html`.
    files.append(File("cli/index.md", config["docs_dir"], config["site_dir"], config["use_directory_urls"]))
    with pytest.raises(Exception, match="same page") as caught:
        config.plugins.on_files(files, config=config)
    assert "cli/index.html <- cli.md, cli/index.md" in str(caught.value)


_MD_LINK = re.compile(r"\[([^\]\[]+)\]\(([^)\s]+)\)")


def test_a_link_text_never_leads_to_two_places_on_one_page(pages: dict[str, str]) -> None:
    """WCAG 2.4.4 / 3.2.4: the same words are expected to go to the same place.

    AAK-AZURE-MCP-001 linked "CVE-2026-32211" to a blog post in its own table and to the
    NVD record in the registry reference under it, and the rules index listed the three
    composition rules twice, once to the shared write-up and once to their own pages.
    """
    clashes: dict[str, dict[str, list[str]]] = {}
    for uri, text in pages.items():
        seen: dict[str, set[str]] = {}
        for label, target in _MD_LINK.findall(text):
            seen.setdefault(label, set()).add(target[2:] if target.startswith("./") else target)
        bad = {label: sorted(targets) for label, targets in seen.items() if len(targets) > 1}
        if bad:
            clashes[uri] = bad
    assert not clashes, f"link text that goes to two places: {dict(list(clashes.items())[:3])}"


def test_building_the_site_puts_every_help_page_where_its_helpuri_points(tmp_path: Path) -> None:
    """The check the whole design rests on: build the docs, then follow every helpUri.

    The build is strict, like CI's `docs-build` job, which builds the shipped Material
    config the same way, so a warning from any page (a dead link, a missing anchor)
    fails it. Retired rules are followed too: their alerts outlive them.
    """
    pytest.importorskip("mkdocs.commands.build")
    from mkdocs.commands import build

    site_dir = tmp_path / "site"
    config = _mkdocs_config(site_dir, strict=True)
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
    for rule_id in [*RULES, *RETIRED_RULE_IDS]:
        uri = _help_uri(rule_id)
        assert uri.startswith(site)
        if not (site_dir / uri[len(site):] / "index.html").is_file():
            missing.append(rule_id)
    assert not missing, f"helpUri targets with no built page: {missing[:5]} ({len(missing)})"
    for rule_id in RETIRED_RULE_IDS:
        built = (site_dir / "rules" / rule_id / "index.html").read_text(encoding="utf-8")
        assert f"<title>Retired rule {rule_id}: " in built and "What covers it now" in built

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
    names = (
        {rp.page_uri(rule_id) for rule_id in RULES if rule_id not in own}
        | {rp.page_uri(rule_id) for rule_id in RETIRED_RULE_IDS}
        | {rp.INDEX_URI}
    )
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
