"""A retired rule id stays retired.

A rule id is a public name. It sits in SARIF baselines and code-scanning alerts,
in `--rules` and `--exclude-rules` lists, in VEX statements and in suppressions
written against an earlier release, so a new rule under an old id would be read
as the old rule. `rules.builtin.RETIRED_RULE_IDS` records every id that has left
the registry. `_r()` refuses to register one, and the tests below fail when
anything shipped still names one: a scanner, a compliance table, a preset, the
AIVSS defaults, a coverage map or the published `rules.json`. Each entry also
feeds the help page left at the rule's old address (`tests/test_rule_pages.py`
builds it), so it has to say what the rule was, when it went, why, and what
covers it now.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules import builtin
from agent_audit_kit.rules.builtin import RETIRED_RULE_IDS, RULES

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = REPO_ROOT / "agent_audit_kit"

#: Files shipped inside the package that are read as data rather than imported.
_DATA_SUFFIXES = frozenset({".json", ".yaml", ".yml", ".txt"})

_RULE_ID = re.compile(r"AAK-[A-Z0-9]+(?:-[A-Z0-9]+)*")
_RELEASE_HEADING = re.compile(r"^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$", re.M)


def _rule_pages():
    """`scripts/rule_pages.py`, whose `named_in_code` reads ids from code, not prose."""
    spec = importlib.util.spec_from_file_location(
        "rule_pages_for_retired_ids", REPO_ROOT / "scripts" / "rule_pages.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their own module while being defined
    spec.loader.exec_module(module)
    return module


def test_every_retirement_says_what_it_was_when_and_why() -> None:
    assert RETIRED_RULE_IDS
    blank = [
        rule_id
        for rule_id, retired in RETIRED_RULE_IDS.items()
        if not (retired.title.strip() and retired.reason.strip() and retired.replacement.strip())
    ]
    assert not blank, f"retired with a blank title, reason or replacement: {blank}"
    released = set(_RELEASE_HEADING.findall((REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")))
    unreleased = {rule_id: r.last_release for rule_id, r in RETIRED_RULE_IDS.items() if r.last_release not in released}
    assert not unreleased, f"last_release is not a release in CHANGELOG.md: {unreleased}"


def test_every_rule_a_retired_page_names_exists() -> None:
    """The help page links every id the reason or the replacement names, and lists each
    id in `covered_by`, so every one must be a registered rule with a page of its own."""
    dangling: dict[str, list[str]] = {}
    for rule_id, retired in RETIRED_RULE_IDS.items():
        named = (
            set(_RULE_ID.findall(retired.reason))
            | set(_RULE_ID.findall(retired.replacement))
            | set(retired.covered_by)
        )
        if named - set(RULES):
            dangling[rule_id] = sorted(named - set(RULES))
    assert not dangling, f"retired pages naming ids that are not registered rules: {dangling}"
    repeated = [rule_id for rule_id, r in RETIRED_RULE_IDS.items() if len(set(r.covered_by)) != len(r.covered_by)]
    assert not repeated, f"covered_by lists a rule twice: {repeated}"


def test_a_replacement_that_introduces_a_list_has_one() -> None:
    """The page puts `covered_by` straight after the replacement, so a replacement ending
    in a colon needs that list, and a list needs the sentence that introduces it."""
    mismatched = [
        rule_id
        for rule_id, retired in RETIRED_RULE_IDS.items()
        if retired.replacement.rstrip().endswith(":") != bool(retired.covered_by)
    ]
    assert not mismatched, mismatched


#: A comparison sign before a number, as in `< 1.0.0`. One optional sign, then a class
#: and a digit that cannot overlap: linear.
_VERSION_BOUND = re.compile(r"[<>]=?\s*\d")


def test_a_retired_page_says_a_version_bound_in_words() -> None:
    """A screen reader reads `server < 1.0.0` as "server less 1.0.0", heard as
    "serverless", or drops the sign and makes 1.0.0 sound affected. The title is the
    page's `h1` and `<title>`, the first thing announced."""
    signs = [
        (rule_id, text)
        for rule_id, retired in RETIRED_RULE_IDS.items()
        for text in (retired.title, retired.reason, retired.replacement)
        if _VERSION_BOUND.search(text)
    ]
    assert not signs, f"write 'below 1.0.0', not '< 1.0.0': {signs}"


def test_a_home_folder_path_is_introduced_in_words() -> None:
    """The tilde in `~/.config/...` is silent when read aloud, so the path sounds as if
    it starts at the root. A sentence giving one says "home folder" too."""
    bare = [
        (rule_id, sentence)
        for rule_id, retired in RETIRED_RULE_IDS.items()
        for sentence in re.split(r"(?<=\.)\s+", f"{retired.reason} {retired.replacement}")
        if "~/" in sentence and "home folder" not in sentence
    ]
    assert not bare, bare


def test_no_retired_id_is_registered() -> None:
    registered = sorted(set(RETIRED_RULE_IDS) & set(RULES))
    assert not registered, f"retired ids back in RULES: {registered}"


@pytest.mark.parametrize("rule_id", sorted(RETIRED_RULE_IDS))
def test_registering_a_retired_id_fails(rule_id: str) -> None:
    before = dict(RULES)
    with pytest.raises(ValueError, match=rule_id):
        builtin._r(rule_id, "A new rule", "It finds a thing.", Severity.LOW, Category.MCP_CONFIG, "Fix it.")
    assert RULES == before


def test_no_module_names_a_retired_id_in_code() -> None:
    """No scanner can still emit one, and no table outside the registry still lists one."""
    named = _rule_pages().named_in_code(PACKAGE, RETIRED_RULE_IDS)
    assert not named, f"retired ids still named in code: {named}"


def test_no_shipped_data_file_names_a_retired_id() -> None:
    hits = [
        (path.relative_to(REPO_ROOT).as_posix(), rule_id)
        for path in sorted(PACKAGE.rglob("*"))
        if path.is_file() and path.suffix in _DATA_SUFFIXES
        for rule_id in sorted(RETIRED_RULE_IDS)
        if rule_id in path.read_text(encoding="utf-8", errors="replace")
    ]
    assert not hits, f"retired ids still named in package data: {hits}"


def test_the_published_rule_bundle_has_no_retired_id() -> None:
    bundle = json.loads((REPO_ROOT / "rules.json").read_text(encoding="utf-8"))
    published = sorted({rule["rule_id"] for rule in bundle["rules"]} & set(RETIRED_RULE_IDS))
    assert not published, (
        f"rules.json still publishes {published}; run "
        "`PYTHONPATH=. python scripts/sync_rule_count.py --regenerate`"
    )
