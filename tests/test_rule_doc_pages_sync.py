"""The frozen deep-dive set must track ``docs/rules/`` and the rule registry.

``docs/`` is not shipped in the wheel, so the SARIF formatter cannot look on
disk to decide whether a rule has a page. The set is frozen into the package by
``scripts/sync_rule_doc_pages.py`` instead, which means it is a hand-maintained
fact wearing a generated file's clothes unless something fails when the two
disagree. This is that something.

The failure it prevents is quiet in both directions: a page added without
re-running the script leaves a rule pointing at the index when it has a real
page, and a page deleted without re-running it leaves a rule deep-linking a 404.
Neither shows up in any other test, because both produce well-formed SARIF.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from agent_audit_kit.output._rule_doc_pages import RULE_DOC_PAGES
from agent_audit_kit.rules.builtin import RULES

REPO_ROOT = Path(__file__).resolve().parent.parent


def _script():
    path = REPO_ROOT / "scripts" / "sync_rule_doc_pages.py"
    assert path.is_file(), "scripts/sync_rule_doc_pages.py missing"
    spec = importlib.util.spec_from_file_location("sync_rule_doc_pages", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["sync_rule_doc_pages"] = module
    spec.loader.exec_module(module)
    return module


def test_frozen_set_matches_the_docs_tree() -> None:
    """`python scripts/sync_rule_doc_pages.py` and commit the result."""
    assert RULE_DOC_PAGES == frozenset(_script().discovered())


def test_the_generator_is_idempotent() -> None:
    """--check must agree with a fresh render, or the guard is not a guard."""
    assert _script().main(["--check"]) == 0


def test_every_deep_dive_page_names_a_real_rule() -> None:
    """A page for a retired or misspelled id deep-links a 404 forever.

    Rules are never deleted in this project (docs/rule-schema.md: retire via a
    shim, keep the old id firing), so a mismatch here is a typo in a filename
    rather than a legitimately departed rule.
    """
    unknown = sorted(RULE_DOC_PAGES - set(RULES))
    assert not unknown, f"docs/rules/ pages naming no known rule: {unknown}"


def test_the_index_page_is_not_mistaken_for_a_rule() -> None:
    """docs/rules/index.md and skill-composition.md are pages, not rules."""
    assert "index" not in RULE_DOC_PAGES
    assert "skill-composition" not in RULE_DOC_PAGES


def test_the_set_is_a_strict_subset_of_the_registry() -> None:
    """If this ever became equality, the fallback branch in sarif._help_uri
    would be dead code and the index URL would stop being exercised."""
    assert RULE_DOC_PAGES < set(RULES), "every rule has a page — revisit _help_uri"
