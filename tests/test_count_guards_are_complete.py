"""``make count-check`` must cover every rendered count, not most of them.

Two guards exist and each one alone gives a false all-clear:

* ``check_counts.py`` reads *unmarked prose* across tracked markdown, matching a
  fixed list of phrasings. It has no pattern for the shields badge, so a stale
  ``rules-320-blue.svg`` passed it silently.
* ``sync_rule_count.py --check`` owns the *generated* surfaces — the badge and
  its alt text, ``action.yml``, ``__init__.py``, ``docs/rules.md`` and every
  ``<!-- rule-count -->`` anchor — but never looks at free prose.

Until v0.3.88 ``make count-check`` ran only the first, so it reported clean with
a stale badge. That is the same failure this repo keeps finding in its own
automation: a check that runs, passes, and inspects nothing.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MAKEFILE = REPO_ROOT / "Makefile"
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
README = REPO_ROOT / "README.md"


def _recipe(target: str) -> str:
    text = MAKEFILE.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(target)}:\n((?:\t.*\n)+)", text, re.M)
    assert match, f"Makefile has no {target} recipe"
    return match.group(1)


def test_count_check_runs_the_prose_guard() -> None:
    assert "check_counts.py" in _recipe("count-check")


def test_count_check_runs_the_generated_surface_guard() -> None:
    """The half that was missing, and the badge is why it mattered."""
    assert "sync_rule_count.py --check" in _recipe("count-check")


def test_the_badge_is_a_generated_surface_not_prose() -> None:
    """If the badge stops being generated, the prose guard will not catch it.

    ``check_counts.py`` matches phrasings like "N rules across M categories";
    ``rules-320-blue.svg`` is neither of those shapes, which is exactly why it
    has to stay under the generator.
    """
    from scripts.check_counts import PATTERNS  # noqa: PLC0415
    from scripts.sync_rule_count import _README_BADGE_RE  # noqa: PLC0415

    badge = "https://img.shields.io/badge/rules-320-blue.svg"
    assert _README_BADGE_RE.search(badge), "the generator no longer owns the badge"
    assert not any(rx.search(badge) for rx, _ in PATTERNS), (
        "if the prose guard now matches the badge, this test's premise changed - "
        "re-check that both guards are still needed rather than deleting one"
    )


def test_the_badge_in_the_readme_matches_the_registry() -> None:
    from agent_audit_kit import RULE_COUNT  # noqa: PLC0415

    text = README.read_text(encoding="utf-8")
    found = re.search(r"img\.shields\.io/badge/rules-(\d+)-", text)
    assert found, "README has no rules badge"
    assert int(found.group(1)) == RULE_COUNT
    assert f'alt="Rules: {RULE_COUNT}"' in text, "badge alt text drifted from the badge"


def test_ci_runs_the_count_guard_under_its_own_name() -> None:
    """A red 4-way matrix does not say "the counts are stale"; a named job does."""
    ci = CI.read_text(encoding="utf-8")
    assert "counts:" in ci
    assert "make count-check" in ci
    assert "sync_scanner_count.py --check" in ci


def test_docs_landing_page_count_is_generated() -> None:
    """It was a bare literal that only the prose guard watched."""
    index = (REPO_ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    assert "<!-- rule-count:total -->" in index

    from scripts.sync_rule_count import _TOTAL_ANCHOR_DOCS  # noqa: PLC0415

    assert "docs/index.md" in _TOTAL_ANCHOR_DOCS


def test_a_bold_number_count_is_guarded() -> None:
    """Emphasis on the number alone defeated both guards.

    `docs/launch/CHECKLIST.md` stated "**348** rules, **103** scanners" while the
    registry held 362 rules: the `**` between the digits and the noun matched
    none of the PATTERNS phrasings, and the corroboration sweep's `\\s+` cannot
    step over it either. The row sat stale with `make count-check` clean.
    """
    from scripts.check_counts import PATTERNS  # noqa: PLC0415

    row = "| Rules / scanners | **348** rules, **103** scanners, 14 categories |"
    found = {
        (key, int(m.group(1)))
        for rx, key in PATTERNS if "+" not in key
        for m in rx.finditer(row)
    }
    assert ("rules", 348) in found, "a bold-number rule count is not guarded"
    assert ("scanners", 103) in found, "a bold-number scanner count is not guarded"
