"""Live rule titles say a version bound, or any other bound on a number, in words.

A screen reader reads `server < 1.0.0` as "server less 1.0.0", heard as
"serverless", or drops the sign and makes 1.0.0 sound affected; `>=2 agents`
loses its sign the same way. A title is the rule page's `h1` and `<title>`, the
SARIF rule's `shortDescription` and the finding's title in every report, so it
is the first thing announced. `tests/test_retired_rules.py` holds retired titles to
the same rule; this holds the live ones (#1060).
"""

from __future__ import annotations

import re

from agent_audit_kit.rules.builtin import RULES

#: A comparison sign before a number, with an optional `v` (`< 1.0.0`, `<=v2.1`,
#: `>12`). One optional sign, then classes that cannot overlap: linear.
_BOUND = re.compile(r"[<>]=?\s*v?\d")


def test_a_live_title_says_a_bound_in_words() -> None:
    signs = sorted((rule.rule_id, rule.title) for rule in RULES.values() if _BOUND.search(rule.title))
    assert not signs, (
        "write 'below 1.0.0', '1.0.0 or earlier', 'from 1.0.0 below 2.0.0' or "
        f"'more than 12', not a comparison sign: {signs}"
    )


def test_the_pattern_catches_each_spelling_it_names() -> None:
    for text in ("pkg < 1.0.0", "pkg <=1.1.1", "(<v2.0)", ">=2 agents", "with >12 parameters"):
        assert _BOUND.search(text), text
    for text in ("pkg below 1.0.0", "1.1.1 or earlier", "two or more agents", "a -> b", "x → y"):
        assert not _BOUND.search(text), text
