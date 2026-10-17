"""`_helpers.PatternSpans` answers a range as a search of that range alone does.

Scanners that judge each function by its own lines find every match once per
file and ask about each function's range. A match over the whole text can run
across a range's edge where a search of the range alone finds a shorter one, or
one that starts inside it: at `anthropic.create` on a function's last line, with
the next line starting `create`, the `anthropic` sink arm took `create` as its
optional name and went on to that line (verification of e1cc1f9e).
"""

from __future__ import annotations

import random
import re

from agent_audit_kit.scanners._helpers import MatchSpans, PatternSpans

# Patterns that can match across a line break and give different matches from
# one place: optional greedy parts, a run up to the next parenthesis, a word
# boundary at the end, and blanks between two tokens.
PATTERNS = (
    re.compile(r"anthropic\s*\.\s*(?:\w+\s*)?(?:\.\s*)?(?:messages\.create|create)"),
    re.compile(r"x[^()]*\)"),
    re.compile(r"\bab+\b"),
    re.compile(r"c\s*d"),
)
# Whole tokens of the first pattern come often enough that a match of it runs
# across a line break in many texts.
TOKENS = ["anthropic.", "anthropic", ".", " ", "\n", "\n", "\n", "create", "create", "messages", "re", "x", "(",
          ")", "ab", "b", "c", "d"]


def _line_ranges(text: str) -> list[tuple[int, int]]:
    """Every range of whole lines, ending at the line break after its last line, as a function's lines do."""
    starts = [0] + [i + 1 for i, char in enumerate(text) if char == "\n"]
    ends = [i for i, char in enumerate(text) if char == "\n"] + [len(text)]
    return [(start, end) for start in starts for end in ends if start <= end]


def test_pattern_spans_answer_a_range_as_a_search_of_it_does() -> None:
    rng = random.Random(1043)
    ranges = 0
    for _ in range(6_000):
        text = "".join(rng.choice(TOKENS) for _ in range(rng.randint(0, 16)))
        spans = PatternSpans(PATTERNS, text)
        for start, end in _line_ranges(text):
            hits = [m.start() for p in PATTERNS for m in [p.search(text, start, end)] if m]
            expected = min(hits) if hits else None
            assert spans.first(start, end) == expected, (text, start, end)
            assert spans.within(start, end) is (expected is not None), (text, start, end)
            ranges += 1
    assert ranges > 25_000, ranges


def test_a_match_across_the_range_end_is_searched_again() -> None:
    """The whole-text match runs to the `create` on the next line; the range's own
    search finds `anthropic.create` on the last line."""
    text = "def f():\n    return anthropic.create\ncreate_app()\n"
    arm = PATTERNS[0]
    end = text.index("\ncreate_app")
    assert [m.span() for m in arm.finditer(text)] == [(20, text.index("_app"))]
    assert PatternSpans((arm,), text).first(0, end) == 20


def test_a_match_across_the_range_start_is_searched_again() -> None:
    """The whole-text match from the first line's `x` covers the second line's,
    which a search of the second line alone finds."""
    text = "x\nx)\n"
    run = PATTERNS[1]
    assert [m.span() for m in run.finditer(text)] == [(0, 4)]
    assert PatternSpans((run,), text).first(2, 4) == 2


def test_match_spans_take_a_span_inside_the_range() -> None:
    spans = MatchSpans([(2, 5), (4, 9), (10, 12)])
    assert spans.within(2, 5) and spans.within(0, 12) and spans.within(10, 12)
    assert not spans.within(3, 8) and not spans.within(5, 11)

def test_a_lookahead_that_reads_past_the_line_break_is_not_covered() -> None:
    """Not a guarantee, as the docstring says: in the whole text `(?!\\s*\\.)`
    reads past the range's line break to the `.` on the next line and fails, so
    `cp` is never a match to search again; the range's own search stops at the
    line break and matches it."""
    text = "x = cp\n.exec(c)\n"
    pattern = re.compile(r"cp(?!\s*\.)")
    end = text.index("\n")
    assert pattern.search(text, 0, end) is not None
    assert PatternSpans((pattern,), text).first(0, end) is None


def test_the_scanners_pass_no_pattern_that_looks_past_its_match() -> None:
    """The patterns the scanners hand to PatternSpans look past a match only through
    `\\b`, which reads a line break and the end of the text alike."""
    from agent_audit_kit.scanners import deepseek_v4_tool_injection, log_injection, prtitle_ipi

    patterns = [
        *prtitle_ipi._TITLE_SOURCE_RES, *prtitle_ipi._LLM_SINK_RES, *prtitle_ipi._SANITIZE_RES,
        prtitle_ipi._GH_PR_VIEW_RE, *log_injection._SANITIZERS, *deepseek_v4_tool_injection._SOURCE_RES,
    ]
    for pattern in patterns:
        assert "(?=" not in pattern.pattern and "(?!" not in pattern.pattern, pattern.pattern
        assert "$" not in pattern.pattern, pattern.pattern
