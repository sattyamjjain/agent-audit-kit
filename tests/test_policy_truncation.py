"""Tests for AAK-POLICY-TRUNCATION-001.

A deny policy evaluated against a truncated copy of the value the executor
actually receives. CVE-2026-73614 (ClaudeHookBridge, CVSS 8.8) is the disclosed
instance — truncation to 500 chars before `denyPatterns`, while Claude Code ran
the full command — but that package is unpinnable (absent from npm, PyPI and
GitHub), so the rule keys on the shape rather than the vendor.

The false-positive tests carry the weight here: truncation is extremely common
and almost always benign. The rule only fires when the untruncated source is
still used elsewhere, which is what makes the split exploitable.
"""

from __future__ import annotations

import random
import re
import time
from pathlib import Path
from typing import Callable

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import policy_truncation
from agent_audit_kit.scanners.policy_truncation import scan

RULE = "AAK-POLICY-TRUNCATION-001"
FIXTURES = (
    Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-73614-policy-truncation"
)


def _ids(root: Path) -> set[str]:
    return {f.rule_id for f in scan(root)[0]}


def _write(tmp_path: Path, name: str, content: str) -> Path:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return tmp_path


# --- registration -----------------------------------------------------------


def test_rule_is_registered() -> None:
    assert RULE in RULES
    rule = RULES[RULE]
    assert rule.severity.value == "high"
    assert rule.category.value == "trust-boundary"
    assert "CVE-2026-73614" in rule.cve_references


def test_scan_reports_scanned_files_not_rule_ids(tmp_path: Path) -> None:
    """The second tuple element is scanned file paths, not rule ids (#743).

    This test used to assert the opposite. The engine unions that set into
    ``files_scanned``, so returning rule ids made an empty directory report
    files it never opened, and rule coverage is computed separately from the
    active rule set regardless.
    """
    assert scan(tmp_path)[1] == set()


# --- fixtures ---------------------------------------------------------------


def test_fixtures_positive_and_negative() -> None:
    assert RULE in _ids(FIXTURES / "vulnerable")
    assert RULE not in _ids(FIXTURES / "negative")


# --- the vulnerable shape ---------------------------------------------------


_JS_VULNERABLE = """
const denyPatterns = [/rm -rf/];
function check(payload) {
  const command = payload.command;
  const target = command.slice(0, 500);
  for (const p of denyPatterns) {
    if (p.test(target)) return "deny";
  }
  return execute(command);
}
"""


def test_js_slice_before_deny_check_fires(tmp_path: Path) -> None:
    assert RULE in _ids(_write(tmp_path, "bridge.js", _JS_VULNERABLE))


def test_typescript_substring_variant_fires(tmp_path: Path) -> None:
    src = """
    const blockedPatterns = [/curl/];
    export function guard(cmd: string) {
      const probe = cmd.substring(0, 256);
      if (blockedPatterns.some(p => probe.match(p))) { return "deny"; }
      return run(cmd);
    }
    """
    assert RULE in _ids(_write(tmp_path, "guard.ts", src))


def test_python_slice_before_deny_check_fires(tmp_path: Path) -> None:
    src = (
        "deny_patterns = [r'rm -rf']\n"
        "def check(command):\n"
        "    target = command[:500]\n"
        "    for p in deny_patterns:\n"
        "        if re.search(p, target):\n"
        "            return 'deny'\n"
        "    return execute(command)\n"
    )
    assert RULE in _ids(_write(tmp_path, "guard.py", src))


# --- false-positive resistance ----------------------------------------------


def test_policy_on_the_full_value_stays_quiet(tmp_path: Path) -> None:
    """The fix: match what executes, and reject over-long input outright."""
    src = """
    const denyPatterns = [/rm -rf/];
    function check(payload) {
      const command = payload.command;
      if (command.length > 500) return "deny";
      for (const p of denyPatterns) {
        if (p.test(command)) return "deny";
      }
      return execute(command);
    }
    """
    assert RULE not in _ids(_write(tmp_path, "bridge.js", src))


def test_display_truncation_stays_quiet(tmp_path: Path) -> None:
    """Truncating purely for output is the common, benign case."""
    src = """
    const denyPatterns = [/rm -rf/];
    function render(payload) {
      const preview = payload.summary.slice(0, 120);
      console.log(preview);
      return preview;
    }
    """
    assert RULE not in _ids(_write(tmp_path, "render.js", src))


def test_truncation_with_no_deny_context_stays_quiet(tmp_path: Path) -> None:
    src = """
    function shorten(text) {
      const head = text.slice(0, 500);
      if (head.includes("hello")) { return true; }
      return text;
    }
    """
    assert RULE not in _ids(_write(tmp_path, "shorten.js", src))


def test_truncated_value_used_everywhere_stays_quiet(tmp_path: Path) -> None:
    """No asymmetry: if only the short copy is ever used, nothing is bypassed."""
    src = """
    const denyPatterns = [/rm -rf/];
    function check(payload) {
      const target = payload.command.slice(0, 500);
      for (const p of denyPatterns) {
        if (p.test(target)) return "deny";
      }
      return execute(target);
    }
    """
    assert RULE not in _ids(_write(tmp_path, "bridge.js", src))


def test_comment_mentioning_deny_does_not_create_a_finding(tmp_path: Path) -> None:
    src = """
    // TODO: wire this into denyPatterns one day
    function shorten(text) {
      const head = text.slice(0, 500);
      return head + text.length;
    }
    """
    assert RULE not in _ids(_write(tmp_path, "shorten.js", src))


def test_short_slice_bounds_are_ignored(tmp_path: Path) -> None:
    """A single-digit bound is a parser or formatter, not a policy window."""
    src = """
    const denyPatterns = [/rm -rf/];
    function check(cmd) {
      const verb = cmd.slice(0, 3);
      if (denyPatterns.includes(verb)) return "deny";
      return execute(cmd);
    }
    """
    assert RULE not in _ids(_write(tmp_path, "bridge.js", src))


_CRAFTED_SOURCES = {
    # Every character of a long word or blank run began a truncation attempt.
    ("x.js", "word"): "const denyList = [];\n" + "a" * 990_000,
    ("x.js", "blanks"): "const denyList = [];\n" + " " * 990_000 + "x",
    ("x.py", "word"): "deny_list = []\n" + "a" * 990_000,
    # Every unclosed `/*` was read to the end of the file.
    ("x.js", "open-comments"): "const denyList = [];\n" + "/* a" * 247_000,
    # Every `search(` read its arguments to the first `)`.
    ("x.js", "calls"): "const denyList = [];\nconst short = cmd.slice(0, 50);\n" + "search(" * 141_000,
}


@pytest.mark.parametrize(("name", "shape"), sorted(_CRAFTED_SOURCES))
def test_a_crafted_source_scans_in_linear_time(tmp_path: Path, name: str, shape: str) -> None:
    """Just under the scanner's 1,000,000-byte cap, with a deny context so the
    truncation patterns run. Before, 80 KB of `search(` took 0.29 seconds,
    and every shape grew with the square. The bound is loose for slow CI runners."""
    import time

    content = _CRAFTED_SOURCES[(name, shape)]
    assert len(content) < 1_000_000
    _write(tmp_path, name, content)
    started = time.perf_counter()
    _ids(tmp_path)
    assert time.perf_counter() - started < 5.0


# --- the per-truncation checks are read off one index -------------------------
#
# Whether the policy tests the truncated variable, and whether the source is
# still used, were each a fresh regex over the whole file for every truncation:
# 4,000 truncations in 79 KB took 5.6 seconds and 790 KB took 493. Each timing
# test runs a crafted file at two sizes, best of three, and allows the larger 40
# times the smaller's time for 10 times the text (the old checks needed 100)
# plus a fixed slack, under an absolute bound that is loose for slow CI runners.


def _seconds(run: Callable[[], object]) -> float:
    """Best of three, so one descheduled run cannot fail a timing test."""
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        run()
        best = min(best, time.perf_counter() - started)
    return best


def _grows_linearly(tmp_path: Path, name: str, unit: Callable[[int], str], count: int) -> None:
    """``unit(i)`` for ``count`` and ``10 * count`` values of ``i``."""
    small, large = tmp_path / "small", tmp_path / "large"
    for root, n in ((small, count), (large, 10 * count)):
        root.mkdir()
        (root / name).write_text("".join(unit(i) for i in range(n)), encoding="utf-8")
    t_small, t_large = _seconds(lambda: scan(small)), _seconds(lambda: scan(large))
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


def test_many_truncations_scan_in_linear_time(tmp_path: Path) -> None:
    """4,000 truncations to distinct names, with a deny context: 79 KB took
    5.6 seconds."""
    _grows_linearly(tmp_path, "guard.js", lambda i: f"const denyList = [];\nconst t{i} = cmd.slice(0, 500);\n", 2_000)


@pytest.mark.parametrize("source", ["h.i{i}", "h[i{i}]"])
def test_every_tested_truncation_of_a_once_used_source_scans_in_linear_time(
    tmp_path: Path, source: str
) -> None:
    """Each truncation passes its deny test, and its source is used once, so
    the source check runs for every one. The sources share a head, so they
    cannot be told apart by it. 79 KB took 2.8 seconds."""
    def unit(i: int) -> str:
        return f"const t{i} = {source.format(i=i)}.slice(0, 50); if (denyList.test(t{i})) {{}}\n"

    _grows_linearly(tmp_path, "guard.js", unit, 600)
    assert _ids(tmp_path / "large") == set()


def test_a_run_of_deny_words_scans_in_linear_time(tmp_path: Path) -> None:
    """Every `deny` in a run read the letters after it to the end of the run:
    80,000 characters took 31 seconds."""
    def unit(i: int) -> str:
        return "const t = cmd.slice(0, 50);\n" if i == 0 else "deny" * 25

    _grows_linearly(tmp_path, "guard.js", unit, 800)


# The forms the index must reproduce, and the reference counting, against the
# per-name regexes they replaced: names that end other names (the method and
# `in` forms have no left boundary), `$` in names, nested test calls, `(x)`
# inside `.test(x)`, `in` chains, sources that overlap or carry brackets, and
# deny words split by the 400-character window.
_NAMES = ["t", "at", "x", "x$", "$x", "cmd", "md", "in", "search", "probe"]
_SOURCES = ["cmd", "c.md", "a[0]", "a[a", "p.q[1].r", "h[i1]", "x.y", "a."]
_FRAGMENTS = [
    "const {n} = {s}.slice(0, 50);", "{n} = {s}[:500]", "{n}.match(p)", "x{n} . test (y)", "p.test({n})",
    ".exec( {n} )", "re.search(p, {n})", "search(a, search(b, {n}))", "search(a, {n}, )", "match(a, b",
    "if ({n} in deny)", "for x in {n}", "in {n}x in {n}", "{n} in s", "({n})", "run({s})", "{s}",
    "denyPatterns", "denydenyList", "denyListx", "DENYLIST", "blockedRules", "forbiddenx1", "disallowed",
    "y" * 395, "\n",
]


def _generated_guards(count: int) -> list[str]:
    rng = random.Random(7)
    return [
        " ".join(
            rng.choice(_FRAGMENTS).format(n=rng.choice(_NAMES), s=rng.choice(_SOURCES))
            for _ in range(rng.randint(1, 16))
        )
        for _ in range(count)
    ]


def test_the_index_matches_the_per_name_regexes() -> None:
    for code in _generated_guards(400):
        checks = policy_truncation._TruncationChecks(code, set(_NAMES), set(_SOURCES))
        for name in _NAMES:
            regex = policy_truncation._TEST_TEMPLATE.format(var=re.escape(name))
            assert list(checks.test_matches(name)) == [m.span() for m in re.finditer(regex, code)], (name, code)
        refs = policy_truncation._SourceRefs(code, set(_SOURCES))
        starved = policy_truncation._SourceRefs(code, set(_SOURCES))
        starved._budget = 0  # every bracketed source is counted by reading the file
        for source in _SOURCES:
            regex = policy_truncation._SOURCE_REF.format(src=re.escape(source))
            want = len(re.findall(regex, code)) >= 2
            assert refs.at_least_two(source) == want == starved.at_least_two(source), (source, code)
