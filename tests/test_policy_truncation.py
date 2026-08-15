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

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
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


def test_scanner_always_reports_the_rule_as_evaluated(tmp_path: Path) -> None:
    assert scan(tmp_path)[1] == {RULE}


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
