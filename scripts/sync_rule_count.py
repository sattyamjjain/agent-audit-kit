#!/usr/bin/env python3
"""Single-source-of-truth for rule count.

Reads the current signed bundle (or rebuilds it if missing) and rewrites
every place in the repo that advertises a specific rule count:

    - README.md            shields.io badge
    - action.yml           description:
    - agent_audit_kit/__init__.py  RULE_COUNT constant

Idempotent. Exits 0 when nothing needs changing, 0 when files were updated.
Exits 1 if the bundle can't be read or the regex anchor isn't found.

Runs as:
    * pre-commit hook (blocks human drift)
    * .github/workflows/sync-rule-count.yml (auto-commits after rules.json changes)

Usage:
    python scripts/sync_rule_count.py                # uses ./rules.json
    python scripts/sync_rule_count.py --bundle PATH  # explicit
    python scripts/sync_rule_count.py --regenerate   # (re)build bundle first
    python scripts/sync_rule_count.py --check        # fail if drift detected
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_BUNDLE = REPO_ROOT / "rules.json"

_README_BADGE_RE = re.compile(
    r"(img\.shields\.io/badge/rules-)\d+(-[a-z]+\.svg)"
)
# HTML-comment anchors are the canonical place the badge/phrase/total
# writes hit. Anything NOT inside an anchor is manual prose that we will
# not silently rewrite (the A2A "12 rules" cell on README line 320
# collided with the old phrase regex — we are not doing that again).
_README_ANCHOR_RE = re.compile(
    r"(<!--\s*rule-count:total\s*-->)(.*?)(<!--\s*/rule-count\s*-->)",
    re.DOTALL,
)
# Per-category anchors added v0.3.23 to fix the "What It Scans" table
# drifting independently of the total badge (the table sum was 81 rules
# under-counted before the anchors landed). Each anchor matches the
# Category enum name verbatim — e.g. `<!-- category-count:SUPPLY_CHAIN -->`.
# NOTE: must include `0-9` — `A2A_PROTOCOL` would otherwise be silently
# skipped, which is exactly the bug the v0.3.23 regression test caught.
_README_CATEGORY_ANCHOR_RE = re.compile(
    r"(<!--\s*category-count:([A-Z0-9_]+)\s*-->)(.*?)(<!--\s*/category-count\s*-->)",
    re.DOTALL,
)
_INIT_CONSTANT_RE = re.compile(
    r"^(RULE_COUNT\s*[:=]\s*)\d+(.*)$",
    re.MULTILINE,
)

# State of MCP Security report headline numbers. Driven from
# research/state-of-mcp-2026/results.json, which `make report` regenerates
# deterministically and `make report-check` already guards, so the README cannot drift
# from the report it cites. Asserted by tests/test_report_headline_numbers.py.
_REPORT_RESULTS = REPO_ROOT / "research" / "state-of-mcp-2026" / "results.json"
_README_REPORT_RE = re.compile(
    r"(<!--\s*report:([a-z0-9-]+)\s*-->)(.*?)(<!--\s*/report\s*-->)",
    re.DOTALL,
)


def report_headline_numbers() -> dict[str, str]:
    """marker key -> rendered value, read from the committed results.json.

    Rendered here rather than in the README so one place decides formatting. Counts
    over 999 carry a thousands separator to match the surrounding prose; the test
    compares parsed integers, so a formatting change cannot fail it spuriously.
    """
    import json

    data = json.loads(_REPORT_RESULTS.read_text(encoding="utf-8"))
    auth = data["auth_profile_2026_07_28"]

    def _n(value: int) -> str:
        return f"{value:,}"

    return {
        "corpus": _n(data["distinct_configs_scanned"]),
        "rfc9728-n": _n(auth["rfc9728_prm_discovery"]["n"]),
        "noauth-pct": f"{auth['no_authentication']['pct']:g}",
        "noauth-n": _n(auth["no_authentication"]["n"]),
        "inline-auth-pct": f"{auth['remote_auth_static_credential']['pct']:g}",
        "inline-auth-n": _n(auth["remote_auth_static_credential"]["n"]),
        "inline-auth-d": _n(auth["remote_auth_static_credential"]["denominator"]),
        # The second headline. PREVALENCE.md and the distribution copy both lead
        # with it, and both sat at 1,217 after the AAK-MCP-001 fix moved it to
        # 1,215 -- the same drift as the no-auth figure, one metric over.
        "critical-pct": f"{data['configs_with_critical_pct']:g}",
        "critical-n": _n(data["configs_with_critical"]),
        # PREVALENCE.md's top-10 row 3 and REPORT.md's OAuth table state the same
        # AAK-OAUTH-008 figure in opposite orders, and they disagreed: 421 / 18.3%
        # against 424 / 18.4%, inside sibling files. Sourced from
        # top_misconfigurations so the row cannot be typed by hand again.
        "oauth008-n": _n(_top_misconfig(data, "AAK-OAUTH-008")["configs"]),
        "oauth008-pct": f"{_top_misconfig(data, 'AAK-OAUTH-008')['config_pct']:g}",
    }


def _top_misconfig(data: dict, rule_id: str) -> dict:
    """One row of results.json's top_misconfigurations, by rule id.

    Raises rather than defaulting: a missing row means the rule dropped out of
    the top ten, and silently rendering a zero would publish a wrong figure that
    still passes every marker check.
    """
    for row in data["top_misconfigurations"]:
        if row["rule_id"] == rule_id:
            return row
    raise SystemExit(
        f"sync_rule_count: {rule_id} is not in results.json top_misconfigurations; "
        f"the surfaces that render its figures need revisiting"
    )


# Every file that carries `report:` markers. The README was the only one for a
# while, and five other surfaces went on stating 52.3% / 1,205 for a week after
# results.json moved to 52.2% / 1,203 -- including the Show HN title and the
# Reddit drafts, i.e. copy pasted in public. A number quoted outside the
# generator's reach is a number that rots.
#
# Two surfaces are deliberately NOT here, because a marker in either would be
# visible to a human rather than invisible in rendered markdown:
#   CITATION.cff                    figures live in a YAML block scalar, so the
#                                   comment renders into the citation abstract.
#   docs/DISTRIBUTION-CHECKLIST.md  the Show HN body and Reddit drafts are copy
#                                   somebody pastes into a comment box.
# Both are asserted against results.json in tests/test_report_headline_numbers.py
# instead, so drift fails CI without putting machinery into text that leaves the
# repository.
_REPORT_MARKER_FILES = (
    "README.md",
    "docs/STATE-OF-MCP-SECURITY-2026.md",
    "research/state-of-mcp-2026/PREVALENCE.md",
)


def _apply_report_markers(text: str, rel: str) -> str:
    """Rewrite every ``report:<key>`` marker in ``text`` from results.json.

    Shared by the README pass and the per-document pass so there is one place
    that decides what a marker means and one error path for an unknown key.
    """
    values = report_headline_numbers()

    def _sub(match: "re.Match[str]") -> str:
        key = match.group(2)
        if key not in values:
            raise SystemExit(
                f"sync_rule_count: {rel} references unknown report marker `{key}` — "
                f"valid keys: {sorted(values)}"
            )
        return f"{match.group(1)}{values[key]}{match.group(4)}"

    return _README_REPORT_RE.sub(_sub, text)


def _update_report_marker_doc(rel: str, *, check: bool) -> bool:
    """Sync one non-README document's report markers. Returns True if it changed."""
    path = REPO_ROOT / rel
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    updated = _apply_report_markers(text, rel)
    if updated == text:
        return False
    if not check:
        path.write_text(updated, encoding="utf-8")
    return True


# Fix-recipe coverage (issue #607). Driven from the registry for the same reason the
# rule total is: it is a published capability number, so a hand-edited value rots.
# Asserted by tests/test_fix_recipe_coverage.py::test_fix_recipe_coverage_is_canonical.
_README_FIX_COUNT_RE = re.compile(
    r"(<!--\s*fix-recipe-coverage:count\s*-->)(.*?)(<!--\s*/fix-recipe-coverage\s*-->)",
    re.DOTALL,
)
_README_TEST_COUNT_RE = re.compile(
    r"(<!--\s*test-count:total\s*-->)(.*?)(<!--\s*/test-count\s*-->)",
    re.DOTALL,
)
_README_FIX_PCT_RE = re.compile(
    r"(<!--\s*fix-recipe-coverage:pct\s*-->)(.*?)(<!--\s*/fix-recipe-coverage\s*-->)",
    re.DOTALL,
)

# Docs that carry a `<!-- rule-count:total -->N<!-- /rule-count -->` anchor —
# same mechanism as the README total-anchor, so the number can never drift
# from len(RULES). Added v0.3.49: docs/rules.md and the comparison pages used
# to hard-code 221 while the registry was at 246.
_TOTAL_ANCHOR_DOCS = (
    # v0.3.86: docs/comparison.md and docs/comparison-gitlab-agentic-sast.md were
    # consolidated into comparisons.md and are now stubs, so the anchors they
    # carried moved with the content they annotated.
    "docs/comparisons.md",
    "docs/STATE-OF-MCP-SECURITY-2026.md",
    # v0.3.88: the docs landing page carried a bare "320 detection rules". The
    # phrase pattern in check_counts.py caught it when it drifted, but catching
    # drift and preventing it are different jobs -- every literal that a human
    # has to retype is a literal that eventually disagrees with the registry.
    "docs/index.md",
)

# docs/rules.md ships a per-category Summary table. It is regenerated wholesale
# from the registry between these markers so a new category (e.g. the 12th,
# MCP_SERVER_CARD) can never be silently omitted the way it was pre-v0.3.49.
_RULES_MD = "docs/rules.md"
_RULES_SUMMARY_BEGIN = "<!-- BEGIN rules-summary (generated by scripts/sync_rule_count.py) -->"
_RULES_SUMMARY_END = "<!-- END rules-summary -->"
_RULES_SUMMARY_RE = re.compile(
    re.escape(_RULES_SUMMARY_BEGIN) + r".*?" + re.escape(_RULES_SUMMARY_END),
    re.DOTALL,
)

# Category enum name → human display name. Mirrors the README "What It Scans"
# table verbatim (the one canonical place these strings live). A live category
# missing from this map fails the sync loudly rather than dropping a row.
_CATEGORY_DISPLAY = {
    "MCP_CONFIG": "MCP Configuration",
    "SUPPLY_CHAIN": "Supply Chain",
    "TOOL_POISONING": "Tool Poisoning",
    "SECRET_EXPOSURE": "Secret Exposure",
    "AGENT_CONFIG": "Agent Config",
    "A2A_PROTOCOL": "A2A Protocol",
    "TAINT_ANALYSIS": "Taint Analysis",
    "HOOK_INJECTION": "Hook Injection",
    "LEGAL_COMPLIANCE": "Legal Compliance",
    "TRUST_BOUNDARY": "Trust Boundaries",
    "TRANSPORT_SECURITY": "Transport Security",
    "MCP_SERVER_CARD": "MCP Server Card",
    "COMPOSITION": "Composition",
    "AGENTIC_SKILL": "Agentic Skills (AST10)",
}


def _category_counts() -> dict[str, int]:
    """Group the live rule registry by Category.name → count."""
    from collections import Counter
    from agent_audit_kit.rules.builtin import RULES
    return {cat.name: n for cat, n in Counter(r.category for r in RULES.values()).items()}


def _test_function_count() -> int:
    """``test_*`` functions under ``tests/``, counted from the AST.

    Deterministic and offline, which is why it is the AST rather than pytest's
    collected total: collection varies with parametrisation, skips and plugins,
    so a generated number taken from it would differ between machines and start
    drifting again. The README says "test functions" so the noun matches what is
    counted.
    """
    import ast

    total = 0
    for path in sorted((REPO_ROOT / "tests").rglob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                total += 1
    return total


def _fix_recipe_count() -> int:
    """Rules carrying a mechanical fix recipe (issue #607).

    Reads the registry's ``auto_fixable`` flag. That flag is only trustworthy because
    ``tests/test_fix_recipe_coverage.py`` asserts every flagged rule has a recipe
    reachable from ``fix._apply_fix`` — before that, three of them did not.
    """
    from agent_audit_kit.rules.builtin import RULES

    return sum(1 for r in RULES.values() if r.auto_fixable)


def _load_rule_count(bundle: pathlib.Path, regenerate: bool) -> int:
    """Read rule count from the bundle (or regenerate then read)."""
    if regenerate or not bundle.is_file():
        # Prefer a clean rebuild via the public API — keeps the bundle in
        # lockstep with the code even if the on-disk rules.json is stale.
        from agent_audit_kit.bundle import write_bundle
        write_bundle(bundle)
    data = json.loads(bundle.read_text(encoding="utf-8"))
    rules = data.get("rules")
    if not isinstance(rules, list):
        raise SystemExit(f"Invalid rule bundle at {bundle}: missing 'rules' list")
    return len(rules)


def _update_readme(count: int, *, check: bool) -> bool:
    """Rewrite the badge URL + every `<!-- rule-count:total -->...<!-- /rule-count -->`
    anchor + every `<!-- category-count:NAME -->...<!-- /category-count -->`
    anchor. Also keep the shields alt-text in lockstep with the badge."""
    readme = REPO_ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    original = text
    text = _README_BADGE_RE.sub(rf"\g<1>{count}\g<2>", text)
    text = re.sub(r"alt=\"Rules:\s*\d+\"", f'alt="Rules: {count}"', text)

    def _sub_total_anchor(match: re.Match) -> str:
        return f"{match.group(1)}{count}{match.group(3)}"

    text = _README_ANCHOR_RE.sub(_sub_total_anchor, text)

    # Per-category anchors — fail loudly if the README references a
    # Category name the registry doesn't have. That catches typos and
    # stops the table from claiming a category that no longer exists.
    cat_counts = _category_counts()

    def _sub_category_anchor(match: re.Match) -> str:
        cat_name = match.group(2)
        if cat_name not in cat_counts:
            raise SystemExit(
                f"sync_rule_count: README references unknown category "
                f"`{cat_name}` — valid Category enum names: "
                f"{sorted(cat_counts.keys())}"
            )
        return f"{match.group(1)}{cat_counts[cat_name]}{match.group(4)}"

    text = _README_CATEGORY_ANCHOR_RE.sub(_sub_category_anchor, text)

    # Fix-recipe coverage — computed from the registry's auto_fixable flag, which
    # tests/test_fix_recipe_coverage.py holds to "has a recipe that actually runs".
    fix_count = _fix_recipe_count()
    text = _README_FIX_COUNT_RE.sub(
        lambda m: f"{m.group(1)}{fix_count}{m.group(3)}", text
    )
    text = _README_FIX_PCT_RE.sub(
        lambda m: f"{m.group(1)}{fix_count / count * 100:.1f}{m.group(3)}", text
    )

    # Test-function count — was a hand-written "1,100+" that sat at roughly 60%
    # of the real number. Generated for the same reason every other count here is.
    test_count = _test_function_count()
    text = _README_TEST_COUNT_RE.sub(
        lambda m: f"{m.group(1)}{test_count:,}{m.group(3)}", text
    )

    # Report headline numbers — see report_headline_numbers() above. Shared with
    # the other marker-bearing documents so one place decides what a key means.
    text = _apply_report_markers(text, "README.md")

    if text == original:
        return False
    if check:
        return True
    readme.write_text(text, encoding="utf-8")
    return True


def _update_action_yml(count: int, *, check: bool) -> bool:
    action = REPO_ROOT / "action.yml"
    text = action.read_text(encoding="utf-8")
    original = text
    new_desc = (
        f"'AgentAuditKit — MCP Security Scan ({count} rules, "
        "OWASP Agentic Top 10 + MCP Top 10)'"
    )
    # Only rewrite the top-level `description:` line (the first one we see).
    pattern = re.compile(r"^description:\s*.+$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        raise SystemExit("Could not find a top-level 'description:' line in action.yml")
    text = pattern.sub(f"description: {new_desc}", text, count=1)
    if text == original:
        return False
    if check:
        return True
    action.write_text(text, encoding="utf-8")
    return True


def _update_init_py(count: int, *, check: bool) -> bool:
    init = REPO_ROOT / "agent_audit_kit" / "__init__.py"
    text = init.read_text(encoding="utf-8")
    original = text
    if _INIT_CONSTANT_RE.search(text):
        text = _INIT_CONSTANT_RE.sub(rf"\g<1>{count}\g<2>", text)
    else:
        text = text.rstrip() + f"\nRULE_COUNT = {count}\n"
    if text == original:
        return False
    if check:
        return True
    init.write_text(text, encoding="utf-8")
    return True


def _update_total_anchor_doc(rel: str, count: int, *, check: bool) -> bool:
    """Rewrite every `<!-- rule-count:total -->N<!-- /rule-count -->` anchor in
    a doc under docs/. Reuses the README anchor regex — anything outside an
    anchor is manual prose we never touch."""
    path = REPO_ROOT / rel
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")

    def _sub(match: re.Match) -> str:
        return f"{match.group(1)}{count}{match.group(3)}"

    new = _README_ANCHOR_RE.sub(_sub, text)
    if new == text:
        return False
    if check:
        return True
    path.write_text(new, encoding="utf-8")
    return True


def _render_rules_summary(count: int) -> str:
    """Build the docs/rules.md Summary table from the live registry, sorted by
    count desc then category name. Deterministic — byte-identical every run."""
    counts = _category_counts()
    rows = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    lines = [
        _RULES_SUMMARY_BEGIN,
        "",
        "| Category | Rules |",
        "|----------|-------|",
    ]
    for name, n in rows:
        if name not in _CATEGORY_DISPLAY:
            raise SystemExit(
                f"sync_rule_count: no display name for category `{name}` — "
                f"add it to _CATEGORY_DISPLAY (valid: {sorted(_CATEGORY_DISPLAY)})"
            )
        lines.append(f"| {_CATEGORY_DISPLAY[name]} | {n} |")
    lines.append(f"| **Total** | **{count}** |")
    lines.extend(["", _RULES_SUMMARY_END])
    return "\n".join(lines)


def _update_docs_rules_md(count: int, *, check: bool) -> bool:
    """Regenerate the docs/rules.md Summary table between the BEGIN/END markers."""
    path = REPO_ROOT / _RULES_MD
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    if not _RULES_SUMMARY_RE.search(text):
        raise SystemExit(
            f"sync_rule_count: {_RULES_MD} is missing the rules-summary markers "
            f"({_RULES_SUMMARY_BEGIN!r} ... {_RULES_SUMMARY_END!r})"
        )
    block = _render_rules_summary(count)
    new = _RULES_SUMMARY_RE.sub(lambda _m: block, text)
    if new == text:
        return False
    if check:
        return True
    path.write_text(new, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", default=str(DEFAULT_BUNDLE), help="Path to rules.json")
    parser.add_argument(
        "--regenerate", action="store_true",
        help="(Re)build the bundle from agent_audit_kit.rules.builtin before reading it.",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Exit 1 if any file would change (for CI / pre-commit).",
    )
    args = parser.parse_args()
    bundle = pathlib.Path(args.bundle)

    count = _load_rule_count(bundle, args.regenerate)
    changed_readme = _update_readme(count, check=args.check)
    changed_action = _update_action_yml(count, check=args.check)
    changed_init = _update_init_py(count, check=args.check)
    changed_rules_md = _update_docs_rules_md(count, check=args.check)
    changed_docs = [
        _update_total_anchor_doc(rel, count, check=args.check)
        for rel in _TOTAL_ANCHOR_DOCS
    ]
    changed_report = [
        _update_report_marker_doc(rel, check=args.check)
        for rel in _REPORT_MARKER_FILES
        if rel != "README.md"  # already handled by _update_readme
    ]

    changed = any(
        (
            changed_readme,
            changed_action,
            changed_init,
            changed_rules_md,
            *changed_docs,
            *changed_report,
        )
    )
    if args.check and changed:
        sys.stderr.write(
            f"sync_rule_count: drift detected (rule count = {count}). "
            "Run `python scripts/sync_rule_count.py` and commit the result.\n"
        )
        return 1
    if changed:
        sys.stdout.write(
            f"sync_rule_count: wrote {count} rules into README / action.yml / "
            "__init__.py / docs/rules.md / comparison pages\n"
        )
    else:
        sys.stdout.write(f"sync_rule_count: clean ({count} rules everywhere).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
