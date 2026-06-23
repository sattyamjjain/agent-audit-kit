"""Single-source-of-truth test for rule count.

README / action.yml / __init__.RULE_COUNT / rules.json must all agree.
This test is the regression fence that catches human drift before it
reaches main. The sync tool (`scripts/sync_rule_count.py`) is the
enforcer; this test is the shape check.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _actual_rule_count() -> int:
    from agent_audit_kit.rules.builtin import RULES

    return len(RULES)


def test_bundle_count_matches_code() -> None:
    bundle = REPO_ROOT / "rules.json"
    assert bundle.is_file(), (
        "rules.json missing. Run `python scripts/sync_rule_count.py --regenerate`."
    )
    data = json.loads(bundle.read_text(encoding="utf-8"))
    assert isinstance(data.get("rules"), list)
    assert len(data["rules"]) == _actual_rule_count()


def test_readme_badge_matches() -> None:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"img\.shields\.io/badge/rules-(\d+)-[a-z]+\.svg", text)
    assert m, "rules badge missing from README.md"
    assert int(m.group(1)) == _actual_rule_count()


def test_readme_anchors_all_match() -> None:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    anchors = re.findall(
        r"<!--\s*rule-count:total\s*-->(\d+)<!--\s*/rule-count\s*-->",
        text,
    )
    assert anchors, "no rule-count anchors in README — sync script won't drive any section"
    for value in anchors:
        assert int(value) == _actual_rule_count()


def test_action_yml_description_matches() -> None:
    text = (REPO_ROOT / "action.yml").read_text(encoding="utf-8")
    m = re.search(r"description:.*?(\d+)\s+rules", text)
    assert m, "action.yml description missing the 'N rules' phrase"
    assert int(m.group(1)) == _actual_rule_count()


def test_init_rule_count_matches() -> None:
    from agent_audit_kit import RULE_COUNT

    assert RULE_COUNT == _actual_rule_count()


def test_sync_script_check_mode_is_clean() -> None:
    """Running the sync tool in --check mode should exit 0 on a clean tree."""
    script = REPO_ROOT / "scripts" / "sync_rule_count.py"
    assert script.is_file()

    # Load the script as a module and invoke main() with a synthetic CLI —
    # faster than subprocess + avoids noisy stdout.
    spec = importlib.util.spec_from_file_location("sync_rule_count", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["sync_rule_count"] = module
    spec.loader.exec_module(module)

    old_argv = sys.argv[:]
    sys.argv = ["sync_rule_count", "--check"]
    try:
        rc = module.main()
    finally:
        sys.argv = old_argv
    assert rc == 0, "sync_rule_count --check reported drift; run the script and commit the result"


def test_no_stale_hardcoded_counts_in_prose() -> None:
    """Anything still saying '77 rules' or '124 rules' is a bug: the launch history
    kept those counts as historical artefacts in CHANGELOG.md but they must not
    appear in README.md / action.yml as current-state text."""
    for rel in ("README.md", "action.yml"):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        # Only flag specifically the old rule-count phrases we know about.
        for stale in ("77 rules", "124 rules", "138 rules total"):
            if stale == f"{_actual_rule_count()} rules":
                continue
            if stale == f"{_actual_rule_count()} rules total":
                continue
            if f"{_actual_rule_count()}" in stale:
                continue
            # The phrase must not appear as a current-state claim.
            assert stale not in text, (
                f"{rel} still contains stale phrase {stale!r}; "
                "run scripts/sync_rule_count.py."
            )


def test_rule_count_is_canonical() -> None:
    """One canonical number, computed from len(RULES), shown everywhere it is
    claimed as current state. Fails if any authoritative surface — README badge,
    README total-anchors, action.yml description, __init__.RULE_COUNT, the signed
    rules.json bundle — or the present-tense launch copy diverges from the
    registry. Historical/version-stamped/category counts (CHANGELOG, ROADMAP
    starting point, per-OWASP-category tables, "(v0.3.5)" snapshots) are NOT
    current-state claims and are intentionally out of scope.
    """
    count = _actual_rule_count()

    # 1. Authoritative current-state surfaces must all equal len(RULES).
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    badge = re.search(r"img\.shields\.io/badge/rules-(\d+)-[a-z]+\.svg", readme)
    assert badge and int(badge.group(1)) == count, "README badge != len(RULES)"
    anchors = re.findall(
        r"<!--\s*rule-count:total\s*-->(\d+)<!--\s*/rule-count\s*-->", readme
    )
    assert anchors and all(int(a) == count for a in anchors), "README anchor drift"

    action = (REPO_ROOT / "action.yml").read_text(encoding="utf-8")
    am = re.search(r"description:.*?(\d+)\s+rules", action)
    assert am and int(am.group(1)) == count, "action.yml description != len(RULES)"

    from agent_audit_kit import RULE_COUNT

    assert RULE_COUNT == count, "__init__.RULE_COUNT != len(RULES)"

    bundle = json.loads((REPO_ROOT / "rules.json").read_text(encoding="utf-8"))
    assert len(bundle["rules"]) == count, "rules.json bundle != len(RULES)"

    # 2. The package meta must not carry a divergent hard-coded count.
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    desc = re.search(r'^description\s*=\s*"([^"]*)"', pyproject, re.MULTILINE)
    assert desc, "pyproject description missing"
    bad = re.search(r"(\d+)\s+rules", desc.group(1))
    assert not bad or int(bad.group(1)) == count, (
        "pyproject description hard-codes a divergent rule count"
    )

    # 3. Present-tense launch copy (marketing claims) must match the registry.
    for rel in (
        "docs/launch/hn.md",
        "docs/launch/reddit.md",
        "docs/launch/x-thread.md",
    ):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        for claimed in re.findall(r"(\d+)\s+(?:deterministic\s+)?rules?\b", text):
            assert int(claimed) == count, (
                f"{rel} claims {claimed} rules; canonical is {count}. "
                "Update launch copy or run scripts/sync_rule_count.py."
            )
