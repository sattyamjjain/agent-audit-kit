"""Fix-recipe coverage is one canonical number, computed from the registry.

Issue #607 asks how many rules carry a fix recipe and targets roughly 30% for the
auto-PR path. v0.3.80 shipped ``suggest --auto-pr``, which refuses anything outside
``AUTO_PR_ALLOWLIST``, so both the recipe count and the allow-list size are published
capability claims — and a published capability claim that overstates is the same
defect this release's remediation-key guard exists to prevent.

It did overstate. Three ``AUTO_PR_ALLOWLIST`` entries had no reachable recipe:
``AAK-FLOWISE-001`` and ``AAK-NEO4J-001`` had none at all, and
``AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001`` had one that only
``suggest --apply-trivial`` could reach. ``plan_auto_pr`` sources its candidates from
``run_fixes`` → ``_apply_fix``, which returned ``None`` for all three, so they could
never enter ``pending`` and ``--auto-pr`` could never act on them.

These tests keep the number honest in both directions:

* ``auto_fixable`` must imply a recipe that actually runs — so the flag cannot
  advertise a fix that does nothing.
* ``AUTO_PR_ALLOWLIST`` must be reachable from ``run_fixes`` — so the auto-PR claim
  cannot outrun the dispatch.
* The README marker must equal the computed count — same discipline as
  ``test_rule_count_is_canonical`` in ``tests/test_rule_count_sync.py``, so the two
  numbers cannot drift apart.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from agent_audit_kit import fix as fix_module
from agent_audit_kit.autopr import AUTO_PR_ALLOWLIST
from agent_audit_kit.rules.builtin import RULES

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"

_COUNT_ANCHOR_RE = re.compile(
    r"<!--\s*fix-recipe-coverage:count\s*-->(\d+)<!--\s*/fix-recipe-coverage\s*-->"
)
_PCT_ANCHOR_RE = re.compile(
    r"<!--\s*fix-recipe-coverage:pct\s*-->([\d.]+)<!--\s*/fix-recipe-coverage\s*-->"
)


def _auto_fixable_rules() -> list[str]:
    """The canonical set: rules the registry marks as carrying a fix recipe."""
    return sorted(rid for rid, rule in RULES.items() if rule.auto_fixable)


def fix_recipe_count() -> int:
    return len(_auto_fixable_rules())


def _dispatches(rule_id: str) -> bool:
    """True when ``_apply_fix`` produces an action for a manifest this rule targets.

    Each recipe is handed a file of the kind it edits. A rule whose dispatch branch is
    missing returns None for every one of them, which is exactly the dead-entry
    condition this module exists to catch.
    """
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        candidates = {
            "requirements.txt": (
                "flowise==3.0.1\nmcp-neo4j-cypher==0.5.0\n"
                "litellm==1.0.0\nlangchain==0.1.0\nlangchain-core==0.1.0\n"
            ),
            "package.json": '{"dependencies": {"flowise": "3.0.1", "langchain": "0.1.0"}}',
            "config.json": (
                '{"mcpServers": {"s": {"env": {"API_KEY": "averylongsecretvalue123456"}}},'
                ' "enableAllProjectMcpServers": true}'
            ),
            "graph.py": "ToolNode([a, b])\n",
        }
        for name, body in candidates.items():
            (root / name).write_text(body, encoding="utf-8")
        for name in candidates:
            if fix_module._apply_fix(root, rule_id, name, dry_run=True) is not None:
                return True
    return False


def test_every_auto_fixable_rule_has_a_recipe_that_runs() -> None:
    """The flag may not advertise a fix that does nothing."""
    missing = [rid for rid in _auto_fixable_rules() if not _dispatches(rid)]
    assert not missing, (
        "rule(s) marked auto_fixable have no recipe reachable from fix._apply_fix, so "
        f"`agent-audit-kit fix` silently does nothing for them: {missing}. Either add "
        "the recipe or drop the auto_fixable flag — do not leave the claim standing."
    )


def test_auto_pr_allowlist_is_reachable_from_run_fixes() -> None:
    """``--auto-pr`` cannot promise a rule that ``run_fixes`` never yields.

    ``plan_auto_pr`` filters ``run_fixes(...)`` output by this allow-list, so an entry
    with no dispatch is dead weight that reads as capability.
    """
    dead = [rid for rid in sorted(AUTO_PR_ALLOWLIST) if not _dispatches(rid)]
    assert not dead, (
        "AUTO_PR_ALLOWLIST entries have no recipe reachable from run_fixes, so "
        f"`suggest --auto-pr` can never act on them: {dead}"
    )


def test_auto_pr_allowlist_is_a_subset_of_auto_fixable() -> None:
    """AAK may only push a fix it claims to have."""
    stray = sorted(AUTO_PR_ALLOWLIST - set(_auto_fixable_rules()))
    assert not stray, f"AUTO_PR_ALLOWLIST entries are not auto_fixable: {stray}"


def test_auto_pr_allowlist_is_narrower_than_auto_fixable() -> None:
    """The two numbers are deliberately different.

    A recipe ``aak fix`` will apply on request is not automatically a change AAK
    should open a PR for. If these ever become equal, the distinction has collapsed
    and the auto-PR gate is no longer doing anything.
    """
    auto_fixable = set(_auto_fixable_rules())
    assert AUTO_PR_ALLOWLIST < auto_fixable, (
        "AUTO_PR_ALLOWLIST is no longer a strict subset of auto_fixable — the "
        "recipe/push distinction has collapsed"
    )


def test_fix_recipe_coverage_is_canonical() -> None:
    """The README marker must equal the registry-computed count.

    Mirrors ``test_rule_count_is_canonical``: the published number is derived, and a
    hand-edited marker fails here rather than rotting in the README.
    """
    count = fix_recipe_count()
    total = len(RULES)
    text = README.read_text(encoding="utf-8")

    anchors = _COUNT_ANCHOR_RE.findall(text)
    assert anchors, (
        "README has no fix-recipe-coverage:count anchor — nothing drives the number"
    )
    for value in anchors:
        assert int(value) == count, (
            f"README claims {value} fix recipes; canonical is {count}. Run "
            "`python scripts/sync_rule_count.py`."
        )

    pct_anchors = _PCT_ANCHOR_RE.findall(text)
    assert pct_anchors, "README has no fix-recipe-coverage:pct anchor"
    expected_pct = f"{count / total * 100:.1f}"
    for value in pct_anchors:
        assert value == expected_pct, (
            f"README claims {value}% fix-recipe coverage; canonical is "
            f"{expected_pct}%. Run `python scripts/sync_rule_count.py`."
        )


def test_coverage_is_reported_not_inflated() -> None:
    """Guard the honest-reporting posture issue #607 invites breaking.

    #607 targets ~30%. Reaching that by marking rules auto_fixable without a working
    recipe is the failure mode; ``test_every_auto_fixable_rule_has_a_recipe_that_runs``
    already blocks it. This test additionally pins the claim as a *ratio of the whole
    registry*, so coverage can never be made to look better by quietly shrinking the
    denominator.
    """
    total = len(RULES)
    from agent_audit_kit import RULE_COUNT

    assert total == RULE_COUNT, (
        "fix-recipe coverage must be reported against the full rule registry; "
        f"len(RULES)={total} but RULE_COUNT={RULE_COUNT}"
    )
    assert 0 < fix_recipe_count() <= total


def test_oauth_008_is_not_auto_fixable_and_the_reason_is_recorded() -> None:
    """#607's largest remaining rule, decided against rather than left open.

    `AAK-OAUTH-008` is the biggest single block of findings without a recipe, so
    it is the obvious next candidate. It is also the one where a recipe would be
    actively harmful, which is why the decision is pinned here instead of being
    re-derived by whoever next reads the issue.
    """
    from agent_audit_kit.autopr import NON_MECHANICAL
    from agent_audit_kit.rules.builtin import RULES

    assert RULES["AAK-OAUTH-008"].auto_fixable is False
    shapes = " ".join(shape for shape, _ in NON_MECHANICAL)
    assert "AAK-OAUTH-008" in shapes, (
        "the decision not to auto-fix AAK-OAUTH-008 must be recorded in "
        "NON_MECHANICAL with its reason, or it reads as an oversight"
    )


def test_a_bare_prm_keyword_silences_oauth_008_without_fixing_anything() -> None:
    """The demonstration behind the decision above.

    `AAK-OAUTH-008` clears when the file mentions a PRM keyword. So the cheapest
    "fix" a recipe could apply -- write `authorization_servers` into the config --
    makes the finding vanish while the hardcoded credential it is complaining
    about stays exactly where it was. This test exists so that anyone who later
    proposes an auto-fix for this rule sees the failure mode rather than the
    argument for it.
    """
    import json
    from pathlib import Path

    from agent_audit_kit.scanners.oauth_misconfig import scan

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        config = root / ".mcp.json"
        config.write_text(json.dumps({
            "mcpServers": {
                "remote-api": {
                    "url": "https://api.example.com/mcp",
                    "headers": {"Authorization": "Bearer sk-live-abc123"},
                }
            }
        }), encoding="utf-8")

        before, _ = scan(root)
        assert "AAK-OAUTH-008" in {f.rule_id for f in before}, (
            "fixture no longer trips the rule, so the demonstration is vacuous"
        )

        # The minimal edit a mechanical recipe could make. Nothing is served, no
        # authorization server is contacted, the credential is untouched.
        config.write_text(json.dumps({
            "mcpServers": {
                "remote-api": {
                    "url": "https://api.example.com/mcp",
                    "headers": {"Authorization": "Bearer sk-live-abc123"},
                    "authorization_servers": ["https://auth.example.com"],
                }
            }
        }), encoding="utf-8")

        after, _ = scan(root)
        assert "AAK-OAUTH-008" not in {f.rule_id for f in after}, (
            "the detector no longer clears on a bare PRM keyword — re-evaluate "
            "whether a recipe is now safe, and update NON_MECHANICAL if so"
        )
        assert "sk-live-abc123" in config.read_text(encoding="utf-8"), (
            "the credential must still be present: that is the whole point"
        )
