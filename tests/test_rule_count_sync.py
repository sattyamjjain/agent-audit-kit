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

# Docs the sync script drives, mirrored here so the test fails if a surface is
# dropped from the script (or a doc loses its anchor/markers) — v0.3.49.
_DOC_TOTAL_ANCHOR_FILES = (
    "docs/comparison.md",
    "docs/comparison-gitlab-agentic-sast.md",
    "docs/STATE-OF-MCP-SECURITY-2026.md",
)
_DOCS_RULES_MD = "docs/rules.md"


def _actual_rule_count() -> int:
    from agent_audit_kit.rules.builtin import RULES

    return len(RULES)


def _load_sync_module():
    """Import scripts/sync_rule_count.py as a module (it lives outside the package)."""
    script = REPO_ROOT / "scripts" / "sync_rule_count.py"
    assert script.is_file(), "scripts/sync_rule_count.py missing"
    spec = importlib.util.spec_from_file_location("sync_rule_count", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["sync_rule_count"] = module
    spec.loader.exec_module(module)
    return module


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
    """Running the sync tool in --check mode should exit 0 on a clean tree.

    This is the broad fence: --check now covers README + action.yml +
    __init__.py + docs/rules.md summary + the comparison-page anchors.
    """
    module = _load_sync_module()

    old_argv = sys.argv[:]
    sys.argv = ["sync_rule_count", "--check"]
    try:
        rc = module.main()
    finally:
        sys.argv = old_argv
    assert rc == 0, "sync_rule_count --check reported drift; run the script and commit the result"


def test_docs_rules_summary_is_generated_from_registry() -> None:
    """docs/rules.md's Summary table must be the exact block the sync script
    renders from the live registry — so a new/renamed category or a count
    change can never leave the doc stale (the 221-vs-246 + missing-12th-category
    drift that motivated v0.3.49)."""
    module = _load_sync_module()
    count = _actual_rule_count()
    expected_block = module._render_rules_summary(count)
    text = (REPO_ROOT / _DOCS_RULES_MD).read_text(encoding="utf-8")
    assert expected_block in text, (
        f"{_DOCS_RULES_MD} summary table is not the registry-generated block; "
        "run scripts/sync_rule_count.py and commit the result."
    )
    # Every live category must be represented (guards against a dropped row).
    from agent_audit_kit.rules.builtin import RULES

    live_categories = {r.category.name for r in RULES.values()}
    for name in live_categories:
        assert name in module._CATEGORY_DISPLAY, (
            f"Category {name} has no display name in sync_rule_count._CATEGORY_DISPLAY"
        )


def test_docs_comparison_anchors_match_registry() -> None:
    """Every `<!-- rule-count:total -->N<!-- /rule-count -->` anchor in the
    comparison docs must equal len(RULES)."""
    count = _actual_rule_count()
    anchor_re = re.compile(
        r"<!--\s*rule-count:total\s*-->(\d+)<!--\s*/rule-count\s*-->"
    )
    for rel in _DOC_TOTAL_ANCHOR_FILES:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        anchors = anchor_re.findall(text)
        assert anchors, f"{rel} has no rule-count anchor — sync can't drive it"
        for value in anchors:
            assert int(value) == count, (
                f"{rel} claims {value} rules; canonical is {count}. "
                "Run scripts/sync_rule_count.py."
            )


# Docs that are intentionally frozen, dated, point-in-time snapshots: their
# counts are historical facts, not current-state claims, so the prose guard skips
# them. Keep this list tight — a path only belongs here if its counts are meant
# to stay pinned to a past release.
_PROSE_COUNT_EXEMPT_PREFIXES = (
    "docs/research/mcp-security-baseline-v1.0.md",  # frozen v1.0 baseline (262 rules)
    "docs/presets/",                                 # "shipped in vX" dated preset facts
    # Dated empirical case studies in launch/: their "N rules / M scanners" is the
    # methodology of a specific past scan run (v0.3.41, 225 rules), and the reported
    # corpus results (571/47 configs, finding totals) came from that run — bumping the
    # rule count would falsify the measurement. Same "keep the published numbers"
    # category as research/state-of-mcp-2026/**. Both self-label as drafts.
    "launch/state-of-mcp-security-2026.md",          # self-labelled "Superseded — earlier marketing draft"
    "launch/blog-50-mcp-servers.md",                 # "We scanned 47 configs" — 258 findings tied to the 225-rule run
)


def _canonical_prose_counts() -> dict[str, int]:
    """The five numbers current-state prose is allowed to claim, each computed
    from the live source of truth — never hard-coded here."""
    from agent_audit_kit import SCANNER_COUNT, discovery
    from agent_audit_kit.cli import cli
    from agent_audit_kit.output import pdf_report

    return {
        "rules": _actual_rule_count(),        # len(RULES)
        "scanners": SCANNER_COUNT,
        "commands": len(cli.commands),        # the real Click root-group command set
        # `report --framework` PDF/text evidence packs — the number an auditor
        # can actually request (cross-checked in test_report_framework_choices_match_titles).
        "frameworks": len(pdf_report._FRAMEWORK_TITLES),
        # agent platforms `discover` enumerates (NOT compliance frameworks, and NOT
        # `compliance.FRAMEWORKS`, which is the smaller `scan --compliance` table).
        "platforms": len(discovery.AGENT_CONFIGS),
    }


# (compiled pattern, count-key). Each pattern targets an unambiguous *headline
# total* phrasing so per-category tables ("**12 rules**", "2 scanners", "≥ 1
# deterministic rule") and historical quotes ("read '77 rules, 13 scanners'")
# never trip it. Bare "N rules" in launch copy is covered by
# test_rule_count_is_canonical; here we fence the prose surfaces the sync script
# does NOT drive: README.md, CLAUDE.md, and docs/**/*.md.
_PROSE_COUNT_PATTERNS = (
    # rules — bold "**N rules** across", "all N rules", "N RuleDefinition
    # entries", "N deterministic rules", "rule (N total".
    (re.compile(r"\*\*(\d+)\s+(?:deterministic |detection )?rules?\*\*\s+across", re.I), "rules"),
    (re.compile(r"\ball (\d+) rules\b", re.I), "rules"),
    (re.compile(r"\b(\d+)\s+RuleDefinition entries\b"), "rules"),
    (re.compile(r"\b(\d+)\s+deterministic rules\b", re.I), "rules"),
    (re.compile(r"\brule\s*\((\d+)\s+total\b", re.I), "rules"),
    # scanners — canonical phrasing is "N scanner modules" (never bare "N
    # scanners", which appears as per-language counts).
    (re.compile(r"\b(\d+)\s+scanner modules?\b", re.I), "scanners"),
    # CLI commands — "N CLI commands" and "(N commands)" entry-point note.
    (re.compile(r"\b(\d+)\s+CLI commands?\b", re.I), "commands"),
    (re.compile(r"entry point\s*\((\d+)\s+commands?\)", re.I), "commands"),
    # compliance frameworks — the `report --framework` PDF/text targets. Match the
    # headline forms only ("**N frameworks**", "(N frameworks)", "mapped to N
    # frameworks", "N compliance frameworks"); deliberately NOT bare "N frameworks"
    # (docs/index.md L23 historically mislabels agent platforms "frameworks", and a
    # per-item "N frameworks" in a sentence isn't a total).
    (re.compile(r"\*\*(\d+)\s+frameworks\*\*", re.I), "frameworks"),
    (re.compile(r"\((\d+)\s+frameworks\)", re.I), "frameworks"),
    (re.compile(r"\bmapped to (\d+) frameworks\b", re.I), "frameworks"),
    (re.compile(r"\b(\d+)\s+compliance frameworks\b", re.I), "frameworks"),
    # agent platforms — the surface `discover` walks. Match "**N agent platforms**"
    # and bare "N agent platforms"; deliberately NOT bare "N platforms" (avoids the
    # AUTO-MANAGED architecture-tree "(N platforms)" note and stray prose).
    (re.compile(r"\*\*(\d+)\s+agent platforms\*\*", re.I), "platforms"),
    (re.compile(r"\b(\d+)\s+agent platforms\b", re.I), "platforms"),
)


def test_no_stale_hardcoded_counts_in_prose() -> None:
    """Every current-state count claim in prose must equal the live registry.

    Extended fence (v0.3.61): scans README.md, CLAUDE.md, all docs/**/*.md, and all
    launch/**/*.md (the outbound copy — HN/Reddit/OWASP outreach/awesome-list PR
    bodies, where a wrong number does the most reputational damage) for headline
    'N rules' / 'N scanner modules' / 'N CLI commands' / 'N frameworks' /
    'N agent platforms' phrasings, and fails on any disagreement with the canonical
    counts computed from the code (len(RULES), SCANNER_COUNT, len(cli.commands),
    len(_FRAMEWORK_TITLES), len(AGENT_CONFIGS)). Historical/dated snapshots are
    exempt via _PROSE_COUNT_EXEMPT_PREFIXES; research/state-of-mcp-2026/** is left
    unscanned on purpose (frozen research artifacts); per-category and singular
    phrasings are excluded by construction of the patterns.
    """
    counts = _canonical_prose_counts()

    files = [REPO_ROOT / "README.md", REPO_ROOT / "CLAUDE.md"]
    files += sorted((REPO_ROOT / "docs").rglob("*.md"))
    files += sorted((REPO_ROOT / "launch").rglob("*.md"))

    failures: list[str] = []
    for path in files:
        rel = path.relative_to(REPO_ROOT).as_posix()
        if any(rel == p or rel.startswith(p) for p in _PROSE_COUNT_EXEMPT_PREFIXES):
            continue
        text = path.read_text(encoding="utf-8")
        for pattern, key in _PROSE_COUNT_PATTERNS:
            for m in pattern.finditer(text):
                claimed = int(m.group(1))
                if claimed != counts[key]:
                    failures.append(
                        f"{rel}: {m.group(0).strip()!r} claims {claimed} {key}; "
                        f"canonical is {counts[key]}"
                    )

    assert not failures, (
        "stale count(s) in prose — reconcile to the registry "
        "(run scripts/sync_rule_count.py where it applies):\n  "
        + "\n  ".join(failures)
    )


def test_report_framework_choices_match_titles() -> None:
    """`len(_FRAMEWORK_TITLES)` is only a legitimate canonical number if it is the
    exact set of `report --framework` targets. Read the Click choices off the live
    command object (never re-listed by hand) and assert they equal the title keys
    once the single non-framework value `standards-crosswalk` is removed. If these
    drift, the "N frameworks" prose fence is measuring the wrong thing."""
    import click

    from agent_audit_kit.cli import cli
    from agent_audit_kit.output import pdf_report

    report_cmd = cli.commands["report"]
    framework_param = next(p for p in report_cmd.params if p.name == "framework")
    param_type = framework_param.type
    assert isinstance(param_type, click.Choice), "--framework is no longer a Click Choice"
    choices = set(param_type.choices)
    choices.discard("standards-crosswalk")

    titles = set(pdf_report._FRAMEWORK_TITLES)
    assert choices == titles, (
        "report --framework choices (minus standards-crosswalk) diverged from "
        f"pdf_report._FRAMEWORK_TITLES: only-in-choices={sorted(choices - titles)}, "
        f"only-in-titles={sorted(titles - choices)}"
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

    # 4. Docs pages the sync script drives — the rules-reference summary total
    #    and the competitor-comparison rule-count cells (v0.3.49).
    anchor_re = re.compile(r"<!--\s*rule-count:total\s*-->(\d+)<!--\s*/rule-count\s*-->")
    rules_md = (REPO_ROOT / "docs/rules.md").read_text(encoding="utf-8")
    total_row = re.search(r"\|\s*\*\*Total\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|", rules_md)
    assert total_row and int(total_row.group(1)) == count, "docs/rules.md Total != len(RULES)"
    for rel in ("docs/comparison.md", "docs/comparison-gitlab-agentic-sast.md"):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        anchors = anchor_re.findall(text)
        assert anchors and all(int(a) == count for a in anchors), f"{rel} rule-count anchor drift"
