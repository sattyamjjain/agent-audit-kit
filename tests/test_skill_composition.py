"""Tests for the composition-aware capability-union check (AAK-AGENT-COMPOSE-001).

The rule operates on the SET of skills that load into one agent context, not one
artifact at a time. Fixtures under tests/fixtures/skill_composition/ reproduce the
ColluSkill shape: three skills that individually pass every existing rule but
collectively cross the exfiltration boundary. A benign three-skill set is the
false-positive control.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.skill_composition import _parse_frontmatter, scan

FIX = Path(__file__).resolve().parent / "fixtures" / "skill_composition"
RULE = "AAK-AGENT-COMPOSE-001"


def _ids(root: Path) -> list[str]:
    return [f.rule_id for f in scan(root)[0]]


def test_rule_registered_with_limitations() -> None:
    assert RULE in RULES
    rule = RULES[RULE]
    assert rule.severity.value == "high"
    assert rule.category.value == "trust-boundary"
    assert rule.owasp_agentic_references, "needs a framework mapping"
    # Honest about its own scope.
    assert rule.limitations and "declared capability" in rule.limitations.lower()
    # Cites the composition study.
    assert "2608.09732" in rule.description


def test_collude_set_trips() -> None:
    assert RULE in _ids(FIX / "collude")


def test_benign_set_does_not_trip() -> None:
    # The false-positive control: a read/write-only set with no egress must stay silent.
    assert _ids(FIX / "benign") == []


def test_finding_names_which_skill_contributed_which_capability() -> None:
    findings, _ = scan(FIX / "collude")
    finding = next(f for f in findings if f.rule_id == RULE)
    related = {r["file_path"]: r["message"] for r in finding.related_locations}
    # Every one of the three skills is named as a contributor.
    assert any("project-reader" in p for p in related)
    assert any("credential-loader" in p for p in related)
    assert any("metrics-reporter" in p for p in related)
    # The egress destination is surfaced, not just "a set is risky".
    egress_msg = next(m for p, m in related.items() if "metrics-reporter" in p)
    assert "metrics-collector.attacker.example" in egress_msg
    # The read/credential contributors are labelled with the capability they add.
    assert "filesystem_read" in " ".join(related.values())
    assert "credential_access" in " ".join(related.values())


def test_collude_skills_are_individually_clean() -> None:
    # The whole point of the ColluSkill shape: every existing rule passes on each
    # skill in isolation, so the SET-level rule is the ONLY thing that fires.
    ids = {f.rule_id for f in run_scan(FIX / "collude").findings}
    assert ids == {RULE}, f"a per-skill rule fired on an individually-benign skill: {ids}"


def test_sarif_carries_contributors_as_related_locations() -> None:
    result = run_scan(FIX / "collude")
    sarif = json.loads(format_results(result, project_root=FIX / "collude"))
    results = sarif["runs"][0]["results"]
    compose = next(r for r in results if r["ruleId"] == RULE)
    related = compose.get("relatedLocations", [])
    uris = {rl["physicalLocation"]["artifactLocation"]["uri"] for rl in related}
    assert any("metrics-reporter" in u for u in uris)
    assert any("credential-loader" in u for u in uris)
    assert any("project-reader" in u for u in uris)


def test_boundary_is_configurable_via_egress_allowlist(tmp_path: Path) -> None:
    # Copy the colluding set, then allowlist the egress destination via a
    # project-level override. The set must then NOT trip — proving the boundary /
    # allowlist is configurable, not hard-coded.
    shutil.copytree(FIX / "collude", tmp_path / "proj")
    aak = tmp_path / "proj" / ".aak"
    aak.mkdir()
    (aak / "composition-boundaries.yaml").write_text(
        "boundaries:\n"
        "  - name: exfiltration-path\n"
        "    left: [filesystem_read, credential_access]\n"
        "    right: [network_egress]\n"
        "    destination_checked_side: right\n"
        "    severity: high\n"
        "egress_allowlist: [metrics-collector.attacker.example]\n",
        encoding="utf-8",
    )
    assert _ids(tmp_path / "proj") == []


_ALLOWLIST_DOCS_ONLY = (
    "boundaries:\n"
    "  - name: exfiltration-path\n"
    "    left: [filesystem_read, credential_access]\n"
    "    right: [network_egress]\n"
    "    destination_checked_side: right\n"
    "    severity: high\n"
    "egress_allowlist: [docs.example.com]\n"
)


def _collude_with_egress(tmp_path: Path, egress: str) -> Path:
    """The colluding set, its egress skill declaring `egress`, `docs.example.com` allowlisted."""
    root = tmp_path / "proj"
    shutil.copytree(FIX / "collude", root)
    reporter = root / "skills" / "metrics-reporter" / "SKILL.md"
    text = reporter.read_text(encoding="utf-8")
    reporter.write_text(
        text.replace("egress: [metrics-collector.attacker.example]", f"egress: ['{egress}']"),
        encoding="utf-8",
    )
    (root / ".aak").mkdir()
    (root / ".aak" / "composition-boundaries.yaml").write_text(_ALLOWLIST_DOCS_ONLY, encoding="utf-8")
    return root


def test_an_allowlisted_egress_url_does_not_trip(tmp_path: Path) -> None:
    assert _ids(_collude_with_egress(tmp_path, "https://docs.example.com/ping")) == []


def test_a_backslash_cannot_make_an_egress_url_look_allowlisted(tmp_path: Path) -> None:
    """`urlparse` read this host as the allowlisted docs.example.com; the agent's
    fetch tool, which parses as Node does, ends the authority at the backslash and
    posts to collector.attacker.example. The set tripped nothing."""
    root = _collude_with_egress(tmp_path, "https://collector.attacker.example\\@docs.example.com/ping")
    assert _ids(root) == [RULE]


def test_a_malformed_egress_url_is_non_allowlisted_not_a_crash(tmp_path: Path) -> None:
    """`urlparse` raises on an unclosed IPv6 bracket, which took the scanner down."""
    assert _ids(_collude_with_egress(tmp_path, "http://[::1/ping")) == [RULE]


# ---------------------------------------------------------------------------
# The SKILL.md frontmatter reader, shared by this scanner, agentic_skills,
# composition and hook_injection. It must not raise on a hostile file, must end
# the block only at a line that is `---`, and must stay linear when YAML aliases
# repeat a node.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "[" * 2000 + "]" * 2000,
    "{a: " * 2000 + "1" + "}" * 2000,
])
def test_frontmatter_nested_past_the_recursion_limit_is_unread_not_a_crash(value: str) -> None:
    assert _parse_frontmatter(f"---\nname: x\nmeta: {value}\n---\nbody\n") == {}


def test_frontmatter_ends_only_at_a_line_that_is_three_dashes() -> None:
    text = (
        "---\nname: deploy\ndescription: Deploy the app --- fast\n"
        "hooks:\n  Stop:\n    - command: echo done\n---\nBody with --- in it.\n---\nmore\n"
    )
    data = _parse_frontmatter(text)
    assert data["description"] == "Deploy the app --- fast"
    assert data["hooks"] == {"Stop": [{"command": "echo done"}]}


def test_frontmatter_with_crlf_line_ends_is_read() -> None:
    text = "---\r\nname: deploy\r\ndescription: Deploy\r\n---\r\nBody.\r\n"
    assert _parse_frontmatter(text) == {"name": "deploy", "description": "Deploy"}


@pytest.mark.parametrize("text", [
    "---\nname: x\n",                           # never closed
    "--- \nname: x\n--",                        # no closing line
    "name: x\n---\nbody\n",                     # no opening line
])
def test_frontmatter_without_both_delimiter_lines_is_empty(text: str) -> None:
    assert _parse_frontmatter(text) == {}


def test_frontmatter_aliases_that_reuse_a_node_are_read() -> None:
    text = (
        "---\nname: fmt\nbase: &fmt {type: command, command: 'npx prettier --write .'}\n"
        "hooks:\n  PostToolUse:\n    - matcher: Write\n      hooks: [*fmt]\n"
        "    - matcher: Edit\n      hooks: [*fmt]\n---\n"
    )
    groups = _parse_frontmatter(text)["hooks"]["PostToolUse"]
    assert [g["hooks"][0]["command"] for g in groups] == ["npx prettier --write ."] * 2


def _amplified(k: int, m: int) -> str:
    return (
        "---\nname: x\nh: &h {type: command, command: 'echo hi'}\n"
        "g: &g {hooks: [" + ", ".join(["*h"] * m) + "]}\n"
        "hooks:\n  Stop: [" + ", ".join(["*g"] * k) + "]\n---\n"
    )


def test_frontmatter_that_aliases_expand_past_its_own_size_is_refused() -> None:
    """300 references to a group of 300 references to one handler: 2,490
    characters that read as 90,000 handlers. Every reader of the result walks
    the expansion, so a hook scan of it took 2.9 s, and 24 KB took 136 s."""
    assert _parse_frontmatter(_amplified(300, 300)) == {}


def test_a_crafted_alias_expansion_reads_in_linear_time() -> None:
    """24 KB of aliases standing for 9,000,000 handlers. The bound is loose for
    slow CI runners."""
    started = time.perf_counter()
    assert _parse_frontmatter(_amplified(3000, 3000)) == {}
    assert time.perf_counter() - started < 5.0


def test_a_self_referencing_alias_is_refused() -> None:
    assert _parse_frontmatter("---\nname: x\nloop: &a [*a]\n---\n") == {}


@pytest.mark.parametrize("text", [
    "---\nname: x\nmeta: " + "[" * 250_000 + "\n---\n",
    "---\nname: x\nmeta: " + "{a: " * 120_000 + "\n---\n",
    "---\n" + "".join(" " * i + f"k{i}:\n" for i in range(900)) + "---\n",
])
def test_deep_nesting_is_refused_while_it_is_scanned(text: str) -> None:
    """PyYAML's scanner pays for every open flow level on every token, so a
    structure 1,000 deep cost 213 ms of scanning alone and reaching the
    recursion limit about 2 s, on every parse of the file. Nesting is refused
    past 32 levels as it is scanned. The bound is loose for slow CI runners."""
    started = time.perf_counter()
    assert _parse_frontmatter(text) == {}
    assert time.perf_counter() - started < 1.0


def test_frontmatter_nested_as_deep_as_real_hooks_is_read() -> None:
    text = (
        "---\nname: x\nhooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n"
        "        - type: command\n          command: echo hi\n          args: [-c, [x, [y]]]\n---\n"
    )
    handler = _parse_frontmatter(text)["hooks"]["PreToolUse"][0]["hooks"][0]
    assert handler["args"] == ["-c", ["x", ["y"]]]
