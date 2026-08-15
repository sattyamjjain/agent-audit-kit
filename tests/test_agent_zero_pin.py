"""Tests for AAK-AGENT-ZERO-CVE-2026-30624-PIN-001 (issue #160).

Agent Zero 0.9.8 executes the `command` / `args` of a user-supplied JSON MCP
server config without validation — a malicious External MCP Servers entry is RCE
(CVE-2026-30624, CVSS 8.6). NVD scopes the CVE to exactly 0.9.8 and names no
fixed release.

The 2026-05 roadmap row this rule came from was stale in three ways, and each
correction has a test here:

  * the repo moved `frdel/agent-zero` -> `agent0ai/agent-zero`;
  * `agent-zero` now resolves on PyPI, but as an unrelated voice-agent
    framework, so the bare distribution name must never fire;
  * the version scheme jumped 0.9.8 -> 1.x -> 2.x, so the floor is 1.0.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.supply_chain import scan

RULE = "AAK-AGENT-ZERO-CVE-2026-30624-PIN-001"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-30624-agent-zero"


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
    assert rule.category.value == "supply-chain"
    assert "CVE-2026-30624" in rule.cve_references


# --- fixtures ---------------------------------------------------------------


def test_fixtures_positive_and_negative() -> None:
    assert RULE in _ids(FIXTURES / "vulnerable")
    assert RULE not in _ids(FIXTURES / "negative")


# --- affected line fires ----------------------------------------------------


def test_pinned_at_affected_version_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"agent-zero": "github:agent0ai/agent-zero#v0.9.8"}}'
    assert RULE in _ids(_write(tmp_path, "package.json", content))


def test_old_org_spelling_still_fires(tmp_path: Path) -> None:
    """Manifests written before the rename still say frdel/."""
    content = '{"dependencies": {"agent-zero": "github:frdel/agent-zero#v0.9.8"}}'
    assert RULE in _ids(_write(tmp_path, "package.json", content))


def test_patch_line_below_one_fires(tmp_path: Path) -> None:
    """0.9.8.3 collapses to (0, 9, 8); no advisory says which patch carries a fix."""
    content = "git+https://github.com/agent0ai/agent-zero@v0.9.8.3\n"
    assert RULE in _ids(_write(tmp_path, "requirements.txt", content))


def test_untagged_git_reference_fires(tmp_path: Path) -> None:
    content = "git+https://github.com/agent0ai/agent-zero\n"
    assert RULE in _ids(_write(tmp_path, "requirements.txt", content))


def test_mcp_config_git_reference_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"az": {"command": "npx", "args": ["github:frdel/agent-zero"]}}}'
    assert RULE in _ids(_write(tmp_path, ".mcp.json", content))


# --- fixed line stays quiet -------------------------------------------------


def test_one_x_tag_clears(tmp_path: Path) -> None:
    content = "git+https://github.com/agent0ai/agent-zero@v1.1\n"
    assert RULE not in _ids(_write(tmp_path, "requirements.txt", content))


def test_two_x_tag_clears(tmp_path: Path) -> None:
    content = '{"dependencies": {"agent-zero": "github:agent0ai/agent-zero#v2.9"}}'
    assert RULE not in _ids(_write(tmp_path, "package.json", content))


# --- the PyPI name collision ------------------------------------------------


def test_bare_pypi_distribution_name_does_not_fire(tmp_path: Path) -> None:
    """`agent-zero` on PyPI is an unrelated voice-agent framework.

    The roadmap row called Agent Zero "GitHub-only"; that name has since been
    taken on PyPI by a different project. Matching the bare distribution name
    would fire on every consumer of that innocent package, so the rule is
    git-reference-only.
    """
    assert RULE not in _ids(_write(tmp_path, "requirements.txt", "agent-zero==0.1.2\n"))


def test_bare_name_in_package_json_does_not_fire(tmp_path: Path) -> None:
    content = '{"dependencies": {"agent-zero": "0.9.8"}}'
    assert RULE not in _ids(_write(tmp_path, "package.json", content))


def test_unrelated_repo_with_similar_path_does_not_fire(tmp_path: Path) -> None:
    content = "git+https://github.com/someoneelse/agent-zero-clone\n"
    assert RULE not in _ids(_write(tmp_path, "requirements.txt", content))


def test_sibling_repos_under_the_same_org_do_not_fire(tmp_path: Path) -> None:
    """`agent0ai/agent-zero-plugins` is not `agent0ai/agent-zero`.

    Without a trailing boundary the repo pattern matches as a prefix, so every
    sibling repository in the org inherits the CVE.
    """
    for sibling in ("agent-zero-plugins", "agent-zero-clone", "agent-zero-docs"):
        content = f"git+https://github.com/agent0ai/{sibling}\n"
        assert RULE not in _ids(_write(tmp_path, "requirements.txt", content)), sibling


def test_dot_git_suffix_still_fires(tmp_path: Path) -> None:
    """The boundary must not reject the legitimate `.git` suffix."""
    content = "git+https://github.com/frdel/agent-zero.git@v0.9.8\n"
    assert RULE in _ids(_write(tmp_path, "requirements.txt", content))
