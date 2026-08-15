"""The CVE watcher must not file CVEs from outside the ecosystem it tracks.

NVD's `keywordSearch` matches indexed fields, not only the description. Two
keywords in this project's list are short enough to hit unrelated CVEs:

  * `mcp` — three letters that appear in hardware naming (NVIDIA nForce parts
    are literally "MCP"), so Linux kernel CVEs touching them come back as hits.
  * `claude` — increasingly appears in commit messages that credit the model
    for writing part of a patch.

CVE-2026-68456 arrived through both routes at once: a `ueagle-atm` USB driver
firmware-load race whose description contains the string "mcp" zero times and
ends with "(The latter two were written by Claude...)".

This is not cosmetic. Every filed CVE opens a `cve-response` issue, and the
release workflow's gate blocks any tag while one is open — so an unrelated
kernel CVE stops a publish until a human dispositions it.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "cve_watcher.py"
_spec = importlib.util.spec_from_file_location("cve_watcher_relevance", _SCRIPT)
assert _spec and _spec.loader
cve_watcher = importlib.util.module_from_spec(_spec)
sys.modules["cve_watcher_relevance"] = cve_watcher
_spec.loader.exec_module(cve_watcher)

is_relevant = cve_watcher.is_relevant


# The real description of CVE-2026-68456, trimmed to the parts that matter.
KERNEL_CVE_DESC = (
    "In the Linux kernel, the following vulnerability has been resolved:\n\n"
    "usb: atm: ueagle-atm: wait for pre-firmware load in .disconnect()\n\n"
    "ueagle-atm uses the asynchronous request_firmware_nowait() in .probe(), "
    "but does not wait for its completion, not even in .disconnect(); so, if "
    "the device is disconnected early, the callback may run after the device "
    "is gone.\n"
    "(The latter two were written by Claude; no other code/text in this commit "
    "was.)"
)


def test_the_kernel_cve_that_triggered_this_is_dropped() -> None:
    assert is_relevant(KERNEL_CVE_DESC) is False


def test_a_bare_claude_attribution_is_not_enough() -> None:
    """An AI-authored-patch credit line must not qualify a CVE."""
    assert is_relevant("A bug in libfoo. (This patch was written by Claude.)") is False


def test_a_bare_agent_mention_is_not_enough() -> None:
    """'agent' alone is user agent / SNMP agent / agent process."""
    assert is_relevant("The HTTP agent does not validate the certificate chain.") is False
    assert is_relevant("A buffer overflow in the SNMP agent daemon.") is False


@pytest.mark.parametrize(
    "desc",
    [
        "mcp-memory-service is a semantic memory layer for AI applications.",
        "The Cortex MCP server treats CLAUDE_PROJECT_DIR as trusted.",
        "MCP Atlassian is a Model Context Protocol (MCP) server for Confluence.",
        "A flaw in Claude Code's hook handling permits command execution.",
        "claude-desktop mishandles a config file.",
        "Anthropic's SDK fails to validate a token.",
        "LangChain's load_prompt allows path traversal.",
        "A LangGraph checkpoint deserialisation bug.",
        "The LLM gateway forwards credentials to an attacker-controlled host.",
        "An AI agent framework executes tool calls without validation.",
        "This agentic pipeline permits privilege escalation.",
        "The agent runtime spawns a subprocess from untrusted input.",
    ],
)
def test_genuine_ecosystem_cves_are_kept(desc: str) -> None:
    assert is_relevant(desc) is True


def test_empty_and_missing_descriptions_are_dropped() -> None:
    assert is_relevant("") is False
    assert is_relevant(None) is False  # type: ignore[arg-type]


def test_filter_is_applied_in_the_collection_path(tmp_path: Path, monkeypatch) -> None:
    """The filter must sit in collect_new_cves, not only exist as a helper."""
    def fake_fetcher(keyword: str) -> list[dict]:
        if keyword != "mcp":
            return []
        return [
            {"cve": {"id": "CVE-9999-00001", "published": "2026-08-15T00:00:00.000",
                     "descriptions": [{"lang": "en", "value": KERNEL_CVE_DESC}],
                     "metrics": {}}},
            {"cve": {"id": "CVE-9999-00002", "published": "2026-08-15T00:00:00.000",
                     "descriptions": [{"lang": "en",
                                       "value": "An MCP server executes tool arguments."}],
                     "metrics": {}}},
        ]

    monkeypatch.setattr(cve_watcher, "CHANGELOG_PATH", tmp_path / "none.md")
    results, _state = cve_watcher.collect_new_cves(
        state_path=tmp_path / "state.json",
        github_token=None,
        owner_repo=None,
        fetcher=fake_fetcher,
    )
    ids = {r["id"] for r in results}
    assert "CVE-9999-00002" in ids, "a genuine MCP CVE must still be filed"
    assert "CVE-9999-00001" not in ids, "the kernel CVE must be filtered out"
