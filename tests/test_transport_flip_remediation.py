"""Remediation for the transport-flip rules must not promise protection it can't give.

The two transport-flip rules short-circuit on `deny_stdio_transport` and
`allowed_transports`. Measuring the 748 public MCP configs in `benchmarks/data`
found those keys in **zero** of them, and searching this repo found them only in
AAK's own `rules.json`, tests and fixtures — never in a spec artifact. They are
AAK conventions, not MCP specification fields.

The remediation used to read "set `deny_stdio_transport: true` ... so a MITM
cannot flip the transport mid-session". A user who followed that added a key
their MCP client ignores, silenced this rule, and believed they were protected.
That is worse than no advice.

These tests keep the corrected text honest: it must name a control that works,
and it must disclose what those keys actually are.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "benchmarks" / "data"

TRANSPORT_FLIP_RULES = (
    "AAK-DOCSGPT-MCP-STDIO-MITM-001",
    "AAK-GPTRESEARCHER-MCP-STDIO-MITM-001",
)

# The keys the rules short-circuit on, which are not MCP specification fields.
AAK_ONLY_KEYS = (
    "deny_stdio_transport",
    "allowed_transports",
    "reject_transport_override",
    "stdio_fallback",
    "transport_override",
    "permit_transport_override",
)


@pytest.mark.parametrize("rule_id", TRANSPORT_FLIP_RULES)
def test_remediation_discloses_the_keys_are_not_spec_fields(rule_id: str) -> None:
    text = RULES[rule_id].remediation
    assert "not fields the MCP specification defines" in text, (
        f"{rule_id} short-circuits on AAK-only config keys; its remediation must say so"
    )
    assert "do not treat their presence as protection" in text


@pytest.mark.parametrize("rule_id", TRANSPORT_FLIP_RULES)
def test_remediation_names_a_control_that_actually_works(rule_id: str) -> None:
    """A version pin and TLS are real; a config key the client ignores is not."""
    text = RULES[rule_id].remediation.lower()
    assert "pin" in text, f"{rule_id} must still recommend the version pin"
    assert "tls" in text, f"{rule_id} must recommend protecting the channel"


@pytest.mark.parametrize("rule_id", TRANSPORT_FLIP_RULES)
def test_remediation_does_not_present_the_keys_as_the_fix(rule_id: str) -> None:
    """Guard the specific phrasing that made the old text misleading.

    The keys may still be *mentioned* — they have to be, since the rule
    short-circuits on them — but not as the thing that stops the attack.
    """
    text = RULES[rule_id].remediation
    for bad in (
        "so a MITM cannot flip the transport",
        "to prevent MITM transport-flip",
    ):
        assert bad not in text, f"{rule_id} still presents an AAK-only key as the fix"


def test_the_aak_only_keys_are_still_absent_from_the_corpus() -> None:
    """The measurement the remediation cites, kept honest.

    If a future MCP spec adopts any of these, this test fails and the
    remediation note should be revisited rather than left claiming they are
    unknown in the wild.
    """
    if not CORPUS.is_dir():
        pytest.skip("corpus not present in this checkout")
    configs = sorted(CORPUS.glob("*.json"))
    assert len(configs) > 100, f"corpus unexpectedly small ({len(configs)})"

    found: dict[str, int] = {}
    for path in configs:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for key in AAK_ONLY_KEYS:
            if key in text:
                found[key] = found.get(key, 0) + 1

    assert not found, (
        "an AAK-only transport key now appears in real MCP configs "
        f"({found}) — revisit the remediation note, it may no longer be true"
    )


def test_corpus_configs_are_real_mcp_configs() -> None:
    """Guard the guard: if the corpus stopped being MCP configs, the test above is vacuous."""
    if not CORPUS.is_dir():
        pytest.skip("corpus not present in this checkout")
    sample = sorted(CORPUS.glob("*.json"))[:50]
    with_servers = 0
    for path in sample:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and "mcpServers" in data:
            with_servers += 1
    assert with_servers > len(sample) // 2, (
        f"only {with_servers}/{len(sample)} sampled corpus files declare mcpServers"
    )
