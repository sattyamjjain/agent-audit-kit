"""CVE-2026-37006 — WebSocket as a first-class MCP transport.

gpt-researcher <= 0.14.7 exposed a WebSocket endpoint that let an
unauthenticated remote attacker reach code execution through a malicious MCP
configuration. Triaged as deferred on 2026-09-02 with the note that it needs
"the transport rules widened ... to WebSocket ... the same claims over a
language and a transport the detectors do not currently read, so they get a
scanner path, not a second rule id."

What the audit actually found, measured rather than assumed:

* `AAK-MCP-001` (remote server without authentication) **already** treated a
  `ws://` URL as remote and unauthenticated. The "unauthenticated" half was
  covered.
* `AAK-TRANSPORT-001` (cleartext transport) did **not**. It matched `^http://`
  only, so a `ws://` MCP server was exempt from the project's cleartext rule
  while a byte-identical `http://` server was CRITICAL. That is the gap.

`ws://` is not a milder form of the defect. The handshake is an unencrypted
HTTP upgrade: credentials in its headers and every frame after it travel in
clear, exactly as over `http://`. `wss://` is the encrypted counterpart.

The rules in this family now each state which transports they apply to, so a
reader does not have to infer it from a regex. That was the second half of the
gap: the family assumed stdio-or-http and never said so.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.transport_security import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "websocket-transport"
RULE = "AAK-TRANSPORT-001"
_HIGH_CRIT = frozenset({"critical", "high"})


# --- should fire ------------------------------------------------------------


def test_cleartext_websocket_fires() -> None:
    findings, _ = scan(FIXTURES / "ws-cleartext")
    assert RULE in {f.rule_id for f in findings}


def test_cleartext_websocket_evidence_names_the_scheme_and_the_fix() -> None:
    """Evidence must be actionable: which scheme was seen, which to use."""
    findings, _ = scan(FIXTURES / "ws-cleartext")
    hit = next(f for f in findings if f.rule_id == RULE)
    assert "ws://" in (hit.evidence or "")
    assert "wss://" in (hit.evidence or "")


def test_cleartext_websocket_reaches_the_engine() -> None:
    """Registered path, not just the module under direct call."""
    hc = {
        f.rule_id
        for f in run_scan(FIXTURES / "ws-cleartext").findings
        if f.severity.value in _HIGH_CRIT
    }
    assert RULE in hc
    # The unauthenticated half was already covered; assert it stays covered.
    assert "AAK-MCP-001" in hc


# --- should not fire --------------------------------------------------------


def test_secure_websocket_passes() -> None:
    """`wss://` is the encrypted counterpart and must not be flagged."""
    findings, _ = scan(FIXTURES / "ws-secure")
    assert RULE not in {f.rule_id for f in findings}


def test_secure_websocket_has_no_high_critical_at_all() -> None:
    hc = [
        f
        for f in run_scan(FIXTURES / "ws-secure").findings
        if f.severity.value in _HIGH_CRIT
    ]
    assert not hc, f"benign wss:// server produced: {[f.rule_id for f in hc]}"


def test_loopback_websocket_is_excluded() -> None:
    """Loopback is excluded on `ws://` exactly as it is on `http://`.

    The traffic does not leave the host, so the cleartext rule has nothing to
    say about it. Widening the scheme must not narrow the loopback carve-out.
    """
    findings, _ = scan(FIXTURES / "ws-loopback")
    assert RULE not in {f.rule_id for f in findings}


# --- the http:// path must be unchanged -------------------------------------


def test_http_behaviour_is_unchanged(tmp_path: Path) -> None:
    """Widening to `ws://` must not alter the scheme the rule already had."""
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers":{"s":{"type":"http","url":"http://remote.example.com/mcp"}}}',
        encoding="utf-8",
    )
    assert RULE in {f.rule_id for f in scan(tmp_path)[0]}

    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers":{"s":{"type":"http","url":"https://remote.example.com/mcp"}}}',
        encoding="utf-8",
    )
    assert RULE not in {f.rule_id for f in scan(tmp_path)[0]}


# --- the family states its transports ---------------------------------------


def test_every_transport_rule_states_which_transports_it_applies_to() -> None:
    """The documentation half of the gap.

    A transport-sensitive rule that does not say which transports it covers
    leaves the reader to infer it, and the inference here was "stdio or http" —
    which is how WebSocket went unread for four rules at once.
    """
    for rid in (
        "AAK-TRANSPORT-001",
        "AAK-TRANSPORT-002",
        "AAK-TRANSPORT-003",
        "AAK-TRANSPORT-004",
    ):
        desc = RULES[rid].description
        assert "Applies to:" in desc, f"{rid} does not state its transports"
        assert "Does not apply to:" in desc, f"{rid} does not state its exclusions"
        assert "stdio" in desc, f"{rid} does not say where stdio stands"
