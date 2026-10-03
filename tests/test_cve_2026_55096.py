"""CVE-2026-55096 (#853): fast-mcp-telegram before 0.30.1, a hostname-only SSRF guard.

NVD: "Downloads are guarded by _validate_url_security, an SSRF denylist that
checks the URL's literal hostname string but never resolves DNS. The fetch
(httpx.AsyncClient.get) does its own resolution at request time."

Two answers, both measured:

- The version pin `AAK-MCP-FASTMCPTELEGRAM-CVE-2026-55096-001` reports releases
  below 0.30.1 (see tests/test_mcp_cve_pins_2026_07.py).
- `AAK-SSRF-TOCTOU-001` names the class, a guard on the hostname and then a
  fetch that resolves again, but it does not fire on the upstream code. Its name
  track is anchored at `^validate_...`, so the leading underscore of
  `_validate_url_security` fails it, and its body track needs a guard that
  resolves, which this one never does. The CVE is therefore not on that rule, and
  the gap is #855 rather than a widening here.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.ssrf_toctou import scan

FIXTURE = (
    Path(__file__).parent / "fixtures" / "cves" / "cve-2026-55096-fast-mcp-telegram" / "hostname-guard"
)
TOCTOU = "AAK-SSRF-TOCTOU-001"
PIN = "AAK-MCP-FASTMCPTELEGRAM-CVE-2026-55096-001"


def test_the_pin_carries_the_cve() -> None:
    assert RULES[PIN].cve_references == ["CVE-2026-55096"]


def test_the_class_rule_does_not_claim_it() -> None:
    """A CVE on a rule is a coverage claim, and this rule misses the upstream code."""
    assert "CVE-2026-55096" not in RULES[TOCTOU].cve_references


def test_the_upstream_guard_is_a_known_miss() -> None:
    """Recorded, not widened: #855. When that lands, this test flips."""
    findings, _ = scan(FIXTURE)
    assert findings == []
    assert TOCTOU not in {f.rule_id for f in run_scan(FIXTURE).findings}


def test_the_same_shape_fires_once_the_underscore_goes(tmp_path: Path) -> None:
    """The miss is the name track alone: rename the guard and the rule fires."""
    text = (FIXTURE / "server.py").read_text(encoding="utf-8")
    (tmp_path / "server.py").write_text(
        text.replace("_validate_url_security", "validate_url_security"), encoding="utf-8"
    )
    findings, _ = scan(tmp_path)
    assert [f.rule_id for f in findings] == [TOCTOU]
