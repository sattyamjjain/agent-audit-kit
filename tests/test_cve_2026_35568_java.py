"""CVE-2026-35568 — Java MCP SDK DNS rebinding.

`io.modelcontextprotocol.sdk:mcp-core` pre-0.11.0 shipped a
StreamableHTTP transport with no Host-header allow-list.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest

from agent_audit_kit.scanners.dns_rebind import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "dns-rebind-sdk-class"


def test_java_vulnerable_pom_fires() -> None:
    findings, _ = scan(FIXTURES / "java-vulnerable")
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-DNS-REBIND-002" in rule_ids


def test_java_patched_pom_passes() -> None:
    findings, _ = scan(FIXTURES / "java-patched")
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-DNS-REBIND-002" not in rule_ids


def test_java_gradle_vulnerable_pin_fires(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text(
        "dependencies {\n"
        "    implementation 'io.modelcontextprotocol.sdk:mcp-core:0.9.5'\n"
        "}\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-DNS-REBIND-002" for f in findings)


def test_java_gradle_patched_pin_passes(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text(
        "dependencies {\n"
        "    implementation 'io.modelcontextprotocol.sdk:mcp-core:0.11.0'\n"
        "}\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-DNS-REBIND-002" for f in findings)


# ---------------------------------------------------------------------------
# The pom.xml reader: capped like every manifest, and a DOCTYPE refused before
# expat sees it, since the entities a DOCTYPE declares are expanded as they are
# parsed (the "billion laughs") and only expat 2.4 and later bound that.
# ---------------------------------------------------------------------------

_DEPENDENCY = (
    "<dependencies><dependency><groupId>io.modelcontextprotocol.sdk</groupId>"
    "<artifactId>mcp-core</artifactId><version>0.10.0</version></dependency></dependencies>"
)


def _bomb(levels: int = 9) -> str:
    entities = '<!ENTITY e0 "aaaaaaaaaa">' + "".join(
        f'<!ENTITY e{i} "{f"&e{i - 1};" * 10}">' for i in range(1, levels)
    )
    return f'<!DOCTYPE project [{entities}]><project>{_DEPENDENCY}<name>&e{levels - 1};</name></project>'


def _scan_refusals(root: Path) -> tuple[set[str], dict[str, str]]:
    from agent_audit_kit.scanners._helpers import collecting_refusals

    with collecting_refusals() as refused:
        findings, _ = scan(root)
    return {f.rule_id for f in findings}, {Path(p).name: reason for p, reason in refused.items()}


@pytest.mark.parametrize("codec", ["utf-8", "utf-16"])
def test_a_pom_declaring_a_doctype_is_refused_and_not_parsed(tmp_path: Path, codec: str) -> None:
    header = f'<?xml version="1.0" encoding="{codec.upper()}"?>'
    (tmp_path / "pom.xml").write_bytes((header + _bomb()).encode(codec))
    started = time.perf_counter()
    rule_ids, refused = _scan_refusals(tmp_path)
    assert time.perf_counter() - started < 2.0
    assert "AAK-DNS-REBIND-002" not in rule_ids
    assert "DOCTYPE" in refused["pom.xml"], refused


def test_the_tree_builder_refuses_a_doctype_the_byte_search_misses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agent_audit_kit.scanners import dns_rebind

    monkeypatch.setattr(dns_rebind, "_POM_DOCTYPE", re.compile(b"(?!)"))
    (tmp_path / "pom.xml").write_text('<!DOCTYPE project><project>' + _DEPENDENCY + "</project>", encoding="utf-8")
    rule_ids, refused = _scan_refusals(tmp_path)
    assert "AAK-DNS-REBIND-002" not in rule_ids
    assert "DOCTYPE" in refused["pom.xml"], refused


def test_a_pom_over_the_manifest_cap_is_not_read(tmp_path: Path) -> None:
    padding = "<!-- " + "x" * 2_000_000 + " -->"
    (tmp_path / "pom.xml").write_text(f"<project>{_DEPENDENCY}{padding}</project>", encoding="utf-8")
    rule_ids, refused = _scan_refusals(tmp_path)
    assert "AAK-DNS-REBIND-002" not in rule_ids
    assert refused == {}


def test_a_latin1_pom_is_still_read_in_its_own_encoding(tmp_path: Path) -> None:
    pom = f'<?xml version="1.0" encoding="ISO-8859-1"?><project><name>caf\xe9</name>{_DEPENDENCY}</project>'
    (tmp_path / "pom.xml").write_bytes(pom.encode("latin-1"))
    rule_ids, refused = _scan_refusals(tmp_path)
    assert "AAK-DNS-REBIND-002" in rule_ids
    assert refused == {}


def test_the_rules_say_a_doctype_pom_is_refused() -> None:
    from agent_audit_kit.rules.builtin import get_rule

    assert "a pom.xml that declares a DOCTYPE" in get_rule("AAK-DNS-REBIND-002").limitations
    assert "a pom.xml that declares a DOCTYPE" in get_rule("AAK-INTERNAL-SCANNER-FAIL").description
