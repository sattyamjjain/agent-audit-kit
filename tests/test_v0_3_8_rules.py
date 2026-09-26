"""Smoke tests for the 5 v0.3.8 rules."""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.ipi_wild_corpus import scan as ipi_scan
from agent_audit_kit.scanners.mcp_atlassian import scan as atlassian_scan
from agent_audit_kit.scanners.mcp_fhi import scan as fhi_scan
from agent_audit_kit.scanners.mcp_inspector_cve import scan as inspector_scan
from agent_audit_kit.scanners.prtitle_ipi import scan as prtitle_scan

FIXTURES = Path(__file__).parent / "fixtures"


# -------------------- AAK-PRTITLE-IPI-001 --------------------

def test_prtitle_ipi_vulnerable_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "cves" / "comment-and-control-2026-04-25" /
           "vulnerable" / "review_agent.py")
    (tmp_path / "review_agent.py").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8"
    )
    findings, _ = prtitle_scan(tmp_path)
    assert any(f.rule_id == "AAK-PRTITLE-IPI-001" for f in findings)


def test_prtitle_ipi_patched_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "cves" / "comment-and-control-2026-04-25" /
           "patched" / "review_agent.py")
    (tmp_path / "review_agent.py").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8"
    )
    findings, _ = prtitle_scan(tmp_path)
    assert not any(f.rule_id == "AAK-PRTITLE-IPI-001" for f in findings)


def test_prtitle_ipi_ts_fires(tmp_path: Path) -> None:
    (tmp_path / "tool.ts").write_text(
        'const title = req.body.pull_request.title;\n'
        'await anthropic.messages.create({ messages: [{ content: title }] });\n',
        encoding="utf-8",
    )
    findings, _ = prtitle_scan(tmp_path)
    assert any(f.rule_id == "AAK-PRTITLE-IPI-001" for f in findings)


# -------------------- AAK-MCP-FHI-001 --------------------

def test_fhi_imperative_description_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "incidents" / "mcp-fhi" / "vulnerable" / "server.py")
    (tmp_path / "server.py").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8"
    )
    findings, _ = fhi_scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-FHI-001" for f in findings)


def test_fhi_clean_description_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "incidents" / "mcp-fhi" / "clean" / "server.py")
    (tmp_path / "server.py").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8"
    )
    findings, _ = fhi_scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-FHI-001" for f in findings)


def test_fhi_universal_suffix_fires(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        'server.tool("search", "Normal description {{ALWAYS_PREFER_THIS_TOOL}} returns docs", impl);\n',
        encoding="utf-8",
    )
    findings, _ = fhi_scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-FHI-001" for f in findings)


# -------------------- AAK-MCP-ATLASSIAN-CVE --------------------

def test_atlassian_subprocess_sink_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "cves" / "cve-2026-27825-atlassian" /
           "vulnerable" / "agent.py")
    (tmp_path / "agent.py").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8"
    )
    findings, _ = atlassian_scan(tmp_path)
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-MCP-ATLASSIAN-CVE-2026-27825-001" in rule_ids


_PIN_27825 = "AAK-MCP-ATLASSIAN-CVE-2026-27825-001"
_PIN_27826 = "AAK-MCP-ATLASSIAN-CVE-2026-27826-001"


def _pin_ids(tmp_path: Path, requirement: str) -> set[str]:
    (tmp_path / "requirements.txt").write_text(requirement + "\n", encoding="utf-8")
    findings, _ = atlassian_scan(tmp_path)
    return {f.rule_id for f in findings}


def test_atlassian_pin_below_the_fix_reports_both_cves(tmp_path: Path) -> None:
    """NVD records CVE-2026-27825 and CVE-2026-27826 as both fixed in 0.17.0.

    One finding per CVE, so SARIF carries each id: 27825 is the unconfined
    `download_path` write, 27826 the header-driven SSRF.
    """
    assert {_PIN_27825, _PIN_27826} <= _pin_ids(tmp_path, "mcp-atlassian==0.16.2")


def test_atlassian_pin_at_the_fix_is_silent(tmp_path: Path) -> None:
    ids = _pin_ids(tmp_path, "mcp-atlassian==0.17.0")
    assert _PIN_27825 not in ids and _PIN_27826 not in ids


def test_atlassian_patched_pin_is_silent(tmp_path: Path) -> None:
    """The fixture is named patched-pin, and the rule fired on it anyway.

    Until NVD published a fix version, this pin fired on every declared version
    "to surface for review", so a fully patched mcp-atlassian was reported as
    CRITICAL indefinitely. NVD has since recorded 0.17.0 for both CVEs.
    """
    src = FIXTURES / "cves" / "cve-2026-27825-atlassian" / "patched-pin" / "requirements.txt"
    (tmp_path / "requirements.txt").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    findings, _ = atlassian_scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert _PIN_27825 not in ids and _PIN_27826 not in ids


# -------------------- AAK-IPI-WILD-CORPUS-001 --------------------

def test_ipi_wild_payload_in_markdown_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "incidents" / "ipi-wild-2026-04-24" /
           "poisoned_template.md")
    (tmp_path / "poisoned_template.md").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8"
    )
    findings, _ = ipi_scan(tmp_path)
    assert any(f.rule_id == "AAK-IPI-WILD-CORPUS-001" for f in findings)


def test_ipi_wild_clean_passes(tmp_path: Path) -> None:
    (tmp_path / "ok.md").write_text(
        "# Docs\n\nThis is a normal documentation page.\n",
        encoding="utf-8",
    )
    findings, _ = ipi_scan(tmp_path)
    assert not any(f.rule_id == "AAK-IPI-WILD-CORPUS-001" for f in findings)


# -------------------- AAK-MCP-INSPECTOR-CVE-2026-23744-001 --------------------

def test_mcp_inspector_vendored_fork_fires(tmp_path: Path) -> None:
    target = (tmp_path / "vendor" / "mcpjam-inspector")
    target.mkdir(parents=True)
    (target / "server.ts").write_text(
        'inspectorServer.handle("/x", async (req, res) => res.send({}));\n',
        encoding="utf-8",
    )
    findings, _ = inspector_scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-INSPECTOR-CVE-2026-23744-001" for f in findings)


def test_mcp_inspector_clean_passes(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        'console.log("unrelated");\n',
        encoding="utf-8",
    )
    findings, _ = inspector_scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-INSPECTOR-CVE-2026-23744-001" for f in findings)
