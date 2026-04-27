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


def test_atlassian_pin_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "cves" / "cve-2026-27825-atlassian" /
           "patched-pin" / "requirements.txt")
    (tmp_path / "requirements.txt").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8"
    )
    findings, _ = atlassian_scan(tmp_path)
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-MCP-ATLASSIAN-CVE-2026-27825-001" in rule_ids


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
