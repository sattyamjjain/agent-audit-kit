"""Smoke tests for the 5 v0.3.8 rules."""

from __future__ import annotations

from pathlib import Path

import pytest

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


# A script that loads the event JSON reads the title as a subscript or a
# `.get()`, not an attribute path, so the usual form was no source at all.

_REVIEW = '''import json
import os

import anthropic

client = anthropic.Anthropic()


def review():
    with open(os.environ["GITHUB_EVENT_PATH"]) as fh:
        event = json.load(fh)
    title = @@TITLE@@
    return client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=200,
        messages=[{"role": "user", "content": "Review this change: " + title}],
    )
'''


@pytest.mark.parametrize("expr", [
    "event.pull_request.title",
    'event["pull_request"]["title"]',
    "event['pull_request']['title']",
    'event[ "pull_request" ] [ "title" ]',
    'event.get("pull_request", {}).get("title", "")',
    'event.get("pull_request").get("title")',
    'event["pull_request"].get("title")',
    'event.get("pull_request", {})["title"]',
    'event["issue"]["title"]',
    'event.get("issue", {}).get("title")',
    'event["pull_request"]["head"]["ref"]',
])
def test_prtitle_ipi_reads_the_title_however_the_event_is_read(tmp_path: Path, expr: str) -> None:
    (tmp_path / "review.py").write_text(_REVIEW.replace("@@TITLE@@", expr), encoding="utf-8")
    findings, scanned = prtitle_scan(tmp_path)
    assert [(f.rule_id, f.line_number) for f in findings] == [("AAK-PRTITLE-IPI-001", 12)]
    assert scanned == {"review.py"}


@pytest.mark.parametrize("expr", [
    'event["pull_request"]["body"]',
    'event.get("pull_request", {}).get("body")',
    'event["title"]',
    'event["pull_request"]["head"]["sha"]',
    'html.escape(event["pull_request"]["title"])',
])
def test_prtitle_ipi_other_fields_and_an_escaped_title_stay_silent(tmp_path: Path, expr: str) -> None:
    (tmp_path / "review.py").write_text(
        "import html\n" + _REVIEW.replace("@@TITLE@@", expr), encoding="utf-8"
    )
    assert prtitle_scan(tmp_path) == ([], set())


def test_prtitle_ipi_ts_reads_a_subscripted_title(tmp_path: Path) -> None:
    (tmp_path / "review.ts").write_text(
        'import Anthropic from "@anthropic-ai/sdk";\n'
        "const client = new Anthropic();\n"
        'const payload = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH!, "utf8"));\n'
        'const title = payload["pull_request"]["title"];\n'
        "await client.messages.create({ messages: [{ role: \"user\", content: title }] });\n",
        encoding="utf-8",
    )
    findings, _ = prtitle_scan(tmp_path)
    assert [(f.rule_id, f.line_number) for f in findings] == [("AAK-PRTITLE-IPI-001", 4)]


@pytest.mark.parametrize("text", [
    'x["pull_request"]' + " " * 1_000_000 + "y",
    'x.get("pull_request"' + "a" * 1_000_000,
    'x.get("pull_request", {})' * 100_000,
    '["pull_request"]["head"]' * 100_000,
])
def test_prtitle_ipi_reads_a_crafted_event_read_in_linear_time(tmp_path: Path, text: str) -> None:
    """The subscript and `.get()` forms: a key followed by 1 MB without the next
    key, and 100,000 keys in a row, in a TS file, which is matched whole."""
    import time

    (tmp_path / "review.ts").write_text(text + "\nclient.messages.create({})\n", encoding="utf-8")
    started = time.perf_counter()
    prtitle_scan(tmp_path)
    assert time.perf_counter() - started < 5.0


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


@pytest.mark.parametrize("requirements", [
    "\n" * 1_999_000 + "mcp-atlassian==0.16.2",
    "mcp-atlassian" + " " * 1_999_000 + "x",
])
def test_atlassian_pin_reads_a_crafted_manifest_in_linear_time(tmp_path: Path, requirements: str) -> None:
    """From every newline in a run of blank lines the pin pattern's `\\s*` read
    to the end of the run, so 40,000 blank lines took 6.7 seconds and the time
    grew with the square. The bound is loose for slow CI runners; the pin after the blank
    lines is still read, on its own line."""
    import time

    (tmp_path / "requirements.txt").write_text(requirements, encoding="utf-8")
    started = time.perf_counter()
    findings, _ = atlassian_scan(tmp_path)
    assert time.perf_counter() - started < 5.0
    lines = {f.line_number for f in findings if f.rule_id == _PIN_27825}
    assert lines == ({1_999_001} if requirements.endswith("0.16.2") else set())


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
