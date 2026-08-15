"""Tests for AAK-MCP-ATLASSIAN-CVE-2026-73498-001.

mcp-atlassian before 0.22.0 passes the client-supplied `file_path` of
`confluence_upload_attachment` straight to `open(file_path, "rb")` inside
`_upload_attachment_direct()` without calling `validate_safe_path`, so an
authenticated MCP client reads any file the server process can reach and
exfiltrates it to Confluence as an attachment.

Two detection paths, so both are covered here:
  - the dependency pin (`mcp_cve_pins_2026_07`), for a project that installs it;
  - the vendored source pattern (`mcp_atlassian`), for a project that copied or
    reimplemented the handler and so has no pin to read.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_atlassian import scan as scan_source
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import scan as scan_pins

RULE = "AAK-MCP-ATLASSIAN-CVE-2026-73498-001"
FIXTURES = (
    Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-73498-mcp-atlassian"
)


def _pin_ids(root: Path) -> set[str]:
    return {f.rule_id for f in scan_pins(root)[0]}


def _source_ids(root: Path) -> set[str]:
    return {f.rule_id for f in scan_source(root)[0]}


def _write(tmp_path: Path, name: str, content: str) -> Path:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return tmp_path


# --- rule registration ------------------------------------------------------


def test_rule_is_registered() -> None:
    assert RULE in RULES
    rule = RULES[RULE]
    assert rule.severity.value == "high"
    assert rule.category.value == "supply-chain"
    assert "CVE-2026-73498" in rule.cve_references


# --- fixtures ---------------------------------------------------------------


def test_fixtures_pin_positive_and_negative() -> None:
    assert RULE in _pin_ids(FIXTURES / "vulnerable")
    assert RULE not in _pin_ids(FIXTURES / "negative")


def test_fixtures_source_positive_and_negative() -> None:
    assert RULE in _source_ids(FIXTURES / "vulnerable")
    assert RULE not in _source_ids(FIXTURES / "negative")


# --- dependency-pin path ----------------------------------------------------


def test_pin_below_floor_fires(tmp_path: Path) -> None:
    assert RULE in _pin_ids(_write(tmp_path, "requirements.txt", "mcp-atlassian==0.21.1\n"))


def test_pin_at_floor_clears(tmp_path: Path) -> None:
    assert RULE not in _pin_ids(_write(tmp_path, "requirements.txt", "mcp-atlassian==0.22.0\n"))


def test_pin_above_floor_clears(tmp_path: Path) -> None:
    assert RULE not in _pin_ids(_write(tmp_path, "requirements.txt", "mcp-atlassian==0.23.0\n"))


def test_unpinned_mcp_config_fires(tmp_path: Path) -> None:
    cfg = '{"mcpServers": {"atlassian": {"command": "uvx", "args": ["mcp-atlassian"]}}}'
    assert RULE in _pin_ids(_write(tmp_path, ".mcp.json", cfg))


def test_uv_lock_at_floor_clears(tmp_path: Path) -> None:
    lock = '[[package]]\nname = "mcp-atlassian"\nversion = "0.22.0"\n'
    assert RULE not in _pin_ids(_write(tmp_path, "uv.lock", lock))


# --- vendored-source path ---------------------------------------------------


_VULNERABLE_SRC = (
    "def _upload_attachment_direct(base_url, page_id, file_path, token):\n"
    "    with open(file_path, \"rb\") as handle:\n"
    "        return requests.post(url, files={'file': handle})\n"
    "\n"
    "def confluence_upload_attachment(page_id: str, file_path: str):\n"
    "    return _upload_attachment_direct(base, page_id, file_path, tok)\n"
)


def test_vendored_handler_without_validation_fires(tmp_path: Path) -> None:
    assert RULE in _source_ids(_write(tmp_path, "attachments.py", _VULNERABLE_SRC))


def test_vendored_handler_with_validate_safe_path_clears(tmp_path: Path) -> None:
    src = _VULNERABLE_SRC.replace(
        "    with open(file_path, \"rb\") as handle:",
        "    safe = validate_safe_path(file_path, root)\n"
        "    with open(file_path, \"rb\") as handle:",
    )
    assert RULE not in _source_ids(_write(tmp_path, "attachments.py", src))


def test_unrelated_binary_open_is_not_flagged(tmp_path: Path) -> None:
    """No Confluence attachment handler in the file — another rule's territory."""
    src = "def load_blob(file_path):\n    with open(file_path, \"rb\") as fh:\n        return fh.read()\n"
    assert RULE not in _source_ids(_write(tmp_path, "blobs.py", src))
