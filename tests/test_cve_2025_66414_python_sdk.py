"""CVE-2025-66414 / CVE-2025-66416 — Python MCP SDK DNS rebinding.

`mcp` Python SDK < 1.23.0 shipped a StreamableHTTP transport that trusted
the browser-supplied Host header. AAK-DNS-REBIND-002 is the pin check;
AAK-DNS-REBIND-001 is the pattern check for downstream servers embedding
StreamableHTTP without a Host allow-list.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.scanners.dns_rebind import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "dns-rebind-sdk-class"


def test_python_sdk_vulnerable_pin_fires() -> None:
    findings, _ = scan(FIXTURES / "python-vulnerable")
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-DNS-REBIND-002" in rule_ids


def test_python_sdk_patched_pin_passes() -> None:
    findings, _ = scan(FIXTURES / "python-patched")
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-DNS-REBIND-002" not in rule_ids


def test_python_streamable_unguarded_pattern_fires() -> None:
    findings, _ = scan(FIXTURES / "python-pattern-unguarded")
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-DNS-REBIND-001" in rule_ids


def test_python_streamable_guarded_pattern_passes() -> None:
    findings, _ = scan(FIXTURES / "python-pattern-guarded")
    rule_ids = {f.rule_id for f in findings}
    # Pattern rule should not fire when TrustedHostMiddleware present.
    assert "AAK-DNS-REBIND-001" not in rule_ids


# The pin took the first number after `mcp`, acted on `==`, `<` and `<=` only in a
# requirements file and on any operator in pyproject.toml, and had no place for
# extras or a Poetry table. It now reads both manifests as the CVE pin table does,
# so the same line gets the same answer in each, and a range is reported when it
# admits a release below 1.23.0.

_PYPROJECT = '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = [%s]\n'


def _rebind(root: Path) -> list[int | None]:
    return [f.line_number for f in scan(root)[0] if f.rule_id == "AAK-DNS-REBIND-002"]


@pytest.mark.parametrize(("spec", "fires"), [
    ("mcp<1.23.0", True),          # every release it admits is affected, and it read as the fix
    ("mcp>=1.0", True),            # a resolver may pick an affected release
    ("mcp>=1.2.0,<2", True),
    ("mcp>=1.23.0", False),
    ("mcp~=1.23", False),
    ("mcp[cli]==1.22.0", True),    # the SDK's own install line
    ("mcp[cli]>=1.23.0", False),
])
def test_requirements_and_pyproject_agree(tmp_path: Path, spec: str, fires: bool) -> None:
    (tmp_path / "req").mkdir()
    (tmp_path / "req" / "requirements.txt").write_text(spec + "\n", encoding="utf-8")
    (tmp_path / "pyp").mkdir()
    (tmp_path / "pyp" / "pyproject.toml").write_text(_PYPROJECT % json.dumps(spec), encoding="utf-8")
    assert bool(_rebind(tmp_path / "req")) is fires
    assert bool(_rebind(tmp_path / "pyp")) is fires


def test_poetry_table_is_read(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\nname = "demo"\n\n[tool.poetry.dependencies]\npython = "^3.10"\n'
        'mcp = { version = "1.22.0", extras = ["cli"] }\n', encoding="utf-8")
    assert _rebind(tmp_path) == [6]
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\npython = "^3.10"\nmcp = "^1.23.0"\n', encoding="utf-8")
    assert _rebind(tmp_path) == []


def test_unpinned_sdk_is_not_reported(tmp_path: Path) -> None:
    """An unpinned SDK installs a patched release; the pin reads a stated version only."""
    (tmp_path / "requirements.txt").write_text("mcp[cli]\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "latest"}}), encoding="utf-8")
    assert _rebind(tmp_path) == []


@pytest.mark.parametrize(("package", "spec", "fires"), [
    ("@modelcontextprotocol/sdk", "<1.21.1", True),   # read as the fix
    ("@modelcontextprotocol/sdk", "^1.21.1", False),
    ("@apollo/mcp-server", "<1.7.0", True),
    ("@apollo/mcp-server", ">=1.7.0 <2", False),
])
def test_npm_ranges_are_judged_by_what_they_admit(tmp_path: Path, package: str, spec: str, fires: bool) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {package: spec}}), encoding="utf-8")
    assert bool(_rebind(tmp_path)) is fires
