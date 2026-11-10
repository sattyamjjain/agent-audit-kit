"""AAK-MCP-ENV-DUMP-001, -ERROR-LEAK-001, -ANNOTATION-MISMATCH-001 and -REQUESTSTATE-001.

The sources are fixture files, not strings here, so AAK's self-scan does not read these
shapes in this file.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_server_code import RULE_ANNOTATION, RULE_ENV, RULE_ERROR, RULE_STATE, scan

FIXTURES = Path(__file__).parent / "fixtures" / "mcp_server_code"
EVERYTHING = "@modelcontextprotocol/server-everything"


def _scan_one(tmp_path: Path, group: str, name: str) -> list[str]:
    shutil.copy(FIXTURES / group / name, tmp_path / name)
    return [f.rule_id for f in scan(tmp_path)[0]]


@pytest.mark.parametrize("group,name,rule", [
    ("env", "dump_direct.py", RULE_ENV), ("env", "dump_copy_read_only.py", RULE_ENV), ("env", "dump_spread.py", RULE_ENV),
    ("env", "dump.ts", RULE_ENV),
    ("errors", "tool_error.py", RULE_ERROR), ("errors", "mcp_error.py", RULE_ERROR), ("errors", "jsonrpc.py", RULE_ERROR),
    ("errors", "traceback_from_tool.py", RULE_ERROR), ("errors", "a2a_peer.py", RULE_ERROR),
    ("errors", "mcp_error.ts", RULE_ERROR),
    ("annotations", "read_only_writes.py", RULE_ANNOTATION), ("annotations", "read_only_appends.py", RULE_ANNOTATION),
    ("annotations", "not_destructive_deletes.py", RULE_ANNOTATION), ("annotations", "read_only_sql.py", RULE_ANNOTATION),
    ("annotations", "read_only_writes.ts", RULE_ANNOTATION),
    ("state", "trusted.py", RULE_STATE), ("state", "trusted.ts", RULE_STATE), ("state", "signed_unbound.py", RULE_STATE),
])
def test_each_firing_shape_fires_once(tmp_path: Path, group: str, name: str, rule: str) -> None:
    assert _scan_one(tmp_path, group, name) == [rule]


@pytest.mark.parametrize("group,name", [
    ("env", "one_variable.py"), ("env", "not_a_tool.py"), ("env", "spawn_env.ts"), ("env", "one_variable.ts"),
    ("errors", "fixed_message.py"), ("errors", "no_protocol.py"), ("errors", "tool_result.py"),
    ("errors", "fixed_message.ts"),
    ("annotations", "read_only_reads.py"), ("annotations", "not_destructive_appends.py"),
    ("annotations", "no_annotations.py"), ("annotations", "read_only_reads.ts"),
    ("state", "signed_bound.py"), ("state", "opaque_id.py"),
])
def test_each_quiet_shape_stays_quiet(tmp_path: Path, group: str, name: str) -> None:
    assert _scan_one(tmp_path, group, name) == []


def test_the_env_finding_says_read_only_when_it_is(tmp_path: Path) -> None:
    shutil.copy(FIXTURES / "env" / "dump_copy_read_only.py", tmp_path / "s.py")
    (finding,) = scan(tmp_path)[0]
    assert "annotated read-only" in finding.evidence and finding.line_number == 11
    (tmp_path / "s.py").unlink()
    shutil.copy(FIXTURES / "env" / "dump_direct.py", tmp_path / "s.py")
    (finding,) = scan(tmp_path)[0]
    assert "annotated read-only" not in finding.evidence


def _config(root: Path, spec: str, env: dict[str, str] | None = None, rel: str = ".mcp.json") -> list[str]:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    server: dict[str, object] = {"command": "npx", "args": ["-y", spec]}
    if env:
        server["env"] = env
    path.write_text(json.dumps({"mcpServers": {"e": server}}))
    return [f.evidence for f in scan(root)[0]]


@pytest.mark.parametrize("version,fires", [
    ("1.0.0", True), ("2.0.1", True), ("2026.8.31", True), ("2025.1.14", True), ("2.1.0", False), ("2.2.1", False),
])
def test_the_config_arm_reads_a_stated_release(tmp_path: Path, version: str, fires: bool) -> None:
    assert bool(_config(tmp_path, f"{EVERYTHING}@{version}")) is fires


def test_an_unpinned_launch_is_not_reported_since_latest_masks(tmp_path: Path) -> None:
    assert _config(tmp_path, EVERYTHING) == []


def test_the_opt_in_fires_on_any_release(tmp_path: Path) -> None:
    (evidence,) = _config(tmp_path, f"{EVERYTHING}@2.2.1", {"GET_ENV_INCLUDE_SECRETS": "true"})
    assert "GET_ENV_INCLUDE_SECRETS" in evidence


@pytest.mark.parametrize("rel", ["tests/.mcp.json", "examples/demo/.mcp.json", "fixtures/mcp.json"])
def test_a_config_in_a_test_or_example_directory_is_left_out(tmp_path: Path, rel: str) -> None:
    assert _config(tmp_path, f"{EVERYTHING}@2.0.1", rel=rel) == []


def test_the_unbound_state_says_what_is_missing(tmp_path: Path) -> None:
    shutil.copy(FIXTURES / "state" / "signed_unbound.py", tmp_path / "s.py")
    (finding,) = scan(tmp_path)[0]
    for part in ("the principal", "an expiry", "a digest of the request"):
        assert part in finding.evidence


@pytest.mark.parametrize("rule,severity,category", [
    (RULE_ENV, Severity.HIGH, Category.SECRET_EXPOSURE), (RULE_ERROR, Severity.MEDIUM, Category.MCP_CONFIG),
    (RULE_ANNOTATION, Severity.MEDIUM, Category.TOOL_POISONING), (RULE_STATE, Severity.HIGH, Category.TRUST_BOUNDARY),
])
def test_the_rules_are_registered_as_stated(rule: str, severity: Severity, category: Category) -> None:
    assert RULES[rule].severity is severity and RULES[rule].category is category
    assert RULES[rule].limitations.strip()
