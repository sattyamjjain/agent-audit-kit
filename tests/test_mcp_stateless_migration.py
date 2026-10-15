"""AAK-MCP-STATELESS-001..004 — 2026-07-28 stateless-MCP migration tests."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_audit_kit.scanners import mcp_stateless_migration

FIXTURES = Path(__file__).parent / "fixtures" / "mcp_stateless"
RULE_001 = "AAK-MCP-STATELESS-001"
RULE_002 = "AAK-MCP-STATELESS-002"
RULE_003 = "AAK-MCP-STATELESS-003"
RULE_004 = "AAK-MCP-STATELESS-004"


def _copy(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in src.iterdir():
        target = dst / entry.name
        if entry.is_dir():
            _copy(entry, target)
        else:
            shutil.copy2(entry, target)


# --------------------------------------------------------------------------
# 001 — Mcp-Session-Id reliance
# --------------------------------------------------------------------------

def test_001_python_session_id_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_001_py", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_001]
    assert matches, "expected AAK-MCP-STATELESS-001 to fire on Mcp-Session-Id header read"
    assert any(m.file_path.endswith("server.py") for m in matches)


def test_001_typescript_session_id_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_001_ts", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_001]
    assert matches, "expected AAK-MCP-STATELESS-001 to fire on TS Mcp-Session-Id reference"
    assert any(m.file_path.endswith("server.ts") for m in matches)


def test_001_no_sdk_no_finding(tmp_path: Path) -> None:
    """No SDK declared — even if the literal appears, the rule must stay
    silent (matches the sampling-rule SDK gate)."""
    (tmp_path / "requirements.txt").write_text("click>=8.1\n", encoding="utf-8")
    (tmp_path / "notes.py").write_text(
        '# Reference: Mcp-Session-Id is removed in the 2026-07-28 RC\n',
        encoding="utf-8",
    )
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    assert not any(f.rule_id == RULE_001 for f in findings)


# --------------------------------------------------------------------------
# 002 — tasks/list usage
# --------------------------------------------------------------------------

def test_002_tasks_list_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_002_py", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_002]
    assert matches, "expected AAK-MCP-STATELESS-002 to fire on tasks/list dispatch"
    assert any(m.file_path.endswith("client.py") for m in matches)


def test_002_no_sdk_no_finding(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("click>=8.1\n", encoding="utf-8")
    (tmp_path / "client.py").write_text(
        'method = "tasks/list"\n',
        encoding="utf-8",
    )
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    assert not any(f.rule_id == RULE_002 for f in findings)


# --------------------------------------------------------------------------
# 003 — sticky-session / shared-store dependency
# --------------------------------------------------------------------------

def test_003_nginx_sticky_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_003_nginx", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_003]
    assert matches, "expected AAK-MCP-STATELESS-003 to fire on nginx ip_hash"
    assert any(m.file_path.endswith("nginx.conf") for m in matches)


def test_003_k8s_session_affinity_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_003_k8s", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_003]
    assert matches, "expected AAK-MCP-STATELESS-003 to fire on K8s sessionAffinity: ClientIP"


def test_003_session_store_code_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_003_store_py", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_003]
    assert matches, "expected AAK-MCP-STATELESS-003 to fire on session_store[session_id]"
    assert any(m.file_path.endswith("handlers.py") for m in matches)


@pytest.mark.parametrize(("conf", "line"), [
    ("# mcp gateway\nupstream mcp {\n    server a:8080;\n\n\n    ip_hash;\n}\n", 6),
    ("# mcp gateway\nupstream mcp {\n\n    sticky cookie srv_id expires=1h;\n}\n", 4),
    ("# mcp\nhttp:\n  services:\n    mcp:\n      loadBalancer:\n        sticky:   \n\n          cookie:\n", 6),
])
def test_003_sticky_finding_names_the_directive_line(tmp_path: Path, conf: str, line: int) -> None:
    """`^\\s*` let the nginx match start at the first blank line above the
    directive, so the finding named that line; Traefik's `sticky:` line is
    where its match always started."""
    (tmp_path / "gateway.conf").write_text(conf, encoding="utf-8")
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    assert [f.line_number for f in findings if f.rule_id == RULE_003] == [line]


_CRAFTED_INFRA = {
    # From every line start in a run of blank lines `^\\s*` read to the end of the run.
    "blank-lines": "# mcp\n" + "\n" * 1_999_000 + "x",
    # `sticky:` then `\\s*\\n\\s*` split a run of newlines at every newline.
    "traefik-newlines": "# mcp\nsticky:" + "\n" * 1_999_000 + "x",
}


@pytest.mark.parametrize("shape", sorted(_CRAFTED_INFRA))
def test_003_a_crafted_manifest_scans_in_linear_time(tmp_path: Path, shape: str) -> None:
    """A 2 MB manifest that mentions MCP, so the sticky patterns run. Before,
    40,000 blank lines took 1.2 seconds, 80,000 took 4.9, and the time grew
    with the square. The bound is loose for slow CI runners."""
    import time

    (tmp_path / "gateway.conf").write_text(_CRAFTED_INFRA[shape], encoding="utf-8")
    started = time.perf_counter()
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    assert time.perf_counter() - started < 5.0
    assert not any(f.rule_id == RULE_003 for f in findings)


def test_003_unrelated_k8s_manifest_quiet(tmp_path: Path) -> None:
    """A K8s manifest with sessionAffinity but no MCP mention and no MCP
    SDK in the project must not fire."""
    (tmp_path / "service.yaml").write_text(
        "apiVersion: v1\nkind: Service\nspec:\n  sessionAffinity: ClientIP\n",
        encoding="utf-8",
    )
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    assert not any(f.rule_id == RULE_003 for f in findings)


# --------------------------------------------------------------------------
# 004 — client no-cache + per-session state
# --------------------------------------------------------------------------

def test_004_client_no_cache_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_004_client", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_004]
    assert matches, "expected AAK-MCP-STATELESS-004 to fire on un-cached tools/list + session_id"
    assert any(m.file_path.endswith("client.py") for m in matches)


def test_004_cache_marker_suppresses(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n", encoding="utf-8")
    (tmp_path / "client.py").write_text(
        "from functools import lru_cache\n"
        "@lru_cache\n"
        "def fetch(session_id):\n"
        "    a = client.list_tools()\n"
        "    b = client.list_tools()\n"
        "    return a, b\n",
        encoding="utf-8",
    )
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    assert not any(f.rule_id == RULE_004 for f in findings)


def test_004_single_call_quiet(tmp_path: Path) -> None:
    """One call alone is not the hot-path pattern; rule requires ≥2 calls."""
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n", encoding="utf-8")
    (tmp_path / "client.py").write_text(
        "def init(session_id):\n    return client.list_tools()\n",
        encoding="utf-8",
    )
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    assert not any(f.rule_id == RULE_004 for f in findings)


# --------------------------------------------------------------------------
# Cross-cutting: documented-risk opt-out + OWASP mapping
# --------------------------------------------------------------------------

def test_documented_risk_suppresses_all(tmp_path: Path) -> None:
    _copy(FIXTURES / "documented_risk", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    stateless = [f for f in findings if f.rule_id.startswith("AAK-MCP-STATELESS-")]
    assert not stateless, (
        ".agent-audit-kit.yml accepts_stateless_migration_risk must suppress every "
        "STATELESS finding"
    )


def test_clean_python_no_findings(tmp_path: Path) -> None:
    _copy(FIXTURES / "clean_py", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    stateless = [f for f in findings if f.rule_id.startswith("AAK-MCP-STATELESS-")]
    assert not stateless


def test_findings_carry_owasp_mapping(tmp_path: Path) -> None:
    """A spec-migration finding names no OWASP risk, and says so by carrying none.

    STATELESS-001 flags code that will break when the protocol-level session goes
    away. It used to carry MCP07 (authentication), which is not what it detects;
    its framework link is the AICM controls instead.
    """
    _copy(FIXTURES / "vulnerable_001_py", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    match = next((f for f in findings if f.rule_id == RULE_001), None)
    assert match is not None
    assert match.owasp_mcp_references == []
    assert match.owasp_agentic_references == []
    assert match.aicm_references


def test_scanner_registered_in_engine() -> None:
    """Defensive: ensure the scanner is wired into the engine registry so
    `agent-audit-kit scan` actually runs it."""
    from agent_audit_kit.engine import _OPTIONAL_SCANNERS
    names = {name for name, _, _ in _OPTIONAL_SCANNERS}
    assert "mcp_stateless_migration" in names


# --------------------------------------------------------------------------
# The SDK gate. It took pyproject.toml only as the bare quoted "mcp", and cut
# a requirements line at its first `=`, so `"mcp[cli]>=1.2.0"`, Poetry's
# `mcp = "^1.2.0"` and `mcp~=1.2.0` never opened it: 001, 002 and 004 never ran
# for a typical Python server.
# --------------------------------------------------------------------------

_SESSION_SERVER = (
    "from mcp.server.fastmcp import FastMCP\n\n"
    'mcp = FastMCP("demo")\n\n\n'
    "def session_of(request):\n"
    '    return request.headers.get("Mcp-Session-Id")\n'
)


def _gate_fires(root: Path, manifest: str, text: str) -> bool:
    (root / manifest).write_text(text, encoding="utf-8")
    (root / "server.py").write_text(_SESSION_SERVER, encoding="utf-8")
    return any(f.rule_id == RULE_001 for f in mcp_stateless_migration.scan(root)[0])


@pytest.mark.parametrize(("manifest", "text"), [
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["mcp[cli]>=1.2.0"]\n'),
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["MCP>=1.2"]\n'),
    ("pyproject.toml", '[project]\nname = "d"\n[project.optional-dependencies]\nserver = ["mcp>=1.2"]\n'),
    ("pyproject.toml", '[dependency-groups]\ndev = ["mcp>=1.2", {include-group = "x"}]\n'),
    ("pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.10"\nmcp = "^1.2.0"\n'),
    ("pyproject.toml", '[tool.poetry.group.server.dependencies]\nmcp = {version = "^1.2", extras = ["cli"]}\n'),
    ("pyproject.toml", '[tool.uv]\ndev-dependencies = ["mcp>=1.2"]\n'),
    ("pyproject.toml", '[tool.pdm.dev-dependencies]\ndev = ["mcp>=1.2"]\n'),
    ("pyproject.toml", 'dependencies = ["mcp"\n'),  # unparsable: the old quoted test still opens it
    ("requirements.txt", "mcp~=1.2.0\n"),
    ("requirements.txt", 'mcp[cli]>=1.2 ; python_version >= "3.10"\n'),
    ("requirements.txt", "mcp @ https://files.example.com/mcp-1.2.0.tar.gz\n"),
    ("requirements-dev.txt", "MCP==1.2.0  # pinned\n"),
])
def test_the_sdk_gate_reads_real_manifests(tmp_path: Path, manifest: str, text: str) -> None:
    assert _gate_fires(tmp_path, manifest, text)


@pytest.mark.parametrize(("manifest", "text"), [
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["mcp-proxy>=0.3"]\n'),
    ("pyproject.toml", '[project]\nname = "demo-mcp"\ndependencies = ["fastmcp>=2.0"]\n'),
    ("requirements.txt", "mcp-server-git==0.6.2\n"),
    ("requirements.txt", "# mcp>=1.2\n-r mcp.txt\nclick>=8.1\n"),
])
def test_the_sdk_gate_stays_shut_for_other_distributions(
    tmp_path: Path, manifest: str, text: str
) -> None:
    assert not _gate_fires(tmp_path, manifest, text)


def test_the_sdk_gate_names_every_manifest_that_declares_it(tmp_path: Path) -> None:
    from agent_audit_kit.scanners._helpers import declares_mcp_sdk

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "d"\ndependencies = ["mcp[cli]>=1.2.0"]\n', encoding="utf-8"
    )
    (tmp_path / "requirements.txt").write_text("mcp~=1.2.0\n", encoding="utf-8")
    (tmp_path / "Cargo.toml").write_text('[dependencies]\nmcp = "0.1"\n', encoding="utf-8")
    assert declares_mcp_sdk(tmp_path) == (True, ["pyproject.toml", "requirements.txt", "Cargo.toml"])
    assert declares_mcp_sdk(tmp_path / "missing") == (False, [])
