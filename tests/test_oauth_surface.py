"""Tests for the Vercel × Context.ai OAuth-surface scanner.

Task B from the v0.3.2 plan. Rules:
- AAK-OAUTH-SCOPE-001 — broad Workspace scopes to non-allowlisted client.
- AAK-OAUTH-3P-001    — repo depends on an agent-platform SDK.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from agent_audit_kit.scanners import oauth_surface

FIX = Path(__file__).parent / "fixtures" / "incidents" / "vercel-2026-04-19"


# ---------------------------------------------------------------------------
# AAK-OAUTH-SCOPE-001 — broad scopes without allowlist
# ---------------------------------------------------------------------------


def test_scope_rule_fires_on_broad_scopes(tmp_path: Path) -> None:
    shutil.copy(FIX / "app.yaml", tmp_path / "app.yaml")
    findings, scanned = oauth_surface.scan(tmp_path)
    assert "app.yaml" in scanned
    assert any(f.rule_id == "AAK-OAUTH-SCOPE-001" for f in findings)


def test_scope_rule_quiet_when_client_id_is_allowlisted(tmp_path: Path) -> None:
    shutil.copy(FIX / "app.yaml", tmp_path / "app.yaml")
    (tmp_path / ".aak-oauth-trust.yml").write_text(
        "trusted_client_ids:\n"
        "  - 999999999999-syntheticdemoclientidforaudit123.apps.googleusercontent.com\n"
    )
    findings, _ = oauth_surface.scan(tmp_path)
    assert not any(f.rule_id == "AAK-OAUTH-SCOPE-001" for f in findings)


def test_scope_rule_quiet_without_broad_scopes(tmp_path: Path) -> None:
    (tmp_path / "app.yaml").write_text(
        "runtime: python311\n"
        "env_variables:\n"
        '  OAUTH_SCOPES: "openid email profile"\n'
    )
    findings, _ = oauth_surface.scan(tmp_path)
    assert not any(f.rule_id == "AAK-OAUTH-SCOPE-001" for f in findings)


def test_scope_rule_fires_on_vercel_json(tmp_path: Path) -> None:
    (tmp_path / "vercel.json").write_text(
        json.dumps({
            "env": {
                "OAUTH_SCOPES": "https://www.googleapis.com/auth/drive",
                "CLIENT_ID": "111111111111-syntheticblahblahblah000000000000.apps.googleusercontent.com",
            }
        })
    )
    findings, _ = oauth_surface.scan(tmp_path)
    assert any(f.rule_id == "AAK-OAUTH-SCOPE-001" for f in findings)


# ---------------------------------------------------------------------------
# AAK-OAUTH-3P-001 — agent-platform SDK dependency detection
# ---------------------------------------------------------------------------


def test_3p_rule_fires_on_context_ai_in_package_json(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({
            "name": "my-app",
            "dependencies": {
                "context-ai": "^2.1.0",
                "express": "^4.18.0",
            },
        })
    )
    findings, _ = oauth_surface.scan(tmp_path)
    hits = [f for f in findings if f.rule_id == "AAK-OAUTH-3P-001"]
    assert hits
    assert any("context-ai" in f.evidence for f in hits)
    assert not any("express" in f.evidence for f in hits)


def test_3p_rule_fires_on_langsmith_in_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'name = "my-agent"\n'
        'dependencies = ["mcp>=0.9", "httpx"]\n'
    )
    findings, _ = oauth_surface.scan(tmp_path)
    hits = [f for f in findings if f.rule_id == "AAK-OAUTH-3P-001"]
    assert any("mcp" in f.evidence for f in hits)


def test_3p_rule_fires_on_requirements_txt(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "langsmith-py==0.3.0\n"
        "flask==3.0.0\n"
    )
    findings, _ = oauth_surface.scan(tmp_path)
    assert any(f.rule_id == "AAK-OAUTH-3P-001" and "langsmith" in f.evidence for f in findings)


def test_3p_rule_quiet_without_agent_platform_deps(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "dependencies": {"express": "^4"}})
    )
    findings, _ = oauth_surface.scan(tmp_path)
    assert not any(f.rule_id == "AAK-OAUTH-3P-001" for f in findings)


# ---------------------------------------------------------------------------
# Rule metadata: both rules tag the Vercel incident.
# ---------------------------------------------------------------------------


def test_rules_tag_vercel_incident() -> None:
    from agent_audit_kit.rules.builtin import RULES

    for rid in ("AAK-OAUTH-SCOPE-001", "AAK-OAUTH-3P-001"):
        rule = RULES[rid]
        assert "VERCEL-2026-04-19" in rule.incident_references
        assert "ASI04" in rule.owasp_agentic_references
        assert "MCP05:2025" in rule.owasp_mcp_references
