"""Smoke tests for Phase 5 distribution artifacts."""

from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from agent_audit_kit.cli import cli


def test_install_precommit_creates_file(tmp_path: Path) -> None:
    runner = CliRunner()
    r = runner.invoke(cli, ["install-precommit", str(tmp_path)])
    assert r.exit_code == 0, r.output
    cfg = tmp_path / ".pre-commit-config.yaml"
    assert cfg.is_file()
    text = cfg.read_text()
    assert "agent-audit-kit" in text
    assert "rev: v0.3.0" in text


def test_install_precommit_is_idempotent(tmp_path: Path) -> None:
    runner = CliRunner()
    runner.invoke(cli, ["install-precommit", str(tmp_path)])
    r2 = runner.invoke(cli, ["install-precommit", str(tmp_path)])
    assert r2.exit_code == 0
    text = (tmp_path / ".pre-commit-config.yaml").read_text()
    assert text.count("id: agent-audit-kit") == 1


def test_install_precommit_appends_to_existing_config(tmp_path: Path) -> None:
    cfg = tmp_path / ".pre-commit-config.yaml"
    cfg.write_text(
        "repos:\n  - repo: https://github.com/psf/black\n    rev: 24.1.0\n    hooks:\n      - id: black\n"
    )
    runner = CliRunner()
    r = runner.invoke(cli, ["install-precommit", str(tmp_path)])
    assert r.exit_code == 0
    text = cfg.read_text()
    assert "black" in text
    assert "agent-audit-kit" in text


def test_gitlab_template_is_valid_yaml() -> None:
    path = Path("ci/gitlab/agent-audit-kit.gitlab-ci.yml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert "agent-audit-kit" in data
    assert ".agent-audit-kit" in data
    job = data["agent-audit-kit"]
    assert job.get("extends") == ".agent-audit-kit"


def test_version_is_bumped() -> None:
    from agent_audit_kit import __version__

    assert __version__ == "0.3.12"
