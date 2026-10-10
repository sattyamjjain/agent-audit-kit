"""Smoke tests for Phase 5 distribution artifacts."""

from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from agent_audit_kit import __version__
from agent_audit_kit.cli import cli


def test_install_precommit_creates_file(tmp_path: Path) -> None:
    runner = CliRunner()
    r = runner.invoke(cli, ["install-precommit", str(tmp_path)])
    assert r.exit_code == 0, r.output
    cfg = tmp_path / ".pre-commit-config.yaml"
    assert cfg.is_file()
    text = cfg.read_text()
    assert "agent-audit-kit" in text
    # The hook pins the release that wrote it. This asserted a literal
    # v0.3.0 for as long as the command hard-coded one.
    assert f"rev: v{__version__}\n" in text


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
    """The package version agrees with pyproject, which is the source of truth.

    This used to assert a hardcoded literal, so every release had to hand-edit a
    test file and the assertion could only ever disagree with a bump that had
    already happened -- it could not catch a missed one. Deriving it means the
    check is real and the release stops carrying a manual step. The wider
    invariant (pyproject <-> __version__ <-> the README `@vX.Y.Z` Action pins
    <-> the newest tag) is covered by tests/test_version_consistency.py.
    """
    import re
    from pathlib import Path

    from agent_audit_kit import __version__

    pyproject = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    declared = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    assert declared, 'pyproject.toml has no top-level version = "..."'
    assert __version__ == declared.group(1)
