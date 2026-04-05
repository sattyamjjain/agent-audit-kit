from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a minimal temporary project directory."""
    return tmp_path


@pytest.fixture
def vulnerable_mcp_project(tmp_path: Path) -> Path:
    """Tmp project with vulnerable .mcp.json."""
    shutil.copy(FIXTURES_DIR / "vulnerable_mcp.json", tmp_path / ".mcp.json")
    return tmp_path


@pytest.fixture
def clean_mcp_project(tmp_path: Path) -> Path:
    """Tmp project with clean .mcp.json."""
    shutil.copy(FIXTURES_DIR / "clean_mcp.json", tmp_path / ".mcp.json")
    return tmp_path


@pytest.fixture
def vulnerable_settings_project(tmp_path: Path) -> Path:
    """Tmp project with vulnerable .claude/settings.json."""
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    shutil.copy(FIXTURES_DIR / "vulnerable_settings.json", claude_dir / "settings.json")
    return tmp_path


@pytest.fixture
def clean_settings_project(tmp_path: Path) -> Path:
    """Tmp project with clean .claude/settings.json."""
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    shutil.copy(FIXTURES_DIR / "clean_settings.json", claude_dir / "settings.json")
    return tmp_path


@pytest.fixture
def project_with_secrets(tmp_path: Path) -> Path:
    """Tmp project with secret-containing files."""
    shutil.copy(FIXTURES_DIR / "env_with_secrets", tmp_path / ".env")
    # Create a .gitignore WITHOUT .env
    (tmp_path / ".gitignore").write_text("node_modules/\ndist/\n")
    return tmp_path


@pytest.fixture
def project_with_package_risks(tmp_path: Path) -> Path:
    """Tmp project with risky package.json."""
    shutil.copy(FIXTURES_DIR / "package_with_risks.json", tmp_path / "package.json")
    return tmp_path
