from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import Any

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# A parametrize value longer than this gets a short id instead of its own text.
_MAX_PARAM_ID = 200
# No collected test id may be longer than this.
_MAX_NODEID = 500


def pytest_make_parametrize_id(config: pytest.Config, val: Any, argname: str) -> str | None:
    """Keep crafted inputs out of test ids.

    The linear-time tests feed megabyte-long strings through
    ``@pytest.mark.parametrize``, and pytest uses a string value as its own id.
    The collected ids came to 31 MB, and CI runs ``pytest -v``, which writes
    every id into the Actions log: the test jobs went from about 8 minutes to
    as many as 77. A long value now gets ``<argname>-<length>chars-<hash>``,
    unique per value, and short values keep their readable ids.
    """
    if isinstance(val, (str, bytes)) and len(val) > _MAX_PARAM_ID:
        raw = val.encode("utf-8", "surrogatepass") if isinstance(val, str) else val
        return f"{argname}-{len(val)}chars-{hashlib.sha256(raw).hexdigest()[:10]}"
    return None


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Fail collection when a test id grows past ``_MAX_NODEID`` characters.

    The hook above shortens long string parameters. A long id can still come
    from something it does not see (a long test name, a custom ``ids=``), so
    this refuses it outright rather than letting it reach the CI log.
    """
    long_ids = [item.nodeid for item in items if len(item.nodeid) > _MAX_NODEID]
    if long_ids:
        shown = ", ".join(f"{nodeid[:120]}... ({len(nodeid)} chars)" for nodeid in long_ids[:5])
        raise pytest.UsageError(
            f"{len(long_ids)} test id(s) are longer than {_MAX_NODEID} characters: {shown}. "
            "Give the parametrize case a short id (pytest.param(..., id=...))."
        )


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
