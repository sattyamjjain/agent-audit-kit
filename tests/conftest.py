from __future__ import annotations

import errno
import hashlib
import os
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


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep every test out of the developer's home directory.

    `test_update_command` runs `aak update`, which downloads the published
    vulnerability database and writes it to `~/.agent-audit-kit/vuln_db.json`,
    and `load_database()` reads that cache before the bundled copy. So each
    local run replaced the developer's cache, and every later run on any
    branch checked the rules against whatever main last published instead of
    the branch's own `data/vuln_db.json`. On 2026-10-17 that failed the
    AAK-SUPPLY-006 limitation test on branches older than #1020, which had
    dropped a row. CI never saw it because its home starts empty.

    HOME, and the paths modules computed from it at import time, point at an
    empty directory per test, so the tests read only the checkout's own data.
    A test that needs `gh`'s login (the live-tracker check in
    `test_cve_watcher_backpressure.py`) skips locally as it does in CI: the
    token lives in the macOS keychain, which `gh` does not find under this home.
    """
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("AAK_HOME", raising=False)
    from agent_audit_kit import feeds, vuln_db

    state = home / ".agent-audit-kit"
    monkeypatch.setattr(vuln_db, "CACHE_DIR", state)
    monkeypatch.setattr(vuln_db, "CACHED_DB", state / "vuln_db.json")
    monkeypatch.setattr(feeds, "_STATE_DIR", state)
    monkeypatch.setattr(feeds, "_STATE_FILE", state / "watch-state.json")
    monkeypatch.setattr(feeds, "_NVD_CACHE", state / "nvd-cache.json")
    return home


@pytest.fixture
def full_disk(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make `os.write` write 10 bytes, then fail with ENOSPC, as a full disk does.

    The AAK write helpers write through `os.write`; nothing else a test runs in
    process does, since Python's files write through their own C calls.
    """
    real, calls = os.write, []

    def write(fd: int, data: bytes) -> int:
        calls.append(fd)
        if len(calls) == 1:
            return real(fd, bytes(data[:10]))
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(os, "write", write)


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
