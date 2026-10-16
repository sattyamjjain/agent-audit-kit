"""Tests never read or write the developer's home directory (see `tests/conftest.py`)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent_audit_kit import feeds, vuln_db


def _real_home() -> Path:
    pwd = pytest.importorskip("pwd")
    return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()


def test_the_vuln_db_cache_is_not_in_the_real_home() -> None:
    real = _real_home()
    for path in (vuln_db.CACHE_DIR, vuln_db.CACHED_DB, feeds._STATE_DIR, feeds._STATE_FILE, feeds._NVD_CACHE):
        assert real not in path.resolve().parents, path
    assert Path.home().resolve() != real


def test_aak_update_writes_into_the_isolated_home(monkeypatch: pytest.MonkeyPatch) -> None:
    """The download is stubbed; the point is where the file lands."""
    import io
    import json

    published = {"npm": {"left-pad": {"affected": "<1.3.0", "description": "x"}}, "python": {}, "rust": {}}

    def fake_urlopen(*_args: object, **_kwargs: object) -> io.BytesIO:
        return io.BytesIO(json.dumps(published).encode())

    monkeypatch.setattr(vuln_db.urllib.request, "urlopen", fake_urlopen)
    vuln_db.update_database()
    assert json.loads(vuln_db.CACHED_DB.read_text()) == published
    assert _real_home() not in vuln_db.CACHED_DB.resolve().parents
