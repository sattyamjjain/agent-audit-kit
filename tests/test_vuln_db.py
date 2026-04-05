"""Tests for agent_audit_kit.vuln_db module.

Covers load_database() (bundled, cached, fallback), update_database()
(success and failure paths), and cache file persistence.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from agent_audit_kit.vuln_db import load_database, update_database, BUNDLED_DB


# ---------------------------------------------------------------------------
# load_database
# ---------------------------------------------------------------------------


class TestLoadDatabase:
    def test_loads_bundled_db(self) -> None:
        db = load_database()
        assert isinstance(db, dict)
        assert "npm" in db

    def test_bundled_db_exists(self) -> None:
        assert BUNDLED_DB.is_file()

    def test_bundled_db_valid_json(self) -> None:
        data = json.loads(BUNDLED_DB.read_text())
        assert isinstance(data, dict)

    def test_returns_dict_with_expected_keys(self) -> None:
        db = load_database()
        assert "npm" in db
        assert "python" in db
        assert "rust" in db

    def test_prefers_cached_over_bundled(self, tmp_path: Path) -> None:
        cached = tmp_path / "vuln_db.json"
        cached.write_text(json.dumps({"npm": {"test-pkg": {"reason": "test"}}}))
        with patch("agent_audit_kit.vuln_db.CACHED_DB", cached):
            db = load_database()
        assert "test-pkg" in db.get("npm", {})

    def test_falls_back_when_cached_invalid(self, tmp_path: Path) -> None:
        cached = tmp_path / "vuln_db.json"
        cached.write_text("not valid json")
        with patch("agent_audit_kit.vuln_db.CACHED_DB", cached):
            db = load_database()
        assert isinstance(db, dict)

    def test_falls_back_to_bundled_when_cache_missing(self, tmp_path: Path) -> None:
        """When cached DB does not exist, bundled DB is used."""
        missing = tmp_path / "nonexistent.json"
        with patch("agent_audit_kit.vuln_db.CACHED_DB", missing):
            db = load_database()
        assert isinstance(db, dict)
        assert "npm" in db

    def test_returns_empty_structure_when_nothing_available(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.json"
        with patch("agent_audit_kit.vuln_db.CACHED_DB", missing), \
             patch("agent_audit_kit.vuln_db.BUNDLED_DB", missing):
            db = load_database()
        assert db == {"npm": {}, "python": {}, "rust": {}}

    def test_falls_back_when_cached_os_error(self, tmp_path: Path) -> None:
        """When cached DB read raises OSError, fallback to bundled."""
        cached = tmp_path / "vuln_db.json"
        cached.write_text(json.dumps({"npm": {"cached": {}}}))
        # Make the file unreadable by patching read_text
        with patch("agent_audit_kit.vuln_db.CACHED_DB", cached), \
             patch.object(Path, "read_text", side_effect=OSError("permission denied")):
            db = load_database()
        # Should still return a dict (either bundled fallback or empty default)
        assert isinstance(db, dict)


# ---------------------------------------------------------------------------
# update_database
# ---------------------------------------------------------------------------


class TestUpdateDatabase:
    def test_update_success(self, tmp_path: Path) -> None:
        mock_data = json.dumps({"npm": {"a": {}}, "python": {"b": {}}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        cache_dir = tmp_path / "cache"
        cached_db = cache_dir / "vuln_db.json"

        with patch("agent_audit_kit.vuln_db.CACHE_DIR", cache_dir), \
             patch("agent_audit_kit.vuln_db.CACHED_DB", cached_db), \
             patch("agent_audit_kit.vuln_db.urllib.request.urlopen", return_value=mock_resp):
            count = update_database()

        assert count == 2
        assert cached_db.is_file()

    def test_update_writes_correct_json(self, tmp_path: Path) -> None:
        """update_database should write valid JSON to cache path."""
        db_content = {"npm": {"pkg1": {"affected": "<1.0.0"}}, "python": {}, "rust": {}}
        mock_data = json.dumps(db_content).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        cache_dir = tmp_path / "cache"
        cached_db = cache_dir / "vuln_db.json"

        with patch("agent_audit_kit.vuln_db.CACHE_DIR", cache_dir), \
             patch("agent_audit_kit.vuln_db.CACHED_DB", cached_db), \
             patch("agent_audit_kit.vuln_db.urllib.request.urlopen", return_value=mock_resp):
            update_database()

        written = json.loads(cached_db.read_text())
        assert written == db_content

    def test_update_failure_returns_negative(self) -> None:
        with patch("agent_audit_kit.vuln_db.urllib.request.urlopen", side_effect=Exception("fail")):
            count = update_database()
        assert count == -1

    def test_update_creates_cache_directory(self, tmp_path: Path) -> None:
        """update_database should create the cache directory if it does not exist."""
        mock_data = json.dumps({"npm": {}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        cache_dir = tmp_path / "new" / "nested" / "dir"
        cached_db = cache_dir / "vuln_db.json"

        with patch("agent_audit_kit.vuln_db.CACHE_DIR", cache_dir), \
             patch("agent_audit_kit.vuln_db.CACHED_DB", cached_db), \
             patch("agent_audit_kit.vuln_db.urllib.request.urlopen", return_value=mock_resp):
            count = update_database()

        assert count >= 0
        assert cache_dir.is_dir()
        assert cached_db.is_file()

    def test_update_counts_entries_across_ecosystems(self, tmp_path: Path) -> None:
        """Total count should sum all entries across all ecosystem dicts."""
        db_content = {
            "npm": {"a": {}, "b": {}},
            "python": {"c": {}},
            "rust": {"d": {}, "e": {}, "f": {}},
        }
        mock_data = json.dumps(db_content).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        cache_dir = tmp_path / "cache"
        cached_db = cache_dir / "vuln_db.json"

        with patch("agent_audit_kit.vuln_db.CACHE_DIR", cache_dir), \
             patch("agent_audit_kit.vuln_db.CACHED_DB", cached_db), \
             patch("agent_audit_kit.vuln_db.urllib.request.urlopen", return_value=mock_resp):
            count = update_database()

        assert count == 6
