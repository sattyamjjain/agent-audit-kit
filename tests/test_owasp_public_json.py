"""public/owasp-agentic-coverage.json — schema + density + regen guard."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "gen_owasp_coverage.py"
JSON_PATH = REPO_ROOT / "public" / "owasp-agentic-coverage.json"


def _load_module():
    spec = importlib.util.spec_from_file_location("gen_owasp_coverage", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_owasp_coverage"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module", autouse=True)
def _regenerate(tmp_path_factory) -> None:
    module = _load_module()
    # Always regenerate into the canonical path before the assertions.
    rc = module.main([])
    assert rc == 0, "gen_owasp_coverage.py failed (coverage gap?)"


def test_json_file_exists() -> None:
    assert JSON_PATH.is_file(), (
        f"{JSON_PATH} missing. Run `python scripts/gen_owasp_coverage.py`."
    )


def test_schema_shape() -> None:
    payload = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1"
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", payload["last_updated"])
    assert isinstance(payload["aak_version"], str)
    assert isinstance(payload["rule_count"], int)
    assert isinstance(payload["coverage"], list)


def test_all_ten_slots_present() -> None:
    payload = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    ids = [row["asi_id"] for row in payload["coverage"]]
    assert ids == [f"ASI{i:02d}" for i in range(1, 11)]


def test_density_floor_three_per_slot() -> None:
    payload = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    for row in payload["coverage"]:
        assert row["rule_density"] >= 3, (
            f"{row['asi_id']} has density {row['rule_density']} < 3"
        )
        assert len(row["rules"]) == row["rule_density"]


def test_rule_entries_have_required_keys() -> None:
    payload = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    required = {"id", "severity", "cve_references", "aicm_references"}
    for row in payload["coverage"]:
        for rule in row["rules"]:
            assert required.issubset(rule.keys())
            assert isinstance(rule["cve_references"], list)
            assert isinstance(rule["aicm_references"], list)
            assert rule["severity"] in {"critical", "high", "medium", "low", "info"}
