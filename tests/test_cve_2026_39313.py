"""AAK-MCPFRAME-001 / CVE-2026-39313 tests."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from agent_audit_kit.scanners import transport_limits

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-39313"


def _copy_fixture(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in src.iterdir():
        if entry.is_file():
            shutil.copy2(entry, dst / entry.name)


def test_vulnerable_pin_fires(tmp_path: Path) -> None:
    _copy_fixture(FIXTURES / "vulnerable", tmp_path)
    findings, scanned = transport_limits.scan(tmp_path)
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-MCPFRAME-001" in rule_ids
    # both package.json and http.ts should register as scanned
    assert "package.json" in scanned


def test_patched_pin_is_quiet(tmp_path: Path) -> None:
    _copy_fixture(FIXTURES / "patched", tmp_path)
    findings, _ = transport_limits.scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCPFRAME-001" for f in findings)


def test_length_capped_impl_is_quiet(tmp_path: Path) -> None:
    _copy_fixture(FIXTURES / "length-capped", tmp_path)
    # Pair the safe TS with a patched pin.
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"mcp-framework": "0.2.22"}}),
        encoding="utf-8",
    )
    findings, _ = transport_limits.scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCPFRAME-001" for f in findings)


def test_body_accumulation_pattern_alone_fires(tmp_path: Path) -> None:
    # No package.json, just the vulnerable handler.
    (tmp_path / "server.ts").write_text(
        (FIXTURES / "vulnerable" / "http.ts").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    findings, _ = transport_limits.scan(tmp_path)
    assert any(f.rule_id == "AAK-MCPFRAME-001" for f in findings)
