"""AAK-MCPFRAME-001 / CVE-2026-39313 tests."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest

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


# The `+=` arm required a semicolon, so a reader written without one, as in
# StandardJS or any semicolon-free style, was silent while `chunks.push(chunk)`
# in the same style was reported.
_READER = 'import type {{ IncomingMessage }} from "node:http";\n\nexport function readRequestBody(req: IncomingMessage) {{\n  let body = "";\n  {handler}\n}}\n'


@pytest.mark.parametrize("handler", [
    'req.on("data", (chunk) => { body += chunk.toString() });',
    "req.on('data', (chunk) => {\n    body += chunk\n  })",
    "req.on('data', (chunk) => body += chunk)",
    "req.on('data', (chunk) => {\n    data += chunk.toString('utf8', 0, chunk.length)\n  })",
    "req.on('data', (chunk) => { body += chunk; });",
])
def test_an_accumulation_without_a_semicolon_fires(tmp_path: Path, handler: str) -> None:
    (tmp_path / "transport.ts").write_text(_READER.format(handler=handler), encoding="utf-8")
    findings, _ = transport_limits.scan(tmp_path)
    assert any(f.rule_id == "AAK-MCPFRAME-001" for f in findings)


def test_a_capped_reader_without_semicolons_is_quiet(tmp_path: Path) -> None:
    handler = (
        "req.on('data', (chunk) => {\n"
        "    total += chunk.length\n"
        "    if (total > 1048576) req.destroy()\n"
        "    body += chunk\n"
        "  })"
    )
    (tmp_path / "transport.ts").write_text(_READER.format(handler=handler), encoding="utf-8")
    findings, _ = transport_limits.scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCPFRAME-001" for f in findings)


def test_the_accumulation_pattern_reads_a_crafted_file_in_linear_time(tmp_path: Path) -> None:
    """1 MB of `body+=x.toString(` with no `)`. The `.toString(` arm read to
    the next `)` from every occurrence: 136 KB took 0.7 seconds and the time
    grew with the square. The bound is loose for slow CI runners."""
    (tmp_path / "transport.ts").write_text("readRequestBody\n" + "body+=x.toString(" * 60_000, encoding="utf-8")
    started = time.perf_counter()
    transport_limits.scan(tmp_path)
    assert time.perf_counter() - started < 5.0
