"""AAK-MCPFRAME-001 / CVE-2026-39313 tests."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Callable

import pytest

from agent_audit_kit.rules.builtin import RULES
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


@pytest.mark.parametrize(("handler", "fires"), [
    # A comment after a semicolon-free accumulation hid its line break.
    ("req.on('data', (chunk) => {\n    buf += chunk // keep appending\n  })", True),
    ("req.on('data', (chunk) => {\n    body += chunk /* more to come */\n  })", True),
    # A commented-out accumulation is not one.
    ("req.on('data', (chunk) => {\n    // body += chunk\n    stream.write(chunk)\n  })", False),
    # Only the names the limitation gives: `metadata` ends in `data`.
    ("req.on('data', (chunk) => { metadata += chunk; })", False),
    ("req.on('data', (chunk) => { metadata.push(chunk) })", False),
    ("req.on('data', (chunk) => { this.chunks.push(chunk) })", True),
    ("req.on('data', (chunk) => { this._body += chunk; })", True),
    ("req.on('data', (chunk) => { meta_data += chunk; })", False),
])
def test_the_accumulation_is_read_as_code(tmp_path: Path, handler: str, fires: bool) -> None:
    (tmp_path / "transport.ts").write_text(_READER.format(handler=handler), encoding="utf-8")
    findings, _ = transport_limits.scan(tmp_path)
    assert any(f.rule_id == "AAK-MCPFRAME-001" for f in findings) is fires


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


# Two patterns read on to the next `)` from every place they started: the
# request-body gate from each `req.on('data',`, and the `+=` arm from each
# `.toString(`. A file of either with no `)` took time that grew with the square
# of its size, 1 MB about 20 seconds. Each shape runs at two sizes, best of
# three, and the larger may take 40 times the smaller's time for 10 times the
# text (the old patterns needed 100 times) plus a fixed slack, under an absolute
# bound that is loose for slow CI runners.
_CRAFTED = {
    "data-handlers": lambda k: "req.on('data'," * k,
    "tostring-calls": lambda k: "readRequestBody\n" + "body+=x.toString(" * k,
}


def _seconds(run: Callable[[], object]) -> float:
    """Best of three, so one descheduled run cannot fail a timing test."""
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        run()
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("shape", sorted(_CRAFTED))
def test_a_crafted_file_scans_in_linear_time(tmp_path: Path, shape: str) -> None:
    roots = []
    for name, k in (("small", 6_000), ("large", 60_000)):
        root = tmp_path / name
        root.mkdir()
        (root / "transport.ts").write_text(_CRAFTED[shape](k), encoding="utf-8")
        roots.append(root)
    t_small = _seconds(lambda: transport_limits.scan(roots[0]))
    t_large = _seconds(lambda: transport_limits.scan(roots[1]))
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


def test_the_request_body_gate_still_reads_a_handler(tmp_path: Path) -> None:
    """The gate looks for the handler's first `)` within 1,024 characters of
    `req.on('data',`. On 88,502 TS/JS files it came at most 36 after the comma."""
    rx = transport_limits._BODY_CONCAT_RE
    for handler in (
        "req.on('data', (chunk) => {",
        'req.on("data", function onData(chunk) {',
        "req.on('data', onData);",
        "req.on( 'data' ,\n  chunk => { body += chunk; if (body.length > 9) req.destroy() })",
        "for await (const chunk of req) {",
        "for await (const part of req.body) {",
    ):
        assert rx.search(handler), handler
    assert not rx.search("req.on('end', () => resolve(body))")
    assert rx.search("req.on('data'," + " " * 1_018 + "(chunk) => {")  # 1,024 characters before the `)`
    assert not rx.search("req.on('data'," + " " * 1_019 + "(chunk) => {")  # 1,025
    assert "more than 1,024 characters after the comma" in RULES["AAK-MCPFRAME-001"].limitations
