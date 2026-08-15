"""Tree-sitter data-flow for AAK-MCP-STDIO-CMD-INJ-002 (#22).

The rule used to decide on proximity: a `new StdioClientTransport({...})` was
tainted if a network-controlled marker appeared anywhere in the preceding 1024
characters. That both over-fires (an unrelated source nearby) and under-fires (a
real source beyond the window).

What the rule reports is unchanged — same rule_id, severity, framework mappings.
Only the decision moved. These tests cover the two failure modes the old
heuristic had, the acceptance criteria in the issue, and the requirement that
the grammar stay optional.
"""

from __future__ import annotations

import builtins
import shutil
import sys
from pathlib import Path

import pytest

from agent_audit_kit.scanners import _ts_stdio_taint as taint
from agent_audit_kit.scanners.mcp_stdio_params import (
    _TS_STDIO_TRANSPORT_RE,
    _TS_TAINT_RE,
    scan,
)

RULE = "AAK-MCP-STDIO-CMD-INJ-002"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cves" / "ox-mcp-stdio-class"

_IMPORT = 'import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio";\n'


def _proximity_would_fire(text: str) -> bool:
    """The old heuristic, kept here to document what changed."""
    for m in _TS_STDIO_TRANSPORT_RE.finditer(text):
        if _TS_TAINT_RE.search(text[max(0, m.start() - 1024):m.start()]):
            return True
    return False


def _scan_source(tmp_path: Path, body: str, name: str = "server.ts") -> set[str]:
    (tmp_path / name).write_text(_IMPORT + body, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


requires_grammar = pytest.mark.skipif(
    not taint.available(), reason="tree-sitter TS grammar not installed"
)


# --- acceptance criteria from the issue -------------------------------------


@requires_grammar
def test_committed_vulnerable_fixture_fires() -> None:
    assert taint.find_tainted_sink((FIXTURES / "vulnerable_ts.ts").read_text()) is not None


@requires_grammar
def test_committed_patched_fixture_is_silent() -> None:
    assert taint.find_tainted_sink((FIXTURES / "patched_ts.ts").read_text()) is None


@requires_grammar
def test_unconnected_fixture_is_silent() -> None:
    """Source and sink both present, nothing flowing between them."""
    assert taint.find_tainted_sink((FIXTURES / "unconnected_ts.ts").read_text()) is None


def test_unconnected_fixture_is_the_case_proximity_got_wrong() -> None:
    """Documents why the fixture exists: the old heuristic fires on it."""
    src = (FIXTURES / "unconnected_ts.ts").read_text()
    assert _proximity_would_fire(src), "fixture no longer exercises the over-fire"


# --- the two failure modes --------------------------------------------------


@requires_grammar
def test_over_fire_is_fixed(tmp_path: Path) -> None:
    """An unrelated source next to a constant-fed sink must not fire."""
    body = (
        "export async function handler(req: any) {\n"
        "  const reason = req.body.reason;\n"
        "  await audit(reason);\n"
        '  return new StdioClientTransport({ command: "/usr/bin/server-a", args: [] });\n'
        "}\n"
    )
    assert RULE not in _scan_source(tmp_path, body)


@requires_grammar
def test_under_fire_is_fixed(tmp_path: Path) -> None:
    """A real source beyond the 1024-char window, reached via a helper."""
    body = (
        "function pickCommand(req: any) { return req.body.command; }\n"
        + "// an unrelated line of code\n" * 200
        + "export function handler(req: any) {\n"
        "  const cmd = pickCommand(req);\n"
        "  return new StdioClientTransport({ command: cmd, args: [] });\n"
        "}\n"
    )
    assert not _proximity_would_fire(_IMPORT + body), "source should be outside the old window"
    assert RULE in _scan_source(tmp_path, body)


# --- flow shapes the issue lists --------------------------------------------


@requires_grammar
@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("direct", "export function h(req: any) {\n"
                   "  return new StdioClientTransport({ command: req.body.command, args: [] });\n}\n"),
        ("assignment", "export function h(req: any) {\n"
                       "  const c = req.body.command;\n"
                       "  return new StdioClientTransport({ command: c, args: [] });\n}\n"),
        ("destructuring", "export function h(req: any) {\n"
                          "  const { command } = req.body;\n"
                          "  return new StdioClientTransport({ command, args: [] });\n}\n"),
        ("env", "export function h() {\n"
                "  const c = process.env.MCP_COMMAND;\n"
                "  return new StdioClientTransport({ command: c, args: [] });\n}\n"),
        ("json-parse", "export function h(raw: string) {\n"
                       "  const cfg = JSON.parse(raw);\n"
                       "  return new StdioClientTransport({ command: cfg.command, args: [] });\n}\n"),
        ("awaited-fetch", "export async function h(u: string) {\n"
                          "  const cfg = await fetch(u);\n"
                          "  return new StdioClientTransport({ command: cfg.command, args: [] });\n}\n"),
    ],
)
def test_tainted_flows_fire(label: str, body: str, tmp_path: Path) -> None:
    assert RULE in _scan_source(tmp_path, body), label


@requires_grammar
@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("constant", "export function h() {\n"
                     '  return new StdioClientTransport({ command: "/usr/bin/x", args: [] });\n}\n'),
        ("allowlist-table", "const OK: Record<string,string> = { a: \"/usr/bin/a\" };\n"
                            "export function h(name: string) {\n"
                            "  const c = OK[name];\n"
                            "  if (!c) throw new Error('no');\n"
                            "  return new StdioClientTransport({ command: c, args: [] });\n}\n"),
        ("no-sink", "export function h(req: any) {\n"
                    "  return req.body.command;\n}\n"),
    ],
)
def test_untainted_shapes_stay_silent(label: str, body: str, tmp_path: Path) -> None:
    assert RULE not in _scan_source(tmp_path, body), label


# --- the grammar must stay optional ----------------------------------------


def test_falls_back_to_proximity_when_the_grammar_is_absent(tmp_path: Path) -> None:
    """With tree-sitter unimportable, behaviour must match the old scan exactly
    and must not raise an import error."""
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name.startswith("tree_sitter"):
            raise ModuleNotFoundError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    saved = {m: sys.modules[m] for m in list(sys.modules) if m.startswith("tree_sitter")}
    try:
        builtins.__import__ = blocked
        for m in list(saved):
            sys.modules.pop(m, None)
        taint._load.cache_clear()
        assert taint.available() is False
        assert taint.find_tainted_sink(_IMPORT + "const x = 1;\n") is None

        work = tmp_path / "fb"
        work.mkdir()
        shutil.copy(FIXTURES / "vulnerable_ts.ts", work / "vulnerable_ts.ts")
        assert RULE in {f.rule_id for f in scan(work)[0]}

        clean = tmp_path / "fb2"
        clean.mkdir()
        shutil.copy(FIXTURES / "patched_ts.ts", clean / "patched_ts.ts")
        assert RULE not in {f.rule_id for f in scan(clean)[0]}
    finally:
        builtins.__import__ = real_import
        sys.modules.update(saved)
        taint._load.cache_clear()


def test_malformed_typescript_does_not_raise() -> None:
    assert taint.find_tainted_sink("export function ( {{{ unterminated") is None


@requires_grammar
def test_reported_rule_metadata_is_unchanged(tmp_path: Path) -> None:
    """This changed how the rule decides, not what it reports."""
    from agent_audit_kit.rules.builtin import RULES

    body = ("export function h(req: any) {\n"
            "  return new StdioClientTransport({ command: req.body.command, args: [] });\n}\n")
    (tmp_path / "s.ts").write_text(_IMPORT + body, encoding="utf-8")
    found = [f for f in scan(tmp_path)[0] if f.rule_id == RULE]
    assert found
    assert found[0].severity == RULES[RULE].severity
    assert found[0].category == RULES[RULE].category
