"""Reachability tests for ssrf_patterns (#593).

The rule used to decide file-wide: the word `fetch` anywhere plus a user-input
marker anywhere meant CRITICAL, with no requirement that either be code, be
related, or be near the other. Against AAK's own source that produced three
findings, all of them prose — a scanner description, a rule title, and the SSRF
scanner's own detection regex.

Each rule now hangs off a real outbound call site whose URL argument is traced.
The tests below are split into the two things that matter: prose must not fire,
and genuine data flow must still fire.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.scanners._ssrf_reach import analyze_js, analyze_python
from agent_audit_kit.scanners.ssrf_patterns import scan

# Every file must carry an MCP tool hint or the scanner skips it entirely.
_HINT = "from mcp.server.fastmcp import FastMCP\n"


def _ids(tmp_path: Path, name: str, body: str) -> set[str]:
    (tmp_path / name).write_text(_HINT + body, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


# --- the #593 reproduction --------------------------------------------------


def test_scanner_does_not_flag_its_own_source() -> None:
    """The regression that motivated this: AAK flagging its own detection patterns."""
    findings = scan(Path("agent_audit_kit"))[0]
    assert findings == [], (
        "ssrf_patterns fires on AAK's own source: "
        + ", ".join(f"{f.rule_id} {f.file_path}:{f.line_number}" for f in findings)
    )


def test_private_address_in_a_regex_literal_does_not_fire(tmp_path: Path) -> None:
    """The exact shape from ssrf_patterns.py:36 — a detection pattern, not a call."""
    body = (
        'import re\n'
        '_ADDR = re.compile(r"127\\.0\\.0\\.1|localhost|169\\.254\\.169\\.254")\n'
        'def check(text):\n'
        '    return bool(_ADDR.search(text))\n'
    )
    assert _ids(tmp_path, "patterns.py", body) == set()


def test_private_address_in_a_description_string_does_not_fire(tmp_path: Path) -> None:
    """The shape from engine.py:99 and builtin.py:451 — prose in a data structure."""
    body = (
        'SCANNERS = [\n'
        '    ("noauth", "Unauthenticated MCP server on 0.0.0.0 / wildcard CORS", []),\n'
        '    ("url", "MCP server URL points to localhost/internal network", []),\n'
        ']\n'
    )
    assert _ids(tmp_path, "registry.py", body) == set()


def test_user_input_and_fetch_in_the_same_file_but_unconnected(tmp_path: Path) -> None:
    """Both markers present, no flow between them — the old rule fired here."""
    body = (
        'import requests\n'
        'def log_request(request):\n'
        '    print(request.json)\n'
        'def health():\n'
        '    return requests.get("https://status.example.com/健康".encode().decode())\n'
    )
    ids = _ids(tmp_path, "svc.py", body)
    assert "AAK-SSRF-001" not in ids
    assert "AAK-SSRF-005" not in ids


# --- genuine flow must still fire ------------------------------------------


def test_direct_user_input_to_fetch_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'def tool(request):\n'
        '    return requests.get(request.json["url"])\n'
    )
    ids = _ids(tmp_path, "tool.py", body)
    assert "AAK-SSRF-001" in ids
    assert "AAK-SSRF-005" in ids


def test_user_input_through_a_variable_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'def tool(params):\n'
        '    target = params["endpoint"]\n'
        '    return requests.get(target)\n'
    )
    assert "AAK-SSRF-001" in _ids(tmp_path, "tool.py", body)


def test_user_input_through_an_fstring_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'def tool(args):\n'
        '    host = args["host"]\n'
        '    return requests.get(f"https://{host}/v1/data")\n'
    )
    assert "AAK-SSRF-001" in _ids(tmp_path, "tool.py", body)


def test_metadata_address_reaching_a_call_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'def creds():\n'
        '    return requests.get("http://169.254.169.254/latest/meta-data/iam/")\n'
    )
    assert "AAK-SSRF-003" in _ids(tmp_path, "meta.py", body)


def test_metadata_address_via_a_variable_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'METADATA = "http://169.254.169.254/latest/meta-data/"\n'
        'def creds():\n'
        '    return requests.get(METADATA)\n'
    )
    assert "AAK-SSRF-003" in _ids(tmp_path, "meta.py", body)


def test_allowlist_guard_clears_the_tainted_finding(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'ALLOWED_HOSTS = {"api.example.com"}\n'
        'def tool(params):\n'
        '    return requests.get(params["url"])\n'
    )
    assert "AAK-SSRF-005" not in _ids(tmp_path, "tool.py", body)


# --- backend units ----------------------------------------------------------


def test_python_backend_ignores_calls_that_are_not_fetches() -> None:
    sites = analyze_python('import os\ndef f(request):\n    os.getenv(request.json["k"])\n')
    assert sites == []


def test_python_backend_survives_a_syntax_error() -> None:
    """A file that does not parse must yield nothing, not raise."""
    assert analyze_python("def broken(:\n  pass\n") == []


def test_js_backend_resolves_a_single_hop() -> None:
    sites = analyze_js('const target = req.query.url;\nfetch(target);\n')
    assert sites and sites[0].tainted


def test_js_backend_ignores_a_commented_call() -> None:
    sites = analyze_js('// fetch(req.query.url)\nconst x = 1;\n')
    assert all(not s.tainted for s in sites)


@pytest.mark.parametrize("addr", ["127.0.0.1", "169.254.169.254", "192.168.1.5"])
def test_python_backend_finds_private_addresses_in_the_url_arg(addr: str) -> None:
    sites = analyze_python(f'import requests\nrequests.get("http://{addr}/x")\n')
    assert sites and sites[0].private_addr == addr


def test_python_backend_does_not_find_addresses_outside_a_call() -> None:
    sites = analyze_python('import requests\nDOC = "use 127.0.0.1 for local"\nrequests.get("https://a.example")\n')
    assert sites and sites[0].private_addr is None


# --- TS/JS: `//` inside a literal is not a comment ----------------------------
#
# The stripper was two regexes that did not know what a string is, so the `//` of
# every `http://` in a literal started a "comment" to the end of the line. The
# call lost its closing parenthesis and no call site was found: AAK-SSRF-002/003
# never saw a TS URL with a scheme, and 001/005 lost a caller-controlled host as
# soon as it followed `http://` in a template literal.

_TS_HEAD = (
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    'export const server = new McpServer({ name: "fetcher", version: "1.0.0" });\n'
)


def _ts_ids(tmp_path: Path, body: str) -> set[str]:
    (tmp_path / "tool.ts").write_text(_TS_HEAD + body, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


@pytest.mark.parametrize(("body", "rule_id"), [
    ('export const role = () => fetch("http://169.254.169.254/latest/meta-data/");\n', "AAK-SSRF-003"),
    ("export const admin = () => fetch('http://localhost:9000/admin'); // admin port\n", "AAK-SSRF-002"),
    ("export const f = (req: any) => fetch(`http://${req.query.host}/status`);\n", "AAK-SSRF-001"),
    ("export const f = (req: any) => fetch(`http://${req.query.host}/status`);\n", "AAK-SSRF-005"),
    ('export const f = (req: any) => fetch("http://" + req.query.host + "/status");\n', "AAK-SSRF-001"),
    ('const META = "http://169.254.169.254/latest/meta-data/";\n'
     "export const role = () => fetch(META);\n", "AAK-SSRF-003"),
    # a regex literal holding `//` must not eat the rest of its line either
    ('const norm = (p: string) => p.replace(/\\/\\//g, "/"); '
     "export const f = (req: any) => fetch(req.query.url);\n", "AAK-SSRF-001"),
])
def test_a_ts_url_with_a_scheme_is_read(tmp_path: Path, body: str, rule_id: str) -> None:
    assert rule_id in _ts_ids(tmp_path, body)


@pytest.mark.parametrize("body", [
    '// return fetch("http://169.254.169.254/latest/meta-data/");\nexport const x = 1;\n',
    "/* fetch(req.query.url) */ export const y = 2;\n",
    "export const re = /[\"']/; // fetch(req.query.url)\nexport const z = 3;\n",
    "export const half = (a: number, b: number) => (a + b) / 2; // fetch(req.query.url)\n",
    "let n = 4;\nexport const q = n++ / 2; // fetch(req.query.url)\n",
])
def test_a_ts_comment_is_not_a_call(tmp_path: Path, body: str) -> None:
    assert _ts_ids(tmp_path, body) == set()


def test_ts_comment_stripping_keeps_literals_and_layout() -> None:
    from agent_audit_kit.scanners._ssrf_reach import strip_comments

    src = (
        'const a = "http://x.example/*y"; // one\n'
        "const b = `http://${ok ? `${h}` : 'z'}/p`; /* two\n"
        "three */ const c = /^https?:\\/\\//; // four\n"
    )
    out = strip_comments(src, is_python=False)
    assert len(out) == len(src) and out.count("\n") == src.count("\n")
    assert '"http://x.example/*y"' in out
    assert "`http://${ok ? `${h}` : 'z'}/p`" in out
    assert "/^https?:\\/\\//" in out
    assert not any(word in out for word in ("one", "two", "three", "four"))


@pytest.mark.parametrize("unit", ['"//" ', "`${`${a}`}` ", "a / b // c\n", "/[/]/ ", "'\\'' /* x */ "])
def test_ts_comment_stripping_is_linear(unit: str) -> None:
    """Every search resumes where the last one stopped. 400 KB of the worst unit
    took well under a tenth of a second; the bound is loose for slow runners."""
    import time

    from agent_audit_kit.scanners._ssrf_reach import strip_comments

    src = unit * (400_000 // len(unit))
    started = time.perf_counter()
    strip_comments(src, is_python=False)
    assert time.perf_counter() - started < 5.0


def _js_arg(length: int) -> str:
    """A call argument of exactly ``length`` characters that names a request field."""
    return "'" + "a" * (length - 18) + "' + req.query.url"


@pytest.mark.parametrize(("source", "sites"), [
    ("fetch( req.query.url   );\n", [("fetch", 1, True, None)]),
    # The argument is read up to 200 characters before the closer's blanks.
    ("fetch(" + _js_arg(200) + ");\n", [("fetch", 1, True, None)]),
    ("fetch(" + _js_arg(201) + ");\n", []),
    ("fetch(" + _js_arg(199) + " " * 500 + ");\n", [("fetch", 1, True, None)]),
    ("fetch(req.query.url; got(req.body.u);\n", [("got", 1, True, None)]),
    ("fetch(fetch(req.query.url));\n", [("fetch", 1, True, None)]),
    ("axios.get(req.body.target, { timeout: 5 });\n", [("axios.get", 1, True, None)]),
    ("const base = '169.254.169.254/latest';\nfetch(base);\n", [("fetch", 2, False, "169.254.169.254")]),
])
def test_js_backend_call_shapes_keep_their_result(source: str, sites: list[tuple[object, ...]]) -> None:
    assert [tuple(s) for s in analyze_js(source)] == sites


_CRAFTED_JS = {
    # A call with a long blank run and no closer re-read the run once per
    # character before it: "fetch(" and 8,000 blanks took 32 seconds.
    "call-blanks": "fetch(" + " " * 500_000,
    "calls": "fetch(" * 83_000,
    # Every unclosed `/*` read on to the end of the file.
    "open-comments": "/* a" * 125_000,
    # Every character of a long word began an assignment read to its end.
    "word": "a" * 500_000,
    "blanks": " " * 500_000 + "x",
}


@pytest.mark.parametrize("shape", sorted(_CRAFTED_JS))
def test_a_crafted_js_file_scans_in_linear_time(tmp_path: Path, shape: str) -> None:
    """Just under the scanner's 512,000-byte file cap, with the MCP hint. The
    bound is loose for slow CI runners; each takes a fraction of a second."""
    import time

    body = _CRAFTED_JS[shape]
    assert len(_HINT + body) < 512_000
    started = time.perf_counter()
    _ids(tmp_path, "server.ts", body)
    assert time.perf_counter() - started < 5.0
