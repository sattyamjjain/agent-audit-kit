"""Smoke tests for the v0.3.9 rules (4 SAST scanners + autofix codemod)."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import agent_audit_kit
from agent_audit_kit.autofix.langgraph_toolnode import fix as autofix_toolnode
from agent_audit_kit.models import Finding
from agent_audit_kit.scanners import deepseek_v4_tool_injection
from agent_audit_kit.scanners.deepseek_v4_tool_injection import scan as deepseek_scan
from agent_audit_kit.scanners.langgraph_toolnode import scan as langgraph_scan
from agent_audit_kit.scanners.project_deal_drift import scan as deal_scan
from agent_audit_kit.scanners.social_agent_hijack import scan as social_scan

FIXTURES = Path(__file__).parent / "fixtures"


# -------------------- AAK-PROJECT-DEAL-DRIFT-001 --------------------

def test_project_deal_drift_vulnerable_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "project_deal" / "vulnerable" / "pricer.py").read_text()
    (tmp_path / "pricing").mkdir()
    (tmp_path / "pricing" / "pricer.py").write_text(src, encoding="utf-8")
    findings, _ = deal_scan(tmp_path)
    assert any(f.rule_id == "AAK-PROJECT-DEAL-DRIFT-001" for f in findings)


def test_project_deal_drift_safe_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "project_deal" / "safe" / "pricer.py").read_text()
    (tmp_path / "pricing").mkdir()
    (tmp_path / "pricing" / "pricer.py").write_text(src, encoding="utf-8")
    findings, _ = deal_scan(tmp_path)
    assert not any(f.rule_id == "AAK-PROJECT-DEAL-DRIFT-001" for f in findings)


def test_project_deal_drift_non_commerce_passes(tmp_path: Path) -> None:
    """No commerce hint + non-commerce path → must not fire."""
    (tmp_path / "set_price.py").write_text(
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "def set_price(item, model):\n"
        "    return client.messages.create(model=model, messages=[])\n",
        encoding="utf-8",
    )
    findings, _ = deal_scan(tmp_path)
    assert not any(f.rule_id == "AAK-PROJECT-DEAL-DRIFT-001" for f in findings)


def test_project_deal_drift_constant_model_passes(tmp_path: Path) -> None:
    """Hard-coded model literal is single-tier; no parity drift class."""
    (tmp_path / "pricing").mkdir()
    (tmp_path / "pricing" / "p.py").write_text(
        "import stripe\n"
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "def set_price(item):\n"
        "    return client.messages.create(model='claude-opus-4-7', messages=[])\n",
        encoding="utf-8",
    )
    findings, _ = deal_scan(tmp_path)
    assert not any(f.rule_id == "AAK-PROJECT-DEAL-DRIFT-001" for f in findings)


# -------------------- AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001 --------------------

def test_langgraph_toolnode_positional_list_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "langgraph" / "vulnerable" / "graph.py").read_text()
    (tmp_path / "graph.py").write_text(src, encoding="utf-8")
    findings, _ = langgraph_scan(tmp_path)
    assert sum(
        1 for f in findings
        if f.rule_id == "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001"
    ) == 2


def test_langgraph_toolnode_kwargs_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "langgraph" / "safe" / "graph.py").read_text()
    (tmp_path / "graph.py").write_text(src, encoding="utf-8")
    findings, _ = langgraph_scan(tmp_path)
    assert not any(
        f.rule_id == "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001"
        for f in findings
    )


def test_langgraph_toolnode_unrelated_class_passes(tmp_path: Path) -> None:
    """ToolNode call without the langgraph.prebuilt import gate must not fire."""
    (tmp_path / "other.py").write_text(
        "class ToolNode:\n    pass\n"
        "node = ToolNode([1, 2, 3])\n",
        encoding="utf-8",
    )
    findings, _ = langgraph_scan(tmp_path)
    assert not any(
        f.rule_id == "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001"
        for f in findings
    )


def test_langgraph_toolnode_autofix_idempotent() -> None:
    src = "node = ToolNode([a, b])\n"
    once = autofix_toolnode(src)
    twice = autofix_toolnode(once)
    assert once == "node = ToolNode(tools=[a, b])\n"
    assert once == twice


# -------------------- AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001 --------------------

def _read(root: Path, text: str) -> list[Finding]:
    """The DeepSeek reader on one file's text, called directly, so no file-size cap applies."""
    return deepseek_v4_tool_injection._walk_python(text, root / "app.py", root, set())


def test_deepseek_v4_tool_injection_vulnerable_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "deepseek" / "vulnerable" / "agent.py").read_text()
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    findings, _ = deepseek_scan(tmp_path)
    assert any(f.rule_id == "AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001" for f in findings)


def test_deepseek_v4_sanitizer_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "deepseek" / "safe" / "agent.py").read_text()
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    findings, _ = deepseek_scan(tmp_path)
    assert not any(
        f.rule_id == "AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001" for f in findings
    )


_DEEPSEEK = '''import re

from flask import request
from openai import OpenAI

client = OpenAI(base_url="https://api.deepseek.com", api_key="x")


def answer():
    doc = request.json["doc"]
@@SUB@@    return client.chat.completions.create(
        model="deepseek-chat",
        messages=[],
        tools=[{"type": "function", "function": {"name": "lookup", "description": doc}}],
    )
'''


@pytest.mark.parametrize("sub", [
    # Whitespace, tags, control characters and a character allow-list: none
    # removes the routing tokens, so none is the sanitiser the rule asks for.
    '    doc = re.sub(r"\\s+", " ", doc)\n',
    '    doc = re.sub(r"<[^>]+>", "", doc)\n',
    '    doc = re.sub(r"[\\x00-\\x1f\\x7f]", "", doc)\n',
    "    doc = re.sub(r'[^A-Za-z0-9 .,]', '', doc)\n",
    '    doc = re.sub(pattern, "", doc)\n',
])
def test_deepseek_v4_a_substitution_that_leaves_routing_tokens_does_not_clear_it(
    tmp_path: Path, sub: str
) -> None:
    (tmp_path / "app.py").write_text(_DEEPSEEK.replace("@@SUB@@", sub), encoding="utf-8")
    findings, _ = deepseek_scan(tmp_path)
    assert [f.rule_id for f in findings] == ["AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001"]


@pytest.mark.parametrize("sub", [
    '    doc = re.sub(r"\\[\\s*ROUTE\\s*:[^\\]]*\\]", "", doc)\n',
    '    doc = re.sub(r"<\\|\\s*route_id\\s*\\|>|__route__\\s*=", "", doc)\n',
    "    doc = re.sub(r'\\{\\{?\\s*Expert\\s*:[^}]*\\}?\\}?', '[REDACTED]', doc, flags=re.I)\n",
    '    doc = re.sub(\n        r"\\[ROUTE:[^\\]]*\\]", "", doc\n    )\n',
    '    doc = sanitize_tool_description(doc)\n',
])
def test_deepseek_v4_a_substitution_aimed_at_routing_tokens_clears_it(tmp_path: Path, sub: str) -> None:
    (tmp_path / "app.py").write_text(_DEEPSEEK.replace("@@SUB@@", sub), encoding="utf-8")
    assert deepseek_scan(tmp_path)[0] == []


def test_deepseek_v4_reads_a_crafted_substitution_in_linear_time(tmp_path: Path) -> None:
    """`re.sub("` and 1 MB with no routing word and no closing quote, then
    100,000 more `re.sub(`, inside one function. They sit in comments so the
    file parses on every Python, and the finding still firing shows the
    sanitiser pattern read them and did not count them."""
    crafted = '    # re.sub("' + "a" * 1_000_000 + "\n" + "    # re.sub(\n" * 100_000
    started = time.perf_counter()
    findings = _read(tmp_path, _DEEPSEEK.replace("@@SUB@@", crafted))
    assert time.perf_counter() - started < 5.0
    assert [f.rule_id for f in findings] == ["AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001"]


def test_deepseek_v4_reads_many_patterns_and_substitutions_in_linear_time(tmp_path: Path) -> None:
    """10,000 module pattern constants, each bound through the one before, and
    10,000 substitutions on other names in the function (linear: 0.21 s, 0.43 s
    and 1.06 s at 5,000, 10,000 and 20,000 outside pytest)."""
    consts = "P0 = r'\\s+'\n" + "".join(f"P{i} = re.compile(P{i - 1})\n" for i in range(1, 10_000))
    subs = "".join(f"    other{i} = re.sub(P{i}, '', doc)\n" for i in range(10_000))
    src = _DEEPSEEK.replace("import re\n", "import re\n" + consts, 1).replace("@@SUB@@", subs)
    started = time.perf_counter()
    findings = _read(tmp_path, src)
    assert time.perf_counter() - started < 5.0
    assert [f.rule_id for f in findings] == ["AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001"]


def test_deepseek_v4_many_functions_scale_linearly(tmp_path: Path) -> None:
    """Each function's body was cut from a fresh `text.splitlines()` of the whole
    file, so 20,000 functions took 26 s. At ten times the functions a linear
    reader takes about ten times as long; the bounds are loose for slow CI runners."""
    timings = []
    for count in (1_500, 15_000):
        lines = ["import deepseek", "import re"]
        for i in range(count):
            lines += [f"def f{i}(request):", "    data = request.json", "    return data"]
        started = time.perf_counter()
        _read(tmp_path, "\n".join(lines) + "\n")
        timings.append(time.perf_counter() - started)
    small, large = timings
    assert large < 30 * small + 1.0, (small, large)
    assert large < 10.0, large


# The review's cases (2026-10-17): a substitution counts when it is a call
# written in code, its pattern can be read and names the routing tokens, and
# its result is the description sent in the tools payload.

_DESCRIBE = '''import re

from flask import request
from openai import OpenAI

ROUTE_TOKEN_RE = r"\\[ROUTE:[^\\]]*\\]|<\\|route_id\\|>"
_ROUTE = re.compile(ROUTE_TOKEN_RE)
WHITESPACE = r"\\s+"
client = OpenAI(base_url="https://api.deepseek.com")


def describe():
    doc = request.json["description"]
    path = request.json["path"]
@@LINE@@
    return client.chat.completions.create(
        model="deepseek-chat", messages=[],
        tools=[{"type": "function", "function": {"name": "x", "description": doc}}],
    )
'''


@pytest.mark.parametrize(("line", "reported"), [
    ('    doc = re.sub(r"\\s+", " ", doc)', True),
    ('    path = re.sub(r"/route/", "/", path)', True),
    ('    # doc = re.sub(r"\\[ROUTE:[^\\]]*\\]", "", doc)', True),
    ('    doc = re.sub(WHITESPACE, " ", doc)', True),
    ('    doc = re.sub(ROUTE_TOKEN_RE, "", doc)', False),
    ('    doc = _ROUTE.sub("", doc)', False),
    ('    doc = re.sub(r"\\[ROUTE:[^\\]]*\\]", "", doc)', False),
    ('    doc = re.subn(pattern=ROUTE_TOKEN_RE, repl="", string=doc)[0]', False),
    ('    local = re.compile(r"__route__\\s*=")\n    doc = local.sub("", doc)', False),
])
def test_deepseek_v4_a_substitution_counts_only_on_the_description(
    tmp_path: Path, line: str, reported: bool
) -> None:
    (tmp_path / "agent.py").write_text(_DESCRIBE.replace("@@LINE@@", line), encoding="utf-8")
    fired = [f.rule_id for f in deepseek_scan(tmp_path)[0]] == ["AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001"]
    assert fired is reported


@pytest.mark.parametrize("src", [
    # Built into another name the description then uses.
    _DESCRIBE.replace("@@LINE@@", '    clean = re.sub(ROUTE_TOKEN_RE, "", doc)').replace('"description": doc', '"description": clean'),
    # Sanitised inside the payload itself.
    _DESCRIBE.replace("@@LINE@@", "").replace('"description": doc', '"description": re.sub(ROUTE_TOKEN_RE, "", doc)'),
    # A description set by subscript.
    _DESCRIBE.replace("@@LINE@@", '    spec = {}\n    spec["description"] = _ROUTE.sub("", doc)'),
])
def test_deepseek_v4_the_description_can_be_built_several_ways(tmp_path: Path, src: str) -> None:
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    assert deepseek_scan(tmp_path)[0] == []


# Verification of the AST reader (Low): its text says a substitution counts when
# its result is assigned to a name the description uses, but only `=` and an
# annotated `=` were read, so unpacking `subn`, a walrus and `+=` left a cleaned
# description reported.
@pytest.mark.parametrize("line", [
    '    clean, n = re.subn(ROUTE_TOKEN_RE, "", doc)',
    '    clean, _ = _ROUTE.subn("", doc)',
    '    clean, other = re.sub(ROUTE_TOKEN_RE, "", doc), path',
    '    if (clean := re.sub(ROUTE_TOKEN_RE, "", doc)):\n        pass',
    '    clean = ""\n    clean += _ROUTE.sub("", doc)',
])
def test_deepseek_v4_a_cleaned_name_can_be_unpacked_or_appended(tmp_path: Path, line: str) -> None:
    src = _DESCRIBE.replace("@@LINE@@", line).replace('"description": doc', '"description": clean')
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    assert deepseek_scan(tmp_path)[0] == []


@pytest.mark.parametrize("line", [
    # `re.sub` gives one string; unpacking it gives its characters.
    '    clean, n = re.sub(ROUTE_TOKEN_RE, "", doc)',
    # Only the first name `subn` unpacks into gets the new string.
    '    n, clean = re.subn(ROUTE_TOKEN_RE, "", doc)',
    '    clean = doc\n    clean -= _ROUTE.sub("", doc)',
])
def test_deepseek_v4_other_unpacking_cleans_no_name(tmp_path: Path, line: str) -> None:
    src = _DESCRIBE.replace("@@LINE@@", line).replace('"description": doc', '"description": clean')
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    assert [f.rule_id for f in deepseek_scan(tmp_path)[0]] == ["AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001"]


def test_deepseek_v4_no_deepseek_hint_passes(tmp_path: Path) -> None:
    """No deepseek base_url / import → scope gate excludes."""
    (tmp_path / "x.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI(base_url='https://api.openai.com/v1')\n"
        "def handle(request):\n"
        "    body = request.json()\n"
        "    return client.chat.completions.create(\n"
        "        model='gpt-4', messages=[],\n"
        "        tools=[{'description': body['x']}])\n",
        encoding="utf-8",
    )
    findings, _ = deepseek_scan(tmp_path)
    assert not any(
        f.rule_id == "AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001" for f in findings
    )


# Verification of the AST reader (2026-10-17, Medium): it copied the module's
# pattern table for every function it judged and walked each function's whole
# subtree four times, nested functions included, so many constants with many
# functions grew with their product (53 s at 4 MB), and 95 nested functions over
# 9,000 statements took 14.8 s (main 1.4 s). Each function's own body is read
# once now, and a name is looked up through the scopes around it.

def _consts_and_functions(count: int) -> str:
    consts = "".join(f"P{i} = r'\\s+'\n" for i in range(count))
    funcs = "".join(f"def f{i}(request):\n    return request.json\n" for i in range(count))
    return "from openai import OpenAI\nclient = OpenAI(base_url='https://api.deepseek.com')\n" + consts + funcs


def test_deepseek_v4_many_constants_and_functions_read_in_linear_time(tmp_path: Path) -> None:
    """At ten times the constants and the functions a linear reader takes about
    ten times as long; one that copies the table per function, a hundred."""
    timings = []
    for count in (4_000, 40_000):
        started = time.perf_counter()
        _read(tmp_path, _consts_and_functions(count))
        timings.append(time.perf_counter() - started)
    small, large = timings
    assert large < 20 * small + 1.0, (small, large)


def _nested(depth: int, statements: int) -> str:
    """`depth` functions, each nested in the one before, the source read only at
    the end of the innermost, below `statements` lines that name none."""
    src = ["from openai import OpenAI", "client = OpenAI(base_url='https://api.deepseek.com')"]
    for level in range(depth):
        src.append("    " * level + f"def f{level}(request):")
    src += ["    " * depth + f"a{i} = {i}" for i in range(statements)]
    src.append("    " * depth + "doc = request.json")
    src.append("    " * depth + "client.chat.completions.create(tools=[{'description': doc}])")
    return "\n".join(src) + "\n"


def test_deepseek_v4_nested_functions_read_in_linear_time(tmp_path: Path) -> None:
    """Nesting 95 deep costs about what nesting 10 deep does over the same lines,
    and every level still reports: each is tainted, sends a description and
    cleans none."""
    timings = []
    for depth in (10, 95):
        started = time.perf_counter()
        findings = _read(tmp_path, _nested(depth, 9_000))
        timings.append(time.perf_counter() - started)
        assert len(findings) == depth
    shallow, deep = timings
    assert deep < 3 * shallow + 0.5, (shallow, deep)


_NESTED_CLEAN = '''import re
from flask import request
from openai import OpenAI

client = OpenAI(base_url="https://api.deepseek.com")
ROUTE = r"\\[ROUTE:[^\\]]*\\]"


def create_app():
    @app.route("/chat")
    def chat():
        doc = request.json["doc"]
@@INNER@@
        return client.chat.completions.create(model="deepseek-chat", messages=[], tools=[{"description": @@DESC@@}])
    return chat
'''


@pytest.mark.parametrize(("inner", "desc", "lines"), [
    # Nothing cleaned: the route handler and the factory around it both report.
    ("", "doc", [9, 11]),
    # Cleaned in the nested handler: that clears the factory around it too.
    ("        doc = sanitize_tool_description(doc)", "doc", []),
    ("        clean = re.sub(ROUTE, \"\", doc)", "clean", []),
])
def test_deepseek_v4_a_nested_function_is_judged_with_the_one_around_it(
    tmp_path: Path, inner: str, desc: str, lines: list[int]
) -> None:
    (tmp_path / "app.py").write_text(
        _NESTED_CLEAN.replace("@@INNER@@", inner).replace("@@DESC@@", desc), encoding="utf-8"
    )
    assert sorted(f.line_number for f in deepseek_scan(tmp_path)[0]) == lines


def test_deepseek_v4_a_closure_sees_the_names_around_it(tmp_path: Path) -> None:
    """A pattern bound, or a description cleaned, in the function around a nested
    one is read inside it, as Python resolves the name."""
    src = (
        "import re\nfrom flask import request\nfrom openai import OpenAI\n"
        "client = OpenAI(base_url='https://api.deepseek.com')\n"
        "def handler():\n"
        "    pattern = r'__route__\\s*='\n"
        "    doc = request.json['doc']\n"
        "    clean = re.sub(pattern, '', doc)\n"
        "    def send():\n"
        "        raw = request.json['other']\n"
        "        return client.chat.completions.create(tools=[{'description': clean}])\n"
        "    return send()\n"
    )
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    assert deepseek_scan(tmp_path)[0] == []


def test_deepseek_v4_a_sibling_does_not_see_another_functions_names(tmp_path: Path) -> None:
    """A name cleaned in one nested function is that function's own: its sibling,
    and the function around both, send the raw text."""
    src = (
        "import re\nfrom flask import request\nfrom openai import OpenAI\n"
        "client = OpenAI(base_url='https://api.deepseek.com')\n"
        "def handler():\n"
        "    def clean_it():\n"
        "        clean = re.sub(r'\\[ROUTE:[^\\]]*\\]', '', request.json['doc'])\n"
        "    def send():\n"
        "        clean = request.json['doc']\n"
        "        return client.chat.completions.create(tools=[{'description': clean}])\n"
        "    return send()\n"
    )
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    assert sorted(f.line_number for f in deepseek_scan(tmp_path)[0]) == [5, 8]


_DEEPSEEK_HEAD = "from openai import OpenAI\nclient = OpenAI(base_url='https://api.deepseek.com')\n"
_DEEPSEEK_BODY = "def f(request):\n    doc = request.json\n    return client.create(tools=[{'description': doc}])\n"


@pytest.mark.parametrize(("size", "read"), [(512_000, True), (512_001, False)])
def test_deepseek_v4_reads_a_file_up_to_512_kb(tmp_path: Path, size: int, read: bool) -> None:
    padding = "#" * (size - len(_DEEPSEEK_HEAD) - len(_DEEPSEEK_BODY) - 1) + "\n"
    text = _DEEPSEEK_HEAD + padding + _DEEPSEEK_BODY
    assert len(text.encode("utf-8")) == size
    (tmp_path / "app.py").write_text(text, encoding="utf-8")
    assert bool(deepseek_scan(tmp_path)[0]) is read


# Two patterns of main's took quadratic time on a crafted file at any size: the
# gate's `OpenAI\s*\([^)]*base_url...` read to the next `)` from every
# `OpenAI(` (5.6 s at 280 KB), and the source `\bopen\([^)]*\)\.read\(\)` from
# every `open(` (0.62 s at 100 KB). A child process scans each at the cap, so the
# old patterns fail on the timeout instead of holding the suite.
_DEEPSEEK_CHILD = (
    "import sys, time\n"
    "from pathlib import Path\n"
    "from agent_audit_kit.scanners.deepseek_v4_tool_injection import scan\n"
    "started = time.perf_counter()\n"
    "findings, _ = scan(Path(sys.argv[1]))\n"
    "print(time.perf_counter() - started, len(findings))\n"
)


def _deepseek_in_child(root: Path) -> tuple[float, int]:
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(package_root)}
    done = subprocess.run(
        [sys.executable, "-c", _DEEPSEEK_CHILD, str(root)], capture_output=True, text=True, timeout=120, env=env
    )
    assert done.returncode == 0, done.stderr
    elapsed, count = done.stdout.split()
    return float(elapsed), int(count)


@pytest.mark.parametrize(("shape", "findings"), [
    ("OpenAI(" * 73_000, 0),
    (_DEEPSEEK_HEAD + "def f(request):\n    s = '" + "open(" * 101_000 + "'\n", 0),
    (_DEEPSEEK_HEAD + "def f(request):\n    s = '" + "open(" * 101_000 + "'\n"
     "    doc = open(path).read()\n    return client.create(tools=[{'description': doc}])\n", 1),
])
def test_deepseek_v4_reads_its_gate_and_sources_in_linear_time(tmp_path: Path, shape: str, findings: int) -> None:
    (tmp_path / "app.py").write_text(shape, encoding="utf-8")
    assert len(shape.encode("utf-8")) <= 512_000
    elapsed, count = _deepseek_in_child(tmp_path)
    assert count == findings
    assert elapsed < 5.0, elapsed


# Verification of a323344c (2026-10-17, High): the gate's own `base_url=` arm,
# `base_url\s*=\s*['"][^'"]*deepseek[^'"]*['"]`, read a value never closed to the
# end of the file once for every `deepseek` in it: `base_url='` and 63,000 of
# them took 333.8 s at 504 KB, and main does the same at any size. Each value is
# read to its closing quote once now.
@pytest.mark.parametrize(("head", "gated"), [
    ("client = OpenAI(base_url='https://api.deepseek.com')\n", True),
    ('client = OpenAI(base_url = "https://api.deepseek.com/v1")\n', True),
    ('client = OpenAI(api_key=key, base_url="https://api.deepseek.com")\n', True),
    ("import deepseek\n", True),
    ("from deepseek import Client\n", True),
    ("client = OpenAI(base_url='https://api.openai.com')  # deepseek\n", False),
    ("client = OpenAI(base_url='https://example.com/' + 'deepseek')\n", False),
    ("BASE_URL = 'https://api.deepseek.com'\nclient = OpenAI(base_url=BASE_URL)\n", False),
])
def test_deepseek_v4_gate_reads_a_base_url_value_to_its_quote(tmp_path: Path, head: str, gated: bool) -> None:
    src = head + "def f(request):\n    doc = request.json\n    return client.create(tools=[{'description': doc}])\n"
    assert bool(_read(tmp_path, src)) is gated


def test_deepseek_v4_reads_an_unclosed_base_url_in_linear_time(tmp_path: Path) -> None:
    text = "base_url='" + "deepseek" * 63_000 + "\n"
    assert len(text.encode("utf-8")) <= 512_000
    (tmp_path / "app.py").write_text(text, encoding="utf-8")
    elapsed, count = _deepseek_in_child(tmp_path)
    assert count == 0
    assert elapsed < 5.0, elapsed


# Verification of a323344c (2026-10-17, High): a name bound to a pattern held its
# text, and every substitution through the name searched all of it for the
# routing words again, so a 256,000-character pattern used by 8,000 calls took
# 82 s at 424 KB (main, which reads no pattern, 0.11 s). A name holds the verdict
# now, decided once where it is bound.
def test_deepseek_v4_decides_a_bound_pattern_once(tmp_path: Path) -> None:
    text = (
        "import re\n" + _DEEPSEEK_HEAD + "P = '" + "e" * 256_000 + "'\n"
        "def f(request):\n    doc = request.json\n"
        + "    re.sub(P, '', doc)\n" * 8_000
        + "    return client.create(tools=[{'description': doc}])\n"
    )
    assert len(text.encode("utf-8")) <= 512_000
    (tmp_path / "app.py").write_text(text, encoding="utf-8")
    elapsed, count = _deepseek_in_child(tmp_path)
    assert count == 1
    assert elapsed < 5.0, elapsed


# Verification of a323344c (2026-10-17, Low): cleanings main let through (it took
# any `re.sub(` in the function) that the AST reader missed: a nested helper
# assigning the outer name through `nonlocal`, a pattern bound in a block above
# the line that aliases it (bindings were read breadth first), and a pattern
# compiled in place (`.sub` was read only on a name).
_CLEANED_ELSEWHERE_HEAD = "import re\nfrom openai import OpenAI\nclient = OpenAI(base_url='https://api.deepseek.com')\n"


@pytest.mark.parametrize("body", [
    '''
def outer(request):
    clean = request.json["doc"]
    def helper():
        nonlocal clean
        clean = re.sub(r"\\[ROUTE:[^\\]]*\\]", "", clean)
    helper()
    return client.chat.completions.create(tools=[{"description": clean}])
''',
    '''
def outer(request):
    clean = request.json["doc"]
    def helper():
        def inner():
            nonlocal clean
            clean = re.sub(r"\\[ROUTE:[^\\]]*\\]", "", clean)
        inner()
    helper()
    return client.chat.completions.create(tools=[{"description": clean}])
''',
    '''
def f(request):
    if request:
        R = r"\\[ROUTE:[^\\]]*\\]"
    P = R
    doc = re.sub(P, "", request.json["doc"])
    return client.chat.completions.create(tools=[{"description": doc}])
''',
    '''
if True:
    ROUTE = r"\\[ROUTE:[^\\]]*\\]"
else:
    ROUTE = None
PATTERN = ROUTE


def f(request):
    doc = re.sub(PATTERN, "", request.json["doc"])
    return client.chat.completions.create(tools=[{"description": doc}])
''',
    '''
def f(request):
    doc = request.json["doc"]
    return client.chat.completions.create(tools=[{"description": re.compile(r"\\[ROUTE:[^\\]]*\\]").sub("", doc)}])
''',
    '''
def f(request):
    doc = request.json["doc"]
    clean, n = re.compile(r"__route__\\s*=", re.I).subn("", doc)
    return client.chat.completions.create(tools=[{"description": clean}])
''',
])
def test_deepseek_v4_reads_a_cleaning_main_let_through(tmp_path: Path, body: str) -> None:
    (tmp_path / "app.py").write_text(_CLEANED_ELSEWHERE_HEAD + body.lstrip("\n"), encoding="utf-8")
    assert deepseek_scan(tmp_path)[0] == []


@pytest.mark.parametrize("body", [
    # A helper's own `clean` is not the outer one: no `nonlocal`.
    '''
def outer(request):
    clean = request.json["doc"]
    def helper(doc):
        clean = re.sub(r"\\[ROUTE:[^\\]]*\\]", "", doc)
        return clean
    return client.chat.completions.create(tools=[{"description": clean}])
''',
    # `nonlocal` names the nearest function around that binds the name: here the
    # helper's, which is not the one the description uses.
    '''
def outer(request):
    clean = request.json["doc"]
    def helper(doc):
        clean = doc
        def inner():
            nonlocal clean
            clean = re.sub(r"\\[ROUTE:[^\\]]*\\]", "", clean)
        inner()
        return clean
    return client.chat.completions.create(tools=[{"description": clean}])
''',
])
def test_deepseek_v4_a_nested_name_cleans_only_its_own_binding(tmp_path: Path, body: str) -> None:
    (tmp_path / "app.py").write_text(_CLEANED_ELSEWHERE_HEAD + body.lstrip("\n"), encoding="utf-8")
    assert [f.line_number for f in deepseek_scan(tmp_path)[0]] == [4]


# Verification of e1cc1f9e (2026-10-17): a described name was looked up in every
# function around the one judged, so a nested function binding its own `clean`,
# by an assignment or as a parameter, borrowed the outer function's cleaning of
# another variable and was cleared where main reports it. A name is looked up as
# Python resolves it now: the nearest function that binds it decides, for a
# pattern's name too.
@pytest.mark.parametrize(("body", "lines"), [
    ('''
def outer(request):
    clean = re.sub(r"\\[ROUTE:[^\\]]*\\]", "", request.json["a"])
    def inner(request):
        clean = request.json["b"]
        return client.chat.completions.create(tools=[{"description": clean}])
    return inner
''', [4, 6]),
    ('''
def outer(request):
    clean = re.sub(r"\\[ROUTE:[^\\]]*\\]", "", request.json["a"])
    def inner(clean):
        body = request.json
        return client.chat.completions.create(tools=[{"description": clean}])
    return inner
''', [4, 6]),
    ('''
def outer(request):
    P = r"\\[ROUTE:[^\\]]*\\]"
    def inner(P):
        doc = re.sub(P, "", request.json["doc"])
        return client.chat.completions.create(tools=[{"description": doc}])
    return inner
''', [4, 6]),
    # Control: the nested function sends the outer function's cleaned `clean`.
    ('''
def outer(request):
    clean = re.sub(r"\\[ROUTE:[^\\]]*\\]", "", request.json["a"])
    def inner():
        body = request.json
        return client.chat.completions.create(tools=[{"description": clean}])
    return inner
''', []),
])
def test_deepseek_v4_a_name_is_the_variable_python_resolves(tmp_path: Path, body: str, lines: list[int]) -> None:
    (tmp_path / "app.py").write_text(_CLEANED_ELSEWHERE_HEAD + body.lstrip("\n"), encoding="utf-8")
    assert sorted(f.line_number for f in deepseek_scan(tmp_path)[0]) == lines


# -------------------- AAK-TIKTOK-AGENT-HIJACK-001 --------------------

def test_tiktok_agent_hijack_unsafe_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "social_agents" / "tiktok_unsafe.py").read_text()
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    findings, _ = social_scan(tmp_path)
    assert any(f.rule_id == "AAK-TIKTOK-AGENT-HIJACK-001" for f in findings)


def test_tiktok_agent_hijack_human_in_loop_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "social_agents" / "tiktok_human_in_loop.py").read_text()
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    findings, _ = social_scan(tmp_path)
    assert not any(f.rule_id == "AAK-TIKTOK-AGENT-HIJACK-001" for f in findings)


def test_tiktok_agent_hijack_no_user_input_passes(tmp_path: Path) -> None:
    """Reply call with hardcoded text (no taint source) → no finding."""
    (tmp_path / "agent.py").write_text(
        "import tiktok_api\n"
        "tiktok_api.reply('123', 'static reply')\n",
        encoding="utf-8",
    )
    findings, _ = social_scan(tmp_path)
    assert not any(f.rule_id == "AAK-TIKTOK-AGENT-HIJACK-001" for f in findings)


@pytest.mark.parametrize(("line", "imports"), [
    ("from langgraph.prebuilt import ToolNode", True),
    ("from langgraph.prebuilt import x, ToolNode", True),
    ("from langgraph.prebuilt import ToolNodes", False),
    ("from langgraph.prebuilt import x from langgraph.prebuilt import ToolNode", True),
])
def test_toolnode_import_keeps_its_shape(line: str, imports: bool) -> None:
    from agent_audit_kit.scanners.langgraph_toolnode import _TOOLNODE_IMPORT_RE

    assert bool(_TOOLNODE_IMPORT_RE.search(line)) is imports


def test_a_line_of_langgraph_imports_reads_in_linear_time() -> None:
    """1 MB of `from langgraph.prebuilt import x ` on one line. Each import read
    the rest of the line: 80 KB took 0.49 seconds and the time grew with the
    square. The bound is loose for slow CI runners."""
    from agent_audit_kit.scanners.langgraph_toolnode import _TOOLNODE_IMPORT_RE

    started = time.perf_counter()
    _TOOLNODE_IMPORT_RE.search("from langgraph.prebuilt import x " * 30_000)
    assert time.perf_counter() - started < 5.0
