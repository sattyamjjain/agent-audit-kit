"""Smoke tests for the v0.3.9 rules (4 SAST scanners + autofix codemod)."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from agent_audit_kit.autofix.langgraph_toolnode import fix as autofix_toolnode
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
    (tmp_path / "app.py").write_text(_DEEPSEEK.replace("@@SUB@@", crafted), encoding="utf-8")
    started = time.perf_counter()
    findings, _ = deepseek_scan(tmp_path)
    assert time.perf_counter() - started < 5.0
    assert [f.rule_id for f in findings] == ["AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001"]


def test_deepseek_v4_reads_many_patterns_and_substitutions_in_linear_time(tmp_path: Path) -> None:
    """10,000 module pattern constants, each bound through the one before, and
    10,000 substitutions on other names in the function (linear: 0.21 s, 0.43 s
    and 1.06 s at 5,000, 10,000 and 20,000 outside pytest)."""
    consts = "P0 = r'\\s+'\n" + "".join(f"P{i} = re.compile(P{i - 1})\n" for i in range(1, 10_000))
    subs = "".join(f"    other{i} = re.sub(P{i}, '', doc)\n" for i in range(10_000))
    src = _DEEPSEEK.replace("import re\n", "import re\n" + consts, 1).replace("@@SUB@@", subs)
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    started = time.perf_counter()
    findings, _ = deepseek_scan(tmp_path)
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
        root = tmp_path / str(count)
        root.mkdir()
        (root / "app.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
        started = time.perf_counter()
        deepseek_scan(root)
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
