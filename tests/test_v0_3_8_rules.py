"""Smoke tests for the 5 v0.3.8 rules."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import agent_audit_kit
from agent_audit_kit.scanners import prtitle_ipi
from agent_audit_kit.scanners.ipi_wild_corpus import scan as ipi_scan
from agent_audit_kit.scanners.mcp_atlassian import scan as atlassian_scan
from agent_audit_kit.scanners.mcp_fhi import scan as fhi_scan
from agent_audit_kit.scanners.mcp_inspector_cve import scan as inspector_scan
from agent_audit_kit.scanners.prtitle_ipi import scan as prtitle_scan

FIXTURES = Path(__file__).parent / "fixtures"


# -------------------- AAK-PRTITLE-IPI-001 --------------------

def test_prtitle_ipi_vulnerable_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "cves" / "comment-and-control-2026-04-25" /
           "vulnerable" / "review_agent.py")
    (tmp_path / "review_agent.py").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8"
    )
    findings, _ = prtitle_scan(tmp_path)
    assert any(f.rule_id == "AAK-PRTITLE-IPI-001" for f in findings)


def test_prtitle_ipi_patched_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "cves" / "comment-and-control-2026-04-25" /
           "patched" / "review_agent.py")
    (tmp_path / "review_agent.py").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8"
    )
    findings, _ = prtitle_scan(tmp_path)
    assert not any(f.rule_id == "AAK-PRTITLE-IPI-001" for f in findings)


def test_prtitle_ipi_ts_fires(tmp_path: Path) -> None:
    (tmp_path / "tool.ts").write_text(
        'const title = req.body.pull_request.title;\n'
        'await anthropic.messages.create({ messages: [{ content: title }] });\n',
        encoding="utf-8",
    )
    findings, _ = prtitle_scan(tmp_path)
    assert any(f.rule_id == "AAK-PRTITLE-IPI-001" for f in findings)


# A script that loads the event JSON reads the title as a subscript or a
# `.get()`, not an attribute path, so the usual form was no source at all.

_REVIEW = '''import json
import os

import anthropic

client = anthropic.Anthropic()


def review():
    with open(os.environ["GITHUB_EVENT_PATH"]) as fh:
        event = json.load(fh)
    title = @@TITLE@@
    return client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=200,
        messages=[{"role": "user", "content": "Review this change: " + title}],
    )
'''


@pytest.mark.parametrize("expr", [
    "event.pull_request.title",
    'event["pull_request"]["title"]',
    "event['pull_request']['title']",
    'event[ "pull_request" ] [ "title" ]',
    'event.get("pull_request", {}).get("title", "")',
    'event.get("pull_request").get("title")',
    'event["pull_request"].get("title")',
    'event.get("pull_request", {})["title"]',
    'event["issue"]["title"]',
    'event.get("issue", {}).get("title")',
    'event["pull_request"]["head"]["ref"]',
])
def test_prtitle_ipi_reads_the_title_however_the_event_is_read(tmp_path: Path, expr: str) -> None:
    (tmp_path / "review.py").write_text(_REVIEW.replace("@@TITLE@@", expr), encoding="utf-8")
    findings, scanned = prtitle_scan(tmp_path)
    assert [(f.rule_id, f.line_number) for f in findings] == [("AAK-PRTITLE-IPI-001", 12)]
    assert scanned == {"review.py"}


@pytest.mark.parametrize("expr", [
    'event["pull_request"]["body"]',
    'event.get("pull_request", {}).get("body")',
    'event["title"]',
    'event["pull_request"]["head"]["sha"]',
    'html.escape(event["pull_request"]["title"])',
    # A `.get()` default read to the first parenthesis, so one that is itself a
    # call is no source (stated in the limitation).
    'event.get("pull_request", dict()).get("title")',
])
def test_prtitle_ipi_other_fields_and_an_escaped_title_stay_silent(tmp_path: Path, expr: str) -> None:
    (tmp_path / "review.py").write_text(
        "import html\n" + _REVIEW.replace("@@TITLE@@", expr), encoding="utf-8"
    )
    assert prtitle_scan(tmp_path) == ([], set())


def test_prtitle_ipi_ts_reads_a_subscripted_title(tmp_path: Path) -> None:
    (tmp_path / "review.ts").write_text(
        'import Anthropic from "@anthropic-ai/sdk";\n'
        "const client = new Anthropic();\n"
        'const payload = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH!, "utf8"));\n'
        'const title = payload["pull_request"]["title"];\n'
        "await client.messages.create({ messages: [{ role: \"user\", content: title }] });\n",
        encoding="utf-8",
    )
    findings, _ = prtitle_scan(tmp_path)
    assert [(f.rule_id, f.line_number) for f in findings] == [("AAK-PRTITLE-IPI-001", 4)]


@pytest.mark.parametrize("text", [
    'x["pull_request"]' + " " * 1_000_000 + "y",
    'x.get("pull_request"' + "a" * 1_000_000,
    'x.get("pull_request", {})' * 100_000,
    '["pull_request"]["head"]' * 100_000,
])
def test_prtitle_ipi_reads_a_crafted_event_read_in_linear_time(tmp_path: Path, text: str) -> None:
    """The subscript and `.get()` forms: a key followed by 1 MB without the next
    key, and 100,000 keys in a row, in a TS file, which is matched whole. The
    reader is called directly, so the scan's 512 KB file cap does not apply."""
    import time

    started = time.perf_counter()
    prtitle_ipi._walk_ts(text + "\nclient.messages.create({})\n", tmp_path / "review.ts", tmp_path, set())
    assert time.perf_counter() - started < 5.0


# Verification (pre-existing): each function's source was cut from a fresh
# `splitlines()` of the whole file, so 20,000 functions took 35 s, and the file
# had no size cap. Three of the patterns took more than linear time on a crafted
# file at any size: the sink `anthropic\s*\.\s*\w*\s*\.?\s*(...)`, three `\s*`
# side by side, cubic in a run of blanks (0.83 s for 800); the source
# `gh\s+pr\s+view.*?title`, which read to the end of the text from every
# `gh pr view` with no `title` after it; and the sanitiser arm
# `re\.sub\s*\([^)]*['"]...`, which read to the next `)` from every `re.sub(`.

def test_prtitle_ipi_many_functions_read_in_linear_time(tmp_path: Path) -> None:
    import time

    timings = []
    for count in (1_500, 15_000):
        root = tmp_path / str(count)
        root.mkdir()
        text = "".join(f"def f{i}(event):\n    return 1\n" for i in range(count))
        assert len(text) <= 512_000, "the file must be read, not skipped"
        (root / "review.py").write_text(text, encoding="utf-8")
        started = time.perf_counter()
        prtitle_scan(root)
        timings.append(time.perf_counter() - started)
    small, large = timings
    assert large < 30 * small + 1.0, (small, large)
    assert large < 5.0, large


_PRTITLE_CHILD = (
    "import sys, time\n"
    "from pathlib import Path\n"
    "from agent_audit_kit.scanners.prtitle_ipi import scan\n"
    "started = time.perf_counter()\n"
    "findings, _ = scan(Path(sys.argv[1]))\n"
    "print(time.perf_counter() - started, len(findings))\n"
)

# A function's source ends at its last statement, so a crafted comment sits
# before one.
_PY_HEAD = "def review(event):\n    title = event.pull_request.title\n    client.messages.create(title)\n    # "
_PY_TAIL = "\n    return title\n"
_TS_HEAD = "const title = event.pull_request.title;\nclient.messages.create(title);\n"


def _prtitle_in_child(root: Path) -> tuple[float, int]:
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(package_root)}
    done = subprocess.run(
        [sys.executable, "-c", _PRTITLE_CHILD, str(root)], capture_output=True, text=True, timeout=120, env=env
    )
    assert done.returncode == 0, done.stderr
    elapsed, count = done.stdout.split()
    return float(elapsed), int(count)


@pytest.mark.parametrize(("name", "text", "findings"), [
    ("review.ts", "const t = event.pull_request.title;\nanthropic." + " " * 500_000 + "!\n", 0),
    ("review.py", "def f(event):\n    t = event.pull_request.title\n    # anthropic." + " " * 500_000 + "!" + _PY_TAIL, 0),
    ("review.ts", "gh pr view " * 45_000 + "\n", 0),
    ("review.py", "def f(event):\n    # " + "gh pr view " * 45_000 + "\n    return 1\n", 0),
    ("review.ts", _TS_HEAD + "re.sub(" * 70_000 + "\n", 1),
    ("review.py", _PY_HEAD + "re.sub(" * 70_000 + _PY_TAIL, 1),
])
def test_prtitle_ipi_reads_crafted_patterns_in_linear_time(
    tmp_path: Path, name: str, text: str, findings: int
) -> None:
    """A child process scans each, so the old patterns fail the test on its
    timeout instead of holding the suite."""
    assert len(text.encode("utf-8")) <= 512_000
    (tmp_path / name).write_text(text, encoding="utf-8")
    elapsed, count = _prtitle_in_child(tmp_path)
    assert count == findings
    assert elapsed < 5.0, elapsed


@pytest.mark.parametrize(("size", "read"), [(512_000, True), (512_001, False)])
def test_prtitle_ipi_reads_a_file_up_to_512_kb(tmp_path: Path, size: int, read: bool) -> None:
    body = "def review(event):\n    title = event.pull_request.title\n    client.messages.create(title)\n"
    text = "#" * (size - len(body) - 1) + "\n" + body
    assert len(text.encode("utf-8")) == size
    (tmp_path / "review.py").write_text(text, encoding="utf-8")
    assert bool(prtitle_scan(tmp_path)[0]) is read


def test_prtitle_ipi_title_source_reads_plain_text_at_main_speed() -> None:
    """The subscript and `.get()` forms were one group of alternatives inside two
    arms, which gave the regex engine no first character to look for: the search
    ran about seven times slower than main's arms on ordinary text, and a function
    nested 99 deep paid it at every level (2.7 s at 507 KB, main 0.42 s). Each
    form is an arm of its own now, starting with a literal."""
    import re
    import time

    text = "x123 = 'abcdefghijklmnopqrstuvwxyz0123456789'\n" * 100_000
    reference = re.compile(r"pull_request\s*\.\s*title|issue\s*\.\s*title|os\.getenv\(")
    timings = []
    for pattern in (reference, prtitle_ipi._TITLE_SOURCE_RE):
        started = time.perf_counter()
        assert pattern.search(text) is None
        timings.append(time.perf_counter() - started)
    base, title = timings
    assert title < 3 * base + 0.05, (base, title)


_FOUR_BACKSLASHES = "\\" * 4


@pytest.mark.parametrize(("line", "reported"), [
    # The `gh pr view` source: `title` anywhere after it.
    ('    out = os.popen("gh pr view 7 --json title").read()', True),
    ('    out = os.popen("gh pr view 7 --json body").read()', False),
    # The escaped-pattern sanitiser arm: a `re.sub(` with a quoted pattern of
    # four backslashes and a letter before the call's first `)`.
    (f"    out = re.sub('{_FOUR_BACKSLASHES}n', ' ', event.pull_request.title)", False),
    ("    out = re.sub(pattern, ' ', event.pull_request.title)", True),
    # The pattern's quote opens before the call's first `)`; its value may run past it.
    (f'    out = re.sub(" ) {_FOUR_BACKSLASHES}n", " ", event.pull_request.title)', False),
    # A quote after the `)` does not count, though its value holds the escape.
    (f"    out = re.sub(pattern, ' ', event.pull_request.title) + '{_FOUR_BACKSLASHES}n'", True),
    # Five backslashes hold four, and the call and the letter are read in any case.
    (f"    out = re.SUB(r'{_FOUR_BACKSLASHES}\\N', ' ', event.pull_request.title)", False),
    # An escape in a value that closes before the pattern's does not count.
    (f"    out = re.sub(pattern, '{_FOUR_BACKSLASHES}', event.pull_request.title)", True),
])
def test_prtitle_ipi_the_split_out_patterns_read_as_before(tmp_path: Path, line: str, reported: bool) -> None:
    src = (
        "import os\nimport re\n\n\n"
        "def review(event, pattern):\n"
        f"{line}\n"
        "    return client.messages.create(messages=[out])\n"
    )
    (tmp_path / "review.py").write_text(src, encoding="utf-8")
    assert [f.line_number for f in prtitle_scan(tmp_path)[0]] == ([6] if reported else [])


# Verification of a323344c (2026-10-17, High): the escaped-pattern sanitiser,
# matched at each quote as `['"][^'"]*\\\\\\\\[a-z][^'"]*['"]`, tried every escape
# in a quoted value never closed and read to the end of the file from each: a
# quote and then four backslashes and a letter 100,000 times took 511.6 s at
# 500 KB, as main's arm does at any size. Each quoted value is searched once now.
_ESCAPES = (_FOUR_BACKSLASHES + "a") * 100_000


@pytest.mark.parametrize(("name", "text"), [
    ("review.py", _PY_HEAD[: -len("    # ")] + '    re.sub("x", "y", title)\n    # ' + _ESCAPES + _PY_TAIL),
    ("review.ts", _TS_HEAD + "re.sub('" + _ESCAPES + "\n"),
])
def test_prtitle_ipi_reads_an_unclosed_pattern_in_linear_time(tmp_path: Path, name: str, text: str) -> None:
    assert len(text.encode("utf-8")) <= 512_000
    (tmp_path / name).write_text(text, encoding="utf-8")
    elapsed, count = _prtitle_in_child(tmp_path)
    assert count == 1
    assert elapsed < 5.0, elapsed


# Verification of a323344c (2026-10-17, Medium): each function's range was
# searched for a title source, a sink and a sanitiser, so every level of a nested
# function searched the levels inside it again: 99 levels over one line of
# 20,000 `re.sub("a", "b", t)` calls took 31.6 s at 428 KB (main 24.4 s, the same
# body in one function 2.1 s). Each match is found once per file now.
def _nested_review(depth: int) -> str:
    lines = ["import re"]
    lines += [" " * level + f"def f{level}(event, client, t):" for level in range(depth)]
    lines += [
        " " * depth + "x = [" + ", ".join(['re.sub("a", "b", t)'] * 20_000) + "]",
        " " * depth + "title = event.pull_request.title",
        " " * depth + "client.messages.create(prompt=title)",
    ]
    return "\n".join(lines) + "\n"


def test_prtitle_ipi_nested_functions_read_in_linear_time(tmp_path: Path) -> None:
    text = _nested_review(99)
    assert len(text.encode("utf-8")) <= 512_000
    (tmp_path / "review.py").write_text(text, encoding="utf-8")
    elapsed, count = _prtitle_in_child(tmp_path)
    assert count == 99, "every level holds the source, the sink and no sanitiser"
    assert elapsed < 5.0, elapsed


_NESTED_REVIEW = """import html


def outer(event, client):
    title = event.pull_request.title

    def send():
        return client.messages.create(prompt=title)

    def clean(text):
        return html.escape(text)

    return send()


def other(event, client):
    def send(title):
        return client.messages.create(prompt=title)

    return send(event.pull_request.title)


def inner_source(client):
    def read(event):
        return event.pull_request.title

    return client.messages.create(prompt=read)
"""


# Verification of e1cc1f9e (2026-10-17, Low, a regression on main and
# a323344c): a sink match found over the whole file ran past a function's last
# line where a search of the function's lines alone found a shorter one. At
# `anthropic.create` the `anthropic` arm took `create` as its optional name and
# went on to a `create` starting the next line, so the function had no sink. A
# match running across a function's edge is matched again within the function,
# and the arm tries the bare call first.
_PAST_THE_END = {
    "a return, then create_app()": (
        "import anthropic\n\ndef review(event):\n    title = event['pull_request']['title']\n"
        "    prompt = 'Review: ' + title\n    return anthropic.create\n\ncreate_app()\n", [4]),
    "a trailing comment, then create = None": (
        "def review(event, send):\n    title = event.pull_request.title\n"
        "    return send(title)  # goes to anthropic.create\ncreate = None\n", [2]),
    # The arm tried bare first still runs a name ending in `create` on to the
    # next line; only matching again within the function finds this one.
    "a name ending in create, then create = None": (
        "def review(event, send):\n    title = event.pull_request.title\n"
        "    return send(title)  # goes to anthropic.recreate\ncreate = None\n", [2]),
    "control: the function ends the file": (
        "import anthropic\n\ndef review(event):\n    title = event['pull_request']['title']\n"
        "    prompt = 'Review: ' + title\n    return anthropic.create\n", [4]),
}


@pytest.mark.parametrize("case", sorted(_PAST_THE_END))
def test_prtitle_ipi_a_sink_matched_past_the_function_end_is_matched_again(tmp_path: Path, case: str) -> None:
    src, lines = _PAST_THE_END[case]
    compile(src, "review.py", "exec")
    (tmp_path / "review.py").write_text(src, encoding="utf-8")
    assert [f.line_number for f in prtitle_scan(tmp_path)[0]] == lines


def test_prtitle_ipi_judges_a_function_with_the_ones_nested_in_it(tmp_path: Path) -> None:
    """A function's source includes the functions nested in it: `outer` holds a
    sanitiser in `clean`, `other` reads the title in its own line and sends it in
    `send`, and `inner_source` reads it in `read` and sends it itself. A nested
    function holding no source of its own is not reported."""
    (tmp_path / "review.py").write_text(_NESTED_REVIEW, encoding="utf-8")
    assert [f.line_number for f in prtitle_scan(tmp_path)[0]] == [20, 25]


# -------------------- AAK-MCP-FHI-001 --------------------

def test_fhi_imperative_description_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "incidents" / "mcp-fhi" / "vulnerable" / "server.py")
    (tmp_path / "server.py").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8"
    )
    findings, _ = fhi_scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-FHI-001" for f in findings)


def test_fhi_clean_description_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "incidents" / "mcp-fhi" / "clean" / "server.py")
    (tmp_path / "server.py").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8"
    )
    findings, _ = fhi_scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-FHI-001" for f in findings)


def test_fhi_universal_suffix_fires(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        'server.tool("search", "Normal description {{ALWAYS_PREFER_THIS_TOOL}} returns docs", impl);\n',
        encoding="utf-8",
    )
    findings, _ = fhi_scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-FHI-001" for f in findings)


# -------------------- AAK-MCP-ATLASSIAN-CVE --------------------

def test_atlassian_subprocess_sink_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "cves" / "cve-2026-27825-atlassian" /
           "vulnerable" / "agent.py")
    (tmp_path / "agent.py").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8"
    )
    findings, _ = atlassian_scan(tmp_path)
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-MCP-ATLASSIAN-CVE-2026-27825-001" in rule_ids


_PIN_27825 = "AAK-MCP-ATLASSIAN-CVE-2026-27825-001"
_PIN_27826 = "AAK-MCP-ATLASSIAN-CVE-2026-27826-001"


def _pin_ids(tmp_path: Path, requirement: str) -> set[str]:
    (tmp_path / "requirements.txt").write_text(requirement + "\n", encoding="utf-8")
    findings, _ = atlassian_scan(tmp_path)
    return {f.rule_id for f in findings}


def test_atlassian_pin_below_the_fix_reports_both_cves(tmp_path: Path) -> None:
    """NVD records CVE-2026-27825 and CVE-2026-27826 as both fixed in 0.17.0.

    One finding per CVE, so SARIF carries each id: 27825 is the unconfined
    `download_path` write, 27826 the header-driven SSRF.
    """
    assert {_PIN_27825, _PIN_27826} <= _pin_ids(tmp_path, "mcp-atlassian==0.16.2")


def test_atlassian_pin_at_the_fix_is_silent(tmp_path: Path) -> None:
    ids = _pin_ids(tmp_path, "mcp-atlassian==0.17.0")
    assert _PIN_27825 not in ids and _PIN_27826 not in ids


@pytest.mark.parametrize("requirements", [
    "\n" * 1_999_000 + "mcp-atlassian==0.16.2",
    "mcp-atlassian" + " " * 1_999_000 + "x",
])
def test_atlassian_pin_reads_a_crafted_manifest_in_linear_time(tmp_path: Path, requirements: str) -> None:
    """From every newline in a run of blank lines the pin pattern's `\\s*` read
    to the end of the run, so 40,000 blank lines took 6.7 seconds and the time
    grew with the square. The bound is loose for slow CI runners; the pin after the blank
    lines is still read, on its own line."""
    import time

    (tmp_path / "requirements.txt").write_text(requirements, encoding="utf-8")
    started = time.perf_counter()
    findings, _ = atlassian_scan(tmp_path)
    assert time.perf_counter() - started < 5.0
    lines = {f.line_number for f in findings if f.rule_id == _PIN_27825}
    assert lines == ({1_999_001} if requirements.endswith("0.16.2") else set())


def test_atlassian_patched_pin_is_silent(tmp_path: Path) -> None:
    """The fixture is named patched-pin, and the rule fired on it anyway.

    Until NVD published a fix version, this pin fired on every declared version
    "to surface for review", so a fully patched mcp-atlassian was reported as
    CRITICAL indefinitely. NVD has since recorded 0.17.0 for both CVEs.
    """
    src = FIXTURES / "cves" / "cve-2026-27825-atlassian" / "patched-pin" / "requirements.txt"
    (tmp_path / "requirements.txt").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    findings, _ = atlassian_scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert _PIN_27825 not in ids and _PIN_27826 not in ids


# -------------------- AAK-IPI-WILD-CORPUS-001 --------------------

def test_ipi_wild_payload_in_markdown_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "incidents" / "ipi-wild-2026-04-24" /
           "poisoned_template.md")
    (tmp_path / "poisoned_template.md").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8"
    )
    findings, _ = ipi_scan(tmp_path)
    assert any(f.rule_id == "AAK-IPI-WILD-CORPUS-001" for f in findings)


def test_ipi_wild_clean_passes(tmp_path: Path) -> None:
    (tmp_path / "ok.md").write_text(
        "# Docs\n\nThis is a normal documentation page.\n",
        encoding="utf-8",
    )
    findings, _ = ipi_scan(tmp_path)
    assert not any(f.rule_id == "AAK-IPI-WILD-CORPUS-001" for f in findings)


# -------------------- AAK-MCP-INSPECTOR-CVE-2026-23744-001 --------------------

def test_mcp_inspector_vendored_fork_fires(tmp_path: Path) -> None:
    target = (tmp_path / "vendor" / "mcpjam-inspector")
    target.mkdir(parents=True)
    (target / "server.ts").write_text(
        'inspectorServer.handle("/x", async (req, res) => res.send({}));\n',
        encoding="utf-8",
    )
    findings, _ = inspector_scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-INSPECTOR-CVE-2026-23744-001" for f in findings)


def test_mcp_inspector_clean_passes(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        'console.log("unrelated");\n',
        encoding="utf-8",
    )
    findings, _ = inspector_scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-INSPECTOR-CVE-2026-23744-001" for f in findings)
