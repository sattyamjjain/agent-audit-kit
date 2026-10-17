"""AAK-PRTITLE-IPI-001 — PR-title / issue-title indirect prompt injection.

Aonan Guan's 2026-04-25 Comment-and-Control disclosure (CVSS 9.4)
spread credential-theft payloads across Claude Code Security Review,
Gemini CLI Action, and GitHub Copilot Agent. The exploit shape: an
attacker opens a PR whose title contains an injected instruction; the
review agent reads the title, builds an LLM prompt by string-concat,
and the LLM follows the injected instruction with the agent's
credentials.

This rule fires when a function pulls a title-like field from a
GitHub-event source and feeds it into a known LLM client call without
HTML-escape, code-fencing, or a sanitiser pass.

Sources:

- https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/
- https://www.helpnetsecurity.com/2026/04/24/indirect-prompt-injection-in-the-wild/
"""

from __future__ import annotations

import ast
import bisect
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import in_skip_dir, make_finding


# A file over this many bytes is not read; the rule's limitation says so. The
# readers below are linear in the file, so the cap bounds the time a crafted file
# can take rather than keeping a quadratic path in check.
_MAX_BYTES = 512_000
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")


def _subscript(name: str) -> str:
    return rf"""\[\s*['"]{name}['"]\s*\]"""


def _get(name: str) -> str:
    # The default stops at the first parenthesis, which keeps the match linear
    # and leaves out a default that is itself a call, `.get("title", str())`.
    return rf"""\.\s*get\s*\(\s*['"]{name}['"][^()]*\)"""


def _key(name: str) -> str:
    """One step of an event read: `.name`, `["name"]` or `.get("name", <default>)`.

    A script that loads the event JSON (`json.load` on `GITHUB_EVENT_PATH`)
    holds dicts, so it reads `event["pull_request"]["title"]` or
    `event.get("pull_request", {}).get("title")`. Only the attribute path
    used to count, so the usual way to read the title was no source.
    """
    return rf"(?:\.\s*{name}\b|{_subscript(name)}|{_get(name)})"


def _heads(name: str) -> list[str]:
    """The first step of a chain: the bare word, or a subscript or `.get()` of it.

    Each form is an arm of its own in the pattern below, so that every arm
    starts with a literal. As one group inside an arm,
    `(?:pull_request\\b|\\[...|\\.\\s*get...)`, the forms gave the regex engine no
    first character to look for, and the search ran about seven times slower
    than main's on ordinary text (0.24 s for 4.6 MB, main 0.03 s), which a
    function nested 99 deep paid at every level (2.7 s at 507 KB).
    """
    return [rf"{name}\b", _subscript(name), _get(name)]


# Title-shape sources from GitHub event payloads and env vars; the gh CLI's is
# `_GH_PR_VIEW_RE`, below.
_TITLE_SOURCE_RE = re.compile(
    "|".join(
        f"(?:{arm})"
        for arm in (
            r"pull_request\s*\.\s*title",
            r"pull_request\s*\.\s*head\s*\.\s*ref",
            r"issue\s*\.\s*title",
            r"event\s*\.\s*pull_request\s*\.\s*title",
            r"event\s*\.\s*issue\s*\.\s*title",
            r"github\.event\.pull_request\.title",
            r"github\.event\.issue\.title",
            r"""os\.environ\[\s*['"]PR_TITLE['"]\s*\]""",
            r"""os\.environ\[\s*['"]GITHUB_HEAD_REF['"]\s*\]""",
            r"""os\.getenv\(\s*['"]PR_TITLE['"]""",
            r"""os\.getenv\(\s*['"]GITHUB_HEAD_REF['"]""",
            *(head + rf"\s*{_key('title')}" for head in _heads("pull_request")),
            *(head + rf"\s*{_key('head')}\s*{_key('ref')}" for head in _heads("pull_request")),
            *(head + rf"\s*{_key('title')}" for head in _heads("issue")),
        )
    )
)
# `gh pr view` with `title` anywhere after it, read apart. As the arm
# `gh\s+pr\s+view.*?title` (with `.` matching newlines) it read to the end of the
# text from every `gh pr view` with no `title` after it, quadratic in their
# number (2.3 s for 10,000). The first `gh pr view` has a `title` after it
# whenever any does, so it alone decides, and starts where the arm would.
_GH_PR_VIEW_RE = re.compile(r"gh\s+pr\s+view")


def _title_start(text: str, start: int, end: int) -> int | None:
    """Where the first title source in `text[start:end]` begins, or None."""
    found = _TITLE_SOURCE_RE.search(text, start, end)
    first = found.start() if found else None
    gh = _GH_PR_VIEW_RE.search(text, start, end)
    if gh is not None and text.find("title", gh.end(), end) != -1 and (first is None or gh.start() < first):
        first = gh.start()
    return first


# LLM client call shapes that turn a string into model output. The first arm
# was `anthropic\s*\.\s*\w*\s*\.?\s*(...)`: with the name and the dot absent,
# three `\s*` stood side by side, cubic in a run of blanks after
# `anthropic.` (0.83 s for 800 blanks, 13 s for 2,000). Each `\s*` follows a
# token that must be there now, and the arm matches the same text.
_LLM_SINK_RE = re.compile(
    r"""
    (?:
        anthropic\s*\.\s*(?:\w+\s*)?(?:\.\s*)?(?:messages\.create|completions\.create|create)
      | client\s*\.\s*messages\s*\.\s*create
      | openai\s*\.\s*chat\s*\.\s*completions\s*\.\s*create
      | openai\s*\.\s*ChatCompletion\.create
      | openai\s*\.\s*Completion\.create
      | genai\s*\.\s*GenerativeModel
      | model\s*\.\s*generate_content
      | langchain\s*\.\s*\w+\s*\.\s*(?:invoke|run|call)
      | LLMChain\s*\(
      | ChatAnthropic\s*\(
      | ChatOpenAI\s*\(
      | LLM\s*\(\s*\)\s*\.\s*invoke
      | claude_agent_sdk\.\s*\w+
    )
    """,
    re.VERBOSE,
)

# Sanitiser markers — if any of these appear between source and sink in
# the same function, we suppress. An `re.sub(` with an escaped pattern is
# `_escaped_substitution`, below.
_SANITIZE_RE = re.compile(
    r"""
    (?:
        html\.escape\s*\(
      | bleach\.clean\s*\(
      | markupsafe\.escape\s*\(
      | json\.dumps\s*\(
      | shlex\.quote\s*\(
      | hashlib\.\w+\s*\(
      | re\.escape\s*\(
      | \.replace\s*\(\s*['"]<['"]
      | sanitize|sanitise|escape_html|escape_md
      | ALLOWED_TITLE|TITLE_ALLOWLIST|TITLE_REGEX
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)
# `re.sub(` with a quoted pattern of four backslashes and a letter before the
# call's first `)`, read apart. As the arm
# `re\.sub\s*\([^)]*['"][^'"]*\\\\\\\\[a-z][^'"]*['"]` it read to the next `)`
# from every `re.sub(`, quadratic in their number (1.5 s for 10,000). Every
# `re.sub(` before the same `)` sees the same quotes or fewer, so the first of
# them decides, and each quote is tried once.
_SUB_CALL_RE = re.compile(r"re\.sub\s*\(", re.IGNORECASE)
_QUOTE_RE = re.compile(r"""['"]""")
_ESCAPED_PATTERN_RE = re.compile(r"""['"][^'"]*\\\\\\\\[a-z][^'"]*['"]""", re.IGNORECASE)


def _escaped_substitution(text: str, start: int, end: int) -> bool:
    """Whether `text[start:end]` holds an `re.sub(` with an escaped pattern, as the arm read it."""
    while True:
        call = _SUB_CALL_RE.search(text, start, end)
        if call is None:
            return False
        close = text.find(")", call.end(), end)
        stop = end if close == -1 else close
        at = call.end()
        while True:
            quote = _QUOTE_RE.search(text, at, stop)
            if quote is None:
                break
            if _ESCAPED_PATTERN_RE.match(text, quote.start(), end):
                return True
            at = quote.start() + 1
        if close == -1:
            return False
        start = close + 1


def _sanitised(text: str, start: int, end: int) -> bool:
    return bool(_SANITIZE_RE.search(text, start, end)) or _escaped_substitution(text, start, end)


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    """Per-function: title source seen + LLM sink seen + no sanitiser → fire."""
    try:
        tree = ast.parse(text, str(path))
    except SyntaxError:
        return []
    findings: list[Finding] = []
    # A function's source is its lines joined with newlines, searched in place;
    # the file is split once. Each function used to split it again, so 20,000
    # functions took 35 s.
    lines = text.splitlines()
    joined = "\n".join(lines)
    line_starts = [0]
    for line in lines:
        line_starts.append(line_starts[-1] + len(line) + 1)

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._scan(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._scan(node)
            self.generic_visit(node)

        def _scan(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            first = max(0, func.lineno - 1)
            last = min(len(lines), (func.end_lineno or func.lineno))
            if last <= first:
                return
            start, end = line_starts[first], line_starts[last] - 1
            source = _title_start(joined, start, end)
            if source is None:
                return
            if not _LLM_SINK_RE.search(joined, start, end):
                return
            if _sanitised(joined, start, end):
                return
            rel = str(path.relative_to(project_root))
            scanned.add(rel)
            # The title source's line.
            line_no = bisect.bisect_right(line_starts, source)
            findings.append(make_finding(
                "AAK-PRTITLE-IPI-001",
                rel,
                "PR/issue title flows into an LLM client call without "
                "HTML-escape, code-fencing, or allowlist validation. "
                "Comment-and-Control class (CVSS 9.4 — Aonan Guan "
                "2026-04-25): an attacker-controlled title injects "
                "instructions the agent executes with its own creds.",
                line_number=line_no,
            ))

    V().visit(tree)
    return findings


def _walk_ts(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    """Regex pass for TS/JS — title source + LLM sink within 4KB window."""
    findings: list[Finding] = []
    title = _title_start(text, 0, len(text))
    if title is None:
        return findings
    sink_match = _LLM_SINK_RE.search(text)
    if sink_match is None:
        return findings
    if _sanitised(text, 0, len(text)):
        return findings
    rel = str(path.relative_to(project_root))
    scanned.add(rel)
    line = text.count("\n", 0, title) + 1
    findings.append(make_finding(
        "AAK-PRTITLE-IPI-001",
        rel,
        "PR/issue title source reaches an LLM client call without a "
        "sanitiser in this file (TS/JS). Comment-and-Control class.",
        line_number=line,
    ))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        # Every file used to be read, then dropped unless it was one of these.
        suffix = path.suffix
        if suffix != ".py" and suffix not in _TS_SUFFIXES:
            continue
        if not path.is_file():
            continue
        if in_skip_dir(path, project_root):
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if suffix == ".py":
            findings.extend(_walk_python(text, path, project_root, scanned))
        else:
            findings.extend(_walk_ts(text, path, project_root, scanned))
    return findings, scanned
