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

from ._helpers import (
    MatchSpans,
    PatternSpans,
    in_skip_dir,
    make_finding,
    parse_python,
    read_text_capped,
    refusing_overflow,
    walk_tree,
)


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
_TITLE_ARMS = (
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
# token that must be there now, and the arm matches the same text. It tries the
# bare call first, so that a match over the whole file stops at the first
# complete call instead of taking `create` as a name and running on to a
# `create` on the next line (`PatternSpans` searches again any that still does).
_ANTHROPIC_CALL = r"(?:messages\.create|completions\.create|create)"
_LLM_SINK_ARMS = (
    rf"anthropic\s*\.\s*(?:{_ANTHROPIC_CALL}|\w+\s*(?:\.\s*)?{_ANTHROPIC_CALL}|\.\s*{_ANTHROPIC_CALL})",
    r"client\s*\.\s*messages\s*\.\s*create",
    r"openai\s*\.\s*chat\s*\.\s*completions\s*\.\s*create",
    r"openai\s*\.\s*ChatCompletion\.create",
    r"openai\s*\.\s*Completion\.create",
    r"genai\s*\.\s*GenerativeModel",
    r"model\s*\.\s*generate_content",
    r"langchain\s*\.\s*\w+\s*\.\s*(?:invoke|run|call)",
    r"LLMChain\s*\(",
    r"ChatAnthropic\s*\(",
    r"ChatOpenAI\s*\(",
    r"LLM\s*\(\s*\)\s*\.\s*invoke",
    r"claude_agent_sdk\.\s*\w+",
)

# Sanitiser markers — if any of these appear between source and sink in
# the same function, we suppress. An `re.sub(` with an escaped pattern is
# `_escaped_substitutions`, below.
_SANITIZE_ARMS = (
    r"html\.escape\s*\(",
    r"bleach\.clean\s*\(",
    r"markupsafe\.escape\s*\(",
    r"json\.dumps\s*\(",
    r"shlex\.quote\s*\(",
    r"hashlib\.\w+\s*\(",
    r"re\.escape\s*\(",
    r"""\.replace\s*\(\s*['"]<['"]""",
    r"sanitize|sanitise|escape_html|escape_md",
    r"ALLOWED_TITLE|TITLE_ALLOWLIST|TITLE_REGEX",
)


def _either(arms: tuple[str, ...], flags: int = 0) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{arm})" for arm in arms), flags)


# Each list as one pattern, to read a whole file at once, and as one pattern per
# arm, to find every match of each (`_Reader`).
_TITLE_SOURCE_RE = _either(_TITLE_ARMS)
_LLM_SINK_RE = _either(_LLM_SINK_ARMS)
_SANITIZE_RE = _either(_SANITIZE_ARMS, re.IGNORECASE)
_TITLE_SOURCE_RES = tuple(re.compile(arm) for arm in _TITLE_ARMS)
_LLM_SINK_RES = tuple(re.compile(arm) for arm in _LLM_SINK_ARMS)
_SANITIZE_RES = tuple(re.compile(arm, re.IGNORECASE) for arm in _SANITIZE_ARMS)

_SUB_CALL_RE = re.compile(r"re\.sub\s*\(", re.IGNORECASE)
_QUOTE_RE = re.compile(r"""['"]""")
_ESCAPE_RE = re.compile(r"\\\\\\\\[a-z]", re.IGNORECASE)


def _word_starts(text: str, word: str) -> list[int]:
    starts = []
    at = text.find(word)
    while at != -1:
        starts.append(at)
        at = text.find(word, at + 1)
    return starts


def _escaped_substitutions(text: str) -> list[tuple[int, int]]:
    """Every `re.sub(` with a quoted pattern of four backslashes and a letter,
    each as the span from the call to the pattern's closing quote.

    The pattern's quote opens before the call's first `)`, and its value runs
    to the next quote, past the `)` if need be. As a sanitiser arm,
    `re\\.sub\\s*\\([^)]*` and then the quoted pattern, it read to the next `)`
    from every `re.sub(` (1.5 s for 10,000), then tried each escape in a value
    never closed and read to the end of the file from every one: a quote and
    then four backslashes and a letter 100,000 times took 511.6 s at 500 KB.
    Each value between two quotes is searched once now. A call whose first
    escaped value opens after its `)` never matches, since no value opening
    before the `)` holds an escape. A range holds a match when it holds one of
    these spans.
    """
    quotes = [m.start() for m in _QUOTE_RE.finditer(text)]
    opens: list[int] = []
    closes: list[int] = []
    for here, there in zip(quotes, quotes[1:]):
        if _ESCAPE_RE.search(text, here + 1, there):
            opens.append(here)
            closes.append(there)
    if not opens:
        return []
    parens = _word_starts(text, ")")
    spans = []
    for call in _SUB_CALL_RE.finditer(text):
        index = bisect.bisect_left(opens, call.end())
        if index == len(opens):
            break
        paren = bisect.bisect_left(parens, call.end())
        if paren == len(parens) or parens[paren] > opens[index]:
            spans.append((call.start(), closes[index] + 1))
    return spans


class _Reader:
    """A Python file's title sources, sinks and sanitisers, each match found once.

    A function was judged by searching its own lines, so every level of a
    nested function searched the levels inside it again: 99 levels over one
    line of 20,000 calls took 31.6 s at 428 KB (main 24.4 s, the same body in
    one function 2.1 s). Each arm's matches are found once per file now, and a
    function asks about them by binary search (`PatternSpans`), which searches
    a pattern again within the function's lines where one of its matches runs
    across their first or last line: a comment ending `anthropic.create` on a
    function's last line, the next line starting `create = None`, ran the sink
    arm on to that line, and the function had no sink. The escaped
    substitutions are spans that hold for any range (`MatchSpans`).
    """

    def __init__(self, text: str) -> None:
        self._text = text
        self._titles = PatternSpans(_TITLE_SOURCE_RES, text)
        self._views = PatternSpans((_GH_PR_VIEW_RE,), text)
        self._title_words = _word_starts(text, "title")
        self._sinks = PatternSpans(_LLM_SINK_RES, text)
        self._sanitisers = PatternSpans(_SANITIZE_RES, text)
        self._escaped = MatchSpans(_escaped_substitutions(text))

    def title_start(self, start: int, end: int) -> int | None:
        """Where the first title source in `[start, end)` begins, as `_title_start` reads it."""
        first = self._titles.first(start, end)
        view = self._views.first(start, end)
        found = _GH_PR_VIEW_RE.match(self._text, view, end) if view is not None else None
        if found is not None:
            word = bisect.bisect_left(self._title_words, found.end())
            if word < len(self._title_words) and self._title_words[word] + len("title") <= end:
                if first is None or found.start() < first:
                    first = found.start()
        return first

    def reported(self, start: int, end: int) -> int | None:
        """Where the title source begins, when `[start, end)` holds one, a sink and no sanitiser."""
        source = self.title_start(start, end)
        if source is None or not self._sinks.within(start, end):
            return None
        if self._sanitisers.within(start, end) or self._escaped.within(start, end):
            return None
        return source


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    """Per-function: title source seen + LLM sink seen + no sanitiser → fire."""
    # A function's source is its lines joined with newlines, searched in place;
    # the file is split once. Each function used to split it again, so 20,000
    # functions took 35 s.
    lines = text.splitlines()
    joined = "\n".join(lines)
    # No function holds a title source or a sink the file does not.
    if _title_start(joined, 0, len(joined)) is None or not _LLM_SINK_RE.search(joined):
        return []
    try:
        tree = parse_python(text, path)
    except SyntaxError:
        return []
    findings: list[Finding] = []
    line_starts = [0]
    for line in lines:
        line_starts.append(line_starts[-1] + len(line) + 1)
    reader = _Reader(joined)

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
            source = reader.reported(line_starts[first], line_starts[last] - 1)
            if source is None:
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

    walk_tree(V().visit, tree)
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
    if _SANITIZE_RE.search(text) or _escaped_substitutions(text):
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
            text = read_text_capped(path, _MAX_BYTES, errors="replace")
        except OSError:
            continue
        if suffix == ".py":
            with refusing_overflow(path):
                findings.extend(_walk_python(text, path, project_root, scanned))
        else:
            findings.extend(_walk_ts(text, path, project_root, scanned))
    return findings, scanned
