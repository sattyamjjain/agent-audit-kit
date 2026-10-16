"""Deny-policy evaluated on a truncated string the executor never truncates.

`AAK-POLICY-TRUNCATION-001`.

A hook bridge, gateway or guard reads a candidate command / URL / path, cuts it
to a fixed length "for matching", and evaluates its deny patterns against the cut
copy — while the thing that actually runs receives the full, untruncated value.
Anything an attacker positions past the cut point is invisible to the policy and
visible to the executor.

CVE-2026-73614 (Network-AI ClaudeHookBridge < 5.15.1, CVSS 8.8) is the disclosed
instance: the target string is truncated to 500 characters before `denyPatterns`
are evaluated, while Claude Code executes the full Bash command field, so
dangerous content placed past byte 500 bypasses the operator's hard-deny list.

That CVE is **not** pinnable — the package resolves on neither npm nor PyPI and
its GitHub repository 404s (see `CHANGELOG.cves.md`, 2026-08-14) — so this rule
is deliberately vendor-independent. It keys on the *shape*, which is a general
bug in policy code, not on the vendor.

Detection is intentionally narrow. All three must hold in one file:

  1. a truncation with a fixed bound assigned to a variable
     (`x = cmd.slice(0, 500)`, `x = cmd[:500]`, ...);
  2. that variable is then tested against a deny / block / forbid construct;
  3. the untruncated source is still referenced elsewhere — otherwise the whole
     program only ever sees the short string, and there is no asymmetry.

Requiring (3) is what keeps this off legitimate display truncation, where the
short copy is the only copy anyone uses.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from pathlib import Path
from typing import Callable, Iterator

from agent_audit_kit.models import Finding

from ._helpers import in_skip_dir, find_line_number, make_finding, sub_up_to_last

_RULE_ID = "AAK-POLICY-TRUNCATION-001"
_MAX_FILE_BYTES = 1_000_000

# `const short = cmd.slice(0, 500)` / `.substring(0, 500)` / `.substr(0, 500)`
#
# Both patterns start a match only where one could first succeed. Their old
# openings, `(?:const|let|var)?\s*` and a bare name, began an attempt at every
# character of a long word or blank run and read to its end, so a crafted
# source file grew with the square of the run. A JS match now starts at the
# start of a blank run (the name after it is read whole), at the start of a word
# run past any leading digits (a leading `const` / `let` / `var` is dropped from
# the name, as before), or at one of those words that ends a run; a Python match
# at the start of a word run past any leading digits. Every other start failed
# for the same reason as one of these, so the matches are the same.
_JS_TRUNC_RE = re.compile(
    r"""(?:(?<!\s)\s+|(?<![\w$])[^\W_A-Za-z]*(?:(?:const|let|var)\s*)?|(?:const|let|var)(?![\w$])\s*)
        (?P<var>[A-Za-z_$][\w$]*)\s*=\s*
        (?P<src>[A-Za-z_$][\w$.\[\]]*)\s*\.\s*
        (?:slice|substring|substr)\s*\(\s*0\s*,\s*(?P<n>\d{2,})\s*\)""",
    re.VERBOSE,
)
# `short = cmd[:500]`
_PY_TRUNC_RE = re.compile(
    r"""(?<!\w)[^\W_A-Za-z]*(?P<var>[A-Za-z_]\w*)\s*=\s*
        (?P<src>[A-Za-z_][\w.\[\]]*)\s*\[\s*:\s*(?P<n>\d{2,})\s*\]""",
    re.VERBOSE,
)

# A deny / block decision being made. Deliberately broad on naming, because the
# vendor names vary, but it must look like a *policy* decision, not any regex.
#
# Every use asks only whether it matches somewhere. The letters after `deny`,
# `block`, `forbidden` and `disallow` used to be read to the end of their run by
# every occurrence of the word in it, so a run of `deny` repeated grew with the
# square: 80,000 characters took 31 seconds. Each read now stops at the next
# occurrence of its own word, which reads on to the same end itself. Whether a
# suffix ends the run, followed by a non-word character, is the same for every
# occurrence in the run, and none of the four words can overlap a suffix, so the
# last occurrence that leaves room for a suffix matches exactly when the first
# did.
_DENY_CONTEXT_RE = re.compile(
    r"deny(?:(?!deny)[_A-Za-z])*(?:Pattern|List|Rule|Match|Regex|s)\b"
    r"|block(?:ed)?(?:(?!block)[_A-Za-z])*(?:Pattern|List|Rule|Match|Regex|s)\b"
    r"|forbidden(?:(?!forbidden)[_A-Za-z])*\b"
    r"|disallow(?:ed)?(?:(?!disallow)[_A-Za-z])*\b"
    r"|blacklist\w*"
    r"|hard[_-]?deny\w*",
    re.IGNORECASE,
)

# The test operation itself, applied to the truncated variable. Covers both
# argument positions, because the idiom differs by language: JS tends to put the
# subject first (`target.match(p)`, `p.test(target)`) while Python's `re` module
# puts it last (`re.search(pattern, target)`).
#
# The call form reads its arguments up to the next call of the same names as
# well as up to `)`: with a bare `[^)]*`, every `search(` in a file of them read
# to the first `)`: 80,000 characters took 0.29 seconds and the time grew with
# the square of the file. A call nested in the arguments before `, var)` reads the
# rest itself, so the match is the inner call, and tests inside the outer call's
# arguments are no longer swallowed by it. The deny-context window around the
# inner call is inside the outer one's, so the decision can differ only when the
# deny word is more than 400 characters before the inner call.
_TEST_CALL = r"\b(?:search|match|fullmatch|findall|test|exec)\s*\("
_TEST_TEMPLATE = (
    r"(?:{var}\s*\.\s*(?:match|search|test|includes|startsWith|indexOf)\s*\()"
    r"|(?:\.\s*(?:test|exec|search|match|fullmatch)\s*\(\s*{var}\s*\))"
    r"|(?:" + _TEST_CALL + r"(?:(?!" + _TEST_CALL + r")[^)])*,\s*{var}\s*\))"
    r"|(?:\bin\s+{var}\b)"
    r"|(?:{var}\s+in\b)"
    r"|(?:\(\s*{var}\s*\))"
)

_JS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_PY_SUFFIXES = (".py",)

_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_PY_DOCSTRING_RE = re.compile(r'""".*?"""|\'\'\'.*?\'\'\'', re.DOTALL)
_PY_COMMENT_RE = re.compile(r"#[^\n]*")


def _strip_prose(text: str, is_python: bool) -> str:
    """Comments must not create or clear a finding."""
    if is_python:
        return _PY_COMMENT_RE.sub(" ", _PY_DOCSTRING_RE.sub(" ", text))
    return _TS_LINE_COMMENT_RE.sub(" ", sub_up_to_last(_TS_BLOCK_COMMENT_RE, " ", text, "*/"))


# A reference to the untruncated source: not part of a longer name or a member
# access before it, not followed by more of a name.
_SOURCE_REF = r"(?<![\w$.]){src}(?![\w$])"

# The sites of `_TEST_TEMPLATE`'s six forms, found once for every variable at
# once (see `_TruncationChecks`). Forms 1 and 5 start inside the run of name
# characters before them (the variable has no left boundary there), so they are
# found from the run's end and the variable is a suffix of the run.
_FORM_METHOD_RE = re.compile(r"(?<=[\w$])\s*\.\s*(?:match|search|test|includes|startsWith|indexOf)\s*\(")
_FORM_ARG_RE = re.compile(r"\.\s*(?:test|exec|search|match|fullmatch)\s*\(\s*([\w$]+)\s*\)")
_FORM_CALL_RE = re.compile(_TEST_CALL)
_FORM_IN_BEFORE_RE = re.compile(r"\bin(?=\s+[\w$])")
_FORM_IN_AFTER_RE = re.compile(r"(?<=[\w$])\s+in\b")
_FORM_PAREN_RE = re.compile(r"\(\s*([\w$]+)\s*\)")
_BLANKS_RE = re.compile(r"\s*")
_NAME_RUN_RE = re.compile(r"[\w$]*")
_ARG_NAME_RE = re.compile(r"\s*([\w$]+)\s*")
_BOUNDARY_RE = re.compile(r"\b")
_CLOSE_PAREN_RE = re.compile(r"\)")
_COMMA_RE = re.compile(r",")
# A maximal run of name and member-access characters, where a source can start.
_SOURCE_RUN_RE = re.compile(r"(?<![\w$.])[A-Za-z_$][\w$.]*")
_NAME_CHAR_RE = re.compile(r"[\w$]")


class _TruncationChecks:
    """The two questions asked of every truncation, answered from one pass.

    Whether the policy tests the truncated variable, and whether the source is
    still used untruncated, were each a fresh regex over the whole file for
    every truncation, compiled per name: 4,000 truncations in 79 KB took 5.6
    seconds and 790 KB took 493, growing with the square of the file. Both are
    now read off indexes built once per file, and each answer is the one the
    per-name regex gave: `tests/test_policy_truncation.py` holds them to
    `_TEST_TEMPLATE` and `_SOURCE_REF` on generated files.
    """

    def __init__(self, code: str, names: set[str], sources: set[str]) -> None:
        self._code = code
        self._sites = _test_sites(code, names)
        self._deny_windows: dict[tuple[int, int], bool] = {}
        self._tested: dict[str, bool] = {}
        self._sources = sources
        self._refs: _SourceRefs | None = None

    def tests_truncated_value(self, var: str) -> bool:
        """Does a deny-flavoured test read ``var``? The deny context must be
        near the test, not merely somewhere in the file."""
        hit = self._tested.get(var)
        if hit is None:
            hit = self._tested[var] = any(self._deny_near(*span) for span in self.test_matches(var))
        return hit

    def test_matches(self, var: str) -> Iterator[tuple[int, int]]:
        """The spans `_TEST_TEMPLATE`'s regex for ``var`` matches, in order: its
        sites by start, at each start the first form that matches there, and
        none starting inside the previous match."""
        resume = 0
        for start, _form, end in sorted(self._sites.get(var, ())):
            if start >= resume:
                resume = end
                yield start, end

    def source_used_untruncated(self, src: str, var: str) -> bool:
        """Is the original still referenced somewhere other than the truncation?

        Without this, a file that truncates once and only ever uses the short
        copy is legitimate — there is no policy/executor asymmetry to exploit.
        One reference is the truncation's own right-hand side.
        """
        if self._refs is None:
            self._refs = _SourceRefs(self._code, self._sources)
        return self._refs.at_least_two(src) and src != var

    def _deny_near(self, start: int, end: int) -> bool:
        key = (start, end)
        hit = self._deny_windows.get(key)
        if hit is None:
            window = (max(0, start - 400), end + 400)
            hit = self._deny_windows[key] = bool(_DENY_CONTEXT_RE.search(self._code, *window))
        return hit


def _test_sites(code: str, names: set[str]) -> dict[str, list[tuple[int, int, int]]]:
    """``name -> [(start, form, end)]`` for every match `_TEST_TEMPLATE` has for
    a name in ``names``, form numbered as in the template (1 to 6)."""
    sites: dict[str, list[tuple[int, int, int]]] = {}
    lengths = sorted({len(n) for n in names})
    reverse = code[::-1]

    def add(name: str, start: int, form: int, end: int) -> None:
        if name in names:
            sites.setdefault(name, []).append((start, form, end))

    def suffixes(run_end: int, form: int, end: int) -> None:
        # The run of name characters that ends at ``run_end``, read backwards.
        run = _end_of(_NAME_RUN_RE, reverse, len(code) - run_end) - (len(code) - run_end)
        for n in lengths:
            if n > run:
                break
            add(code[run_end - n:run_end], run_end - n, form, end)

    for m in _FORM_METHOD_RE.finditer(code):
        suffixes(m.start(), 1, m.end())
    for m in _FORM_ARG_RE.finditer(code):
        add(m.group(1), m.start(), 2, m.end())
    _call_sites(code, add)
    for m in _FORM_IN_BEFORE_RE.finditer(code):
        at = _end_of(_BLANKS_RE, code, m.end())
        run = _end_of(_NAME_RUN_RE, code, at) - at
        for n in lengths:
            if n > run:
                break
            if _BOUNDARY_RE.match(code, at + n):
                add(code[at:at + n], m.start(), 4, at + n)
    for m in _FORM_IN_AFTER_RE.finditer(code):
        suffixes(m.start(), 5, m.end())
    for m in _FORM_PAREN_RE.finditer(code):
        add(m.group(1), m.start(), 6, m.end())
    return sites


def _end_of(pattern: re.Pattern[str], text: str, pos: int) -> int:
    """Where a pattern that may match nothing (`\\s*`, `[\\w$]*`) stops from ``pos``."""
    m = pattern.match(text, pos)
    return m.end() if m else pos


def _call_sites(code: str, add: Callable[[str, int, int, int], None]) -> None:
    """Form 3: a test call whose last argument is the name.

    Its arguments are read up to the first `)` or the next test call, then back
    to the last `,` before that `)`; the name is what lies between the two.
    """
    calls = list(_FORM_CALL_RE.finditer(code))
    opens = [m.start() for m in calls]
    closes = [m.start() for m in _CLOSE_PAREN_RE.finditer(code)]
    commas = [m.start() for m in _COMMA_RE.finditer(code)]
    for m in calls:
        args = m.end()
        nxt = bisect_left(closes, args)
        close = closes[nxt] if nxt < len(closes) else len(code)
        nxt_open = bisect_left(opens, args)
        if nxt_open < len(opens) and opens[nxt_open] < close:
            continue  # the next test call comes first and reads on itself
        if close == len(code):
            continue
        last = bisect_left(commas, close) - 1
        if last < 0 or commas[last] < args:
            continue
        name = _ARG_NAME_RE.fullmatch(code, commas[last] + 1, close)
        if name:
            add(name.group(1), m.start(), 3, close + 1)


class _SourceRefs:
    """How many references `_SOURCE_REF` finds for each source, up to two.

    A reference starts where a run of name and member-access characters starts.
    A source without brackets is that run, or the part of it before one of its
    dots. A source with a bracket is the run up to its first bracket followed
    by the rest, so it is looked for only where that run starts, and two of
    them count only when the later one starts after the earlier one ends (one
    can overlap another, and the regex reads them left to right). Bracketed
    sources of one head and length are keyed by their text together, within a
    budget of a few times the file; past it, a source is counted by reading the
    file, which is what the budget saves.
    """

    def __init__(self, code: str, sources: set[str]) -> None:
        self._code = code
        self._runs: dict[str, list[int]] = {}
        for m in _SOURCE_RUN_RE.finditer(code):
            self._runs.setdefault(m.group(), []).append(m.start())
        self._dotted: dict[str, int] = {}
        plain_lengths = {len(s) for s in sources if "[" not in s and "]" not in s}
        for run, starts in self._runs.items():
            dot = run.find(".")
            while dot >= 0:
                if dot in plain_lengths:
                    prefix = run[:dot]
                    self._dotted[prefix] = self._dotted.get(prefix, 0) + len(starts)
                dot = run.find(".", dot + 1)
        self._bracketed: dict[tuple[str, int], dict[str, list[int]]] = {}
        self._budget = 8 * len(code) + 65_536
        self._answers: dict[str, bool] = {}

    def at_least_two(self, src: str) -> bool:
        hit = self._answers.get(src)
        if hit is None:
            hit = self._answers[src] = self._count(src)
        return hit

    def _count(self, src: str) -> bool:
        cut = min((i for i in (src.find("["), src.find("]")) if i >= 0), default=-1)
        if cut < 0:
            return len(self._runs.get(src, ())) + self._dotted.get(src, 0) >= 2
        head, size = src[:cut], len(src)
        starts = self._runs.get(head, [])
        group = self._bracketed.get((head, size))
        if group is None:
            if len(starts) * size > self._budget:
                return _two_refs(self._code, src)
            self._budget -= len(starts) * size
            group = self._bracketed[(head, size)] = {}
            code = self._code
            for start in starts:
                after = start + size
                if after <= len(code) and not _NAME_CHAR_RE.match(code, after):
                    group.setdefault(code[start:after], []).append(start)
        refs = group.get(src, [])
        return bool(refs) and refs[-1] >= refs[0] + size


def _two_refs(code: str, src: str) -> bool:
    """`_SOURCE_REF` read directly, stopping at the second reference."""
    if code.count(src) < 2:
        return False
    found = 0
    for _ in re.finditer(_SOURCE_REF.format(src=re.escape(src)), code):
        found += 1
        if found == 2:
            return True
    return False


def _scan_text(code: str, is_python: bool) -> tuple[str, str, str] | None:
    """Return (var, src, bound) for the first genuine truncation-before-deny."""
    if not _DENY_CONTEXT_RE.search(code):
        return None
    trunc_re = _PY_TRUNC_RE if is_python else _JS_TRUNC_RE
    truncations = [(m.group("var"), m.group("src"), m.group("n")) for m in trunc_re.finditer(code)]
    if not truncations:
        return None
    checks = _TruncationChecks(code, {t[0] for t in truncations}, {t[1] for t in truncations})
    for var, src, bound in truncations:
        if not checks.tests_truncated_value(var):
            continue
        if not checks.source_used_untruncated(src, var):
            continue
        return var, src, bound
    return None


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for deny policies evaluated against a truncated copy of their input.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (findings, set of scanned file paths relative to
        ``project_root``). Used to return rule ids, which the engine unions
        into ``files_scanned`` (issue #743).
    """
    findings: list[Finding] = []
    scanned: set[str] = set()

    for path in sorted(project_root.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        is_python = suffix in _PY_SUFFIXES
        if not (is_python or suffix in _JS_SUFFIXES):
            continue
        if in_skip_dir(path, project_root):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        scanned.add(path.relative_to(project_root).as_posix())

        hit = _scan_text(_strip_prose(raw, is_python), is_python)
        if hit is None:
            continue
        var, src, bound = hit

        rel = path.relative_to(project_root).as_posix()
        findings.append(make_finding(
            _RULE_ID,
            rel,
            (
                f"Deny policy is evaluated against `{var}`, a copy of `{src}` cut "
                f"to {bound} characters, while `{src}` is still used untruncated "
                f"elsewhere in the file. Whatever sits past character {bound} is "
                f"invisible to the deny patterns and visible to whatever consumes "
                f"`{src}` — so a caller places the dangerous part after the cut and "
                f"the hard-deny list never sees it. This is the ClaudeHookBridge "
                f"shape (CVE-2026-73614, CVSS 8.8: truncation to 500 characters "
                f"before `denyPatterns`, while Claude Code executed the full "
                f"command). Evaluate the policy on exactly the value the executor "
                f"receives; if a bound is needed for cost, reject over-long input "
                f"rather than matching a prefix of it."
            ),
            find_line_number(raw, f"{bound}") or find_line_number(raw, var),
        ))

    return findings, scanned
