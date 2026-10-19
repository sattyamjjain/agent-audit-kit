from __future__ import annotations

import ast
import bisect
import errno
import hashlib
import io
import ipaddress
import json
import os
import re
import stat
import sys
import threading
import unicodedata
import warnings
from array import array
from bisect import bisect_right
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import Context, ContextVar, copy_context
from itertools import accumulate, chain
from pathlib import Path
from typing import AbstractSet, Any, Callable, Iterable, Iterator, NamedTuple, TypeVar
from urllib.parse import unquote

try:
    import tomllib
except ImportError:  # Python 3.9 and 3.10
    import tomli as tomllib  # type: ignore[no-redef,import-not-found]

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.scanner import ScannerError

from agent_audit_kit.models import Finding
from agent_audit_kit.rules.builtin import get_rule

_T = TypeVar("_T")

# Interpolation of a caller-controlled variable into a command / shell string.
# Shared by hook_rce and ide_task_rce so there is exactly ONE definition of the
# "user input reaches a command string" signature (promoted here from
# hook_rce.py, which now imports it).
#
# The `"+` and `{{` arms used to end in a `\s*` of their own, right before the
# shared one, so a whitespace run after either opener could be split between
# the two every possible way: 40,000 spaces after `{{` took 30 seconds, and
# the time grew with the square of the run. The shared `\s*` matches the same
# whitespace alone, so the pattern matches exactly what it did, in linear time.
INTERPOLATION_RE = re.compile(
    r"""(?:["']\s*\+|\$\{|%\{|{{|\$\(|`)\s*(?:input|args|event|payload|user|argv|request)""",
    re.IGNORECASE,
)

# Block comments (`/\*.*?\*/`, `<!--[\s\S]*?-->`) do not nest, so an opener after
# the last closer can never close. A lazy pattern still read from each such
# opener to the end of the text, so a file of unclosed `/*` grew with the square
# of its size (80,000 characters of `/* a` took 3.3 seconds). These read only up
# to the last closer: every match ends at a closer, none can extend past the
# last one, and an opener before it closes and consumes what it read, so the
# result is the same and each character is read once.


def sub_up_to_last(
    pattern: re.Pattern[str], repl: str | Callable[[re.Match[str]], str], text: str, closer: str
) -> str:
    """``pattern.sub(repl, text)`` for a pattern whose every match ends with ``closer``."""
    end = text.rfind(closer)
    if end < 0:
        return text
    end += len(closer)
    return pattern.sub(repl, text[:end]) + text[end:]


def finditer_up_to_last(pattern: re.Pattern[str], text: str, closer: str) -> Iterator[re.Match[str]]:
    """``pattern.finditer(text)`` for a pattern whose every match ends with ``closer``."""
    return pattern.finditer(text, 0, text.rfind(closer) + len(closer) if closer in text else 0)


def sub_comments(pattern: re.Pattern[str], line_pattern: re.Pattern[str], text: str) -> str:
    """``pattern.sub("", text)`` for a MULTILINE comment pattern of line-comment
    arms (`//` or `#` to the end of the line) and a block-comment arm, where
    ``line_pattern`` is the same pattern without the block arm. Up to the last
    `*/` the whole pattern runs, and a line comment that reaches past it is read
    again in full; after it only the line arms can match, so only they run.
    """
    end = text.rfind("*/") + 2
    if end < 2:
        return line_pattern.sub("", text)
    out: list[str] = []
    pos = 0
    for m in pattern.finditer(text, 0, end):
        if m.end() == end and text[end:end + 1] not in ("", "\n") and not m.group(0).startswith("/*"):
            m = pattern.match(text, m.start()) or m
        out.append(text[pos:m.start()])
        pos = m.end()
    out.append(line_pattern.sub("", text[pos:]))
    return "".join(out)


class MatchSpans:
    """Spans in one text, each found once, to ask whether a range of it holds one.

    A scanner that judges each function by searching the function's own source
    searches the lines of a nested function again for every function around it,
    so a function nested 99 deep made its lines be read 99 times. Each span is
    found once per file instead, and a range is asked about by binary search: a
    span counts when it lies wholly inside the range. That is what a search of
    the range alone gives for spans found the same way in any range, such as a
    fixed string's occurrences or spans a caller builds to be; a regular
    expression's matches over the whole text are not, and go in `PatternSpans`.
    """

    def __init__(self, spans: Iterable[tuple[int, int]]) -> None:
        ordered = sorted(spans)
        self._starts = [start for start, _ in ordered]
        # The earliest end among the spans from each one on.
        self._earliest_end = [end for _, end in ordered]
        for index in range(len(ordered) - 2, -1, -1):
            self._earliest_end[index] = min(self._earliest_end[index], self._earliest_end[index + 1])

    def within(self, start: int, end: int) -> bool:
        """Whether a span lies wholly inside `[start, end)`."""
        index = bisect.bisect_left(self._starts, start)
        return index < len(self._starts) and self._earliest_end[index] <= end


class PatternSpans:
    """Where several patterns match in one text, found once, to ask about a range
    of it as a search of that range alone would.

    `finditer` over the whole text gives each pattern's matches, and one lying
    wholly inside a range is one a search of the range finds too. But a match
    can run across the range's start or end where a search of the range alone
    finds a shorter match at the same place, or one starting inside it: with
    `anthropic.create` on a function's last line and the next line starting
    `create`, a sink pattern with an optional name took `create` as the name and
    went on to that line, and the function had no sink. So a pattern with a
    match across the range's start, or one beginning inside the range and
    ending past it, is searched again within the range
    (`pattern.search(text, start, end)`), and each such search is kept.

    A range is taken to end at a line break, as a function's lines do, and a
    pattern must give the same answer at that end whether it reads the line
    break or the end of the text. `\\b` does, and so does a negative lookahead
    at the next character for a class without the line break (`(?![\\w$])`). A
    lookahead that can read past the line break does not, nor `$` or a lookahead
    that wants a character there (`(?=\\s)`), and such a pattern is not safe to
    pass: with `cp(?!\\s*\\.)`, `cp` ending one line and `.exec(c)` starting the
    next, the whole text has no match at `cp` to search again, while the
    range's own search stops at the line break and matches it.
    """

    def __init__(self, patterns: Iterable[re.Pattern[str]], text: str) -> None:
        self._patterns = tuple(patterns)
        self._text = text
        found = sorted(
            (m.start(), m.end(), which) for which, pattern in enumerate(self._patterns) for m in pattern.finditer(text)
        )
        self._starts = [start for start, _, _ in found]
        self._ends = [end for _, end, _ in found]
        self._which = [which for _, _, which in found]
        # The latest end among the matches up to each one, to tell whether any
        # runs across a position.
        self._latest_end: list[int] = []
        latest = -1
        for end in self._ends:
            latest = max(latest, end)
            self._latest_end.append(latest)
        # Each pattern's own matches, which never overlap, in order.
        self._own: list[tuple[list[int], list[int]]] = [([], []) for _ in self._patterns]
        for start, end, which in found:
            self._own[which][0].append(start)
            self._own[which][1].append(end)
        self._again: dict[tuple[int, int, int], int | None] = {}

    def _search(self, which: int, start: int, end: int) -> int | None:
        key = (which, start, end)
        if key not in self._again:
            match = self._patterns[which].search(self._text, start, end)
            self._again[key] = match.start() if match else None
        return self._again[key]

    def first(self, start: int, end: int) -> int | None:
        """Where the first match of any of the patterns in `[start, end)` begins, or None.

        Every match stepped over begins inside the range and ends past it, so
        covers the range's end; one pattern's matches never overlap, so that is
        at most one per pattern.
        """
        best: int | None = None
        index = bisect.bisect_left(self._starts, start)
        if index and self._latest_end[index - 1] > start:
            for which, (starts, ends) in enumerate(self._own):
                before = bisect.bisect_left(starts, start) - 1
                if before >= 0 and ends[before] > start:
                    at = self._search(which, start, end)
                    if at is not None and (best is None or at < best):
                        best = at
        while index < len(self._starts) and self._starts[index] < end:
            if best is not None and self._starts[index] >= best:
                break
            if self._ends[index] <= end:
                return self._starts[index]
            at = self._search(self._which[index], self._starts[index], end)
            if at is not None and (best is None or at < best):
                best = at
            index += 1
        return best

    def within(self, start: int, end: int) -> bool:
        """Whether any of the patterns matches in `[start, end)`."""
        return self.first(start, end) is not None


SKIP_DIRS = frozenset({
    "node_modules", ".git", "dist", "build", "__pycache__",
    ".next", ".nuxt", "vendor", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "target", "out", ".terraform",
})


def in_skip_dir(
    path: Path,
    root: Path,
    skip_dirs: AbstractSet[str] = SKIP_DIRS,
) -> bool:
    """True when a component of `path` *below* `root` is in `skip_dirs`.

    A skip list exists to keep vendored and generated trees inside the project
    (`node_modules/`, `build/`, `.venv/`) out of the scan. Every scanner used to
    test all of `path.parts`, and on an absolute path that includes the
    directories the project itself lives in. A checkout under a directory with
    one of those names therefore lost every finding from every scanner that
    walked the tree that way. That is not a corner case: Bitbucket Pipelines
    clones into `/opt/atlassian/pipelines/agent/build`, Travis into
    `/home/travis/build/<owner>/<repo>`, and `aak scan .` resolves the path
    before any scanner sees it. The scan then reported a clean project and
    said nothing about what it had skipped: a false all-clear, the worst
    answer a security scanner can give.

    The root is the directory the user chose to scan, so it can never itself
    be "vendored"; only the parts below it are tested. A `node_modules/` or
    `build/` inside the project is skipped exactly as before.

    A path that is not under `root` (a resolved symlink target, an explicit
    user-config path such as `~/.cursor/mcp.json`) has no parts below the root
    and is never skipped: it was named on purpose, and skipping it on the
    strength of its own ancestors would be this bug again. Neither case raises.
    A relative `path` that is not under `root` is taken as already relative to
    it, which is what a caller holding a `relative_to(project_root)` result
    has. When the lexical comparison fails for an absolute path, both sides
    are resolved before giving up, so a `/var` vs `/private/var` spelling of
    one directory still counts as under the root.

    This is for skip lists only. A check that classifies a file by an enclosing
    directory (`hook_rce`'s `.claude/hooks`) may look above the root on
    purpose: `aak scan ~/.claude` depends on the root's own name. `tests/test_skip_dirs.py` fails on a scanner that tests a skip set
    against `.parts` by hand instead of calling this.
    """
    return any(part in skip_dirs for part in _parts_below(path, root))


def _parts_below(path: Path, root: Path) -> tuple[str, ...]:
    """The components of `path` below `root`; `()` when it is not under it."""
    try:
        return path.relative_to(root).parts
    except ValueError:
        pass
    if not path.is_absolute():
        return path.parts
    try:
        return path.resolve().relative_to(root.resolve()).parts
    except (OSError, RuntimeError, ValueError):
        # RuntimeError: a symlink loop on Python < 3.13 (3.13 raises OSError).
        return ()


# ---- Line and source lookups -------------------------------------------------
#
# A scanner that reports one finding per server, task, tool or workflow step looks
# up one line per item, and every lookup used to split the whole text into lines
# again: N items in a file of S characters cost N x S, so 10,000 VS Code tasks
# (1.8 MB) took 48 seconds and 20,000 more than three minutes. What a lookup needs
# from its text (where each line ends, its `splitlines()`, the lines
# `ast.get_source_segment` cuts from) is now worked out once per text and kept
# for the few texts most recently looked up in, so a lookup is a `str.find` and a
# bisect, or a slice.
#
# That still leaves each `find_line_number` call paying the distance to its key's
# first occurrence, and a loop whose keys are each item's own name or URL pays
# N x S / 2 that way: 20,000 tasks spent 23 seconds in `str.find` alone.
# `find_line_numbers` takes the keys such a loop will look up and finds them all
# in one pass; the loop's own `find_line_number` calls are then answered from
# what it found. Both return exactly what one `find_line_number` call returns.


class _TextLookups:
    """What the line and source lookups have worked out about one text."""

    __slots__ = ("line_ends", "past_newlines", "lines", "py_source", "found", "long_lines")

    def __init__(self) -> None:
        self.line_ends: array[int] | None = None
        self.past_newlines: array[int] | None = None
        self.lines: tuple[str, ...] | None = None
        self.py_source: PySource | None = None
        self.found: dict[str, int | None] = {}
        self.long_lines: list[tuple[int, int]] | None = None


# A scanner works through its files one at a time, so a handful of texts is all
# it ever looks up in at once; keeping more would only hold dead files in memory.
_TEXT_LOOKUPS: OrderedDict[str, _TextLookups] = OrderedDict()
_TEXT_LOOKUPS_KEPT = 4
# Scans can run in threads at once, and they share the memo. Finding a text's
# entry and moving it to the end are two steps, and without the lock another
# thread could evict the entry between them, which raised KeyError. What an entry
# keeps is filled in without it: two threads that work out the same answer for
# one text store the same value. The lock is reentrant because the memo's own
# dict lookup hashes and compares the text, which a `str` subclass does in Python
# and can do through another lookup on the same thread.
_TEXT_LOOKUPS_LOCK = threading.RLock()


def _lookups(text: str) -> _TextLookups:
    with _TEXT_LOOKUPS_LOCK:
        entry = _TEXT_LOOKUPS.get(text)
        if entry is None:
            entry = _TEXT_LOOKUPS[text] = _TextLookups()
            if len(_TEXT_LOOKUPS) > _TEXT_LOOKUPS_KEPT:
                _TEXT_LOOKUPS.popitem(last=False)
        else:
            _TEXT_LOOKUPS.move_to_end(text)
        return entry


def _line_ends(text: str, entry: _TextLookups) -> array[int]:
    """The offset just past each line break in `text`, as `splitlines` breaks it."""
    if entry.line_ends is None:
        lines = text.splitlines(True)
        ends = array("q", accumulate(map(len, lines)))
        if lines and lines[-1].splitlines()[0] == lines[-1]:
            ends.pop()  # the last line runs to the end of the text, not to a break
        entry.line_ends = ends
    return entry.line_ends


def _holds_line_break(key: str) -> bool:
    return key.splitlines() != [key]


# Before Python 3.10, `str.find` had no linear worst case. Where the text is long
# runs of the key's own characters it compared up to a line's length at every
# offset, so a lookup of a key longer than the text's lines cost the text times
# the line: 120 task labels of 4,097 characters, looked up in a 1 MB tasks.json
# after lines of 4,000 `a`s, took 22.8 seconds there, where the old search line by
# line, which fails a line shorter than the key at once, took 0.12. 3.10 searches
# with the Two-Way algorithm, which is linear.
_LINEAR_FIND = sys.version_info >= (3, 10)


def linear_find(text: str, key: str, start: int = 0) -> int:
    """`text.find(key, start)`, in time linear in the text on every Python this runs on.

    Before 3.10, a key is compiled into a pattern that matches it literally, which
    `re` searches for with a table of the key's own overlaps (Knuth-Morris-Pratt),
    reading each character of the text once. The pattern is compiled outside
    `re`'s cache, which keeps 512 patterns and would push the scanners' own out.
    Compiling costs about a microsecond and 110 to 170 bytes a character, so only
    a key up to `_LITERAL_LONGEST` characters is compiled; a longer key is searched
    for only in the lines at least as long as itself, the way every key was
    searched for line by line through 0.6.22: text of shorter lines costs nothing,
    and a line that can hold the key is read with `str.find`, which keeps its
    pre-3.10 worst case there. A long line made of the key's own filler costs up to
    the key's length at every offset of the line, as it did through 0.6.22: 20 task
    labels of 4,097 characters against one 500,000-character line took 10 s on
    3.9, on 0.6.22 and here, and what bounds it is how much of a file the scanner
    reads. A key holding a line break, which no line lookup searches for, is read
    with `str.find` too, as is the empty key. `start` is read as `str.find` reads
    it, a negative one counted from the end.
    """
    if _LINEAR_FIND or not key:
        return text.find(key, start)
    start = slice(start, None).indices(len(text))[0]
    if len(key) <= _LITERAL_LONGEST:
        found = _literal(key).search(text, start)
        return found.start() if found else -1
    if _holds_line_break(key):
        return text.find(key, start)
    for line_start, line_end in _long_lines(text):
        line_start = max(line_start, start)
        if line_end - line_start >= len(key):
            offset = text.find(key, line_start, line_end)
            if offset >= 0:
                return offset
    return -1


def _literal(key: str) -> re.Pattern[str]:
    """A pattern that matches `key` and nothing else, compiled outside `re`'s cache."""
    if sys.version_info < (3, 10):
        import sre_compile

        return sre_compile.compile(re.escape(key))
    return re.compile(re.escape(key))  # only a test forces the old search on 3.10 or later


def _long_lines(text: str) -> list[tuple[int, int]]:
    """Where each line of `text` longer than `_LITERAL_LONGEST` starts and ends, found once."""
    entry = _lookups(text)
    if entry.long_lines is None:
        ends = _line_ends(text, entry)
        bounds = zip(chain((0,), ends), chain(ends, (len(text),)))
        entry.long_lines = [(a, b) for a, b in bounds if b - a > _LITERAL_LONGEST]
    return entry.long_lines


def find_line_number(raw: str, key: object) -> int | None:
    """The first line of `raw` that contains `key`, tolerating a non-string key.

    A line is what `raw.splitlines()` yields, so it breaks at `\\r`, `\\v`,
    `\\f`, `\\x1c`-`\\x1e`, `\\x85`, U+2028 and U+2029 as well as `\\n`, and a
    key that holds a line break is on no line.

    Callers pass a value straight out of parsed JSON, and a malformed config can
    put an int or a list where the MCP schema says string. Substring search then
    raised TypeError and took the whole scanner down (issue #743). The value is
    only ever used to point a finding at a line, so coercing is the right
    trade: a wrong-typed key simply fails to match and the finding carries no
    line number, which is what a missing match already did.

    A key with no line break in it lies inside one line wherever it occurs, so
    the first line holding it is the line of its first occurrence: one search
    (`linear_find`) and a bisect over where the lines end, both kept per text
    (see the comment above `_TextLookups`).
    """
    if not isinstance(key, str):
        key = str(key)
    if not key:
        return None
    entry = _lookups(raw)
    found = entry.found
    if key in found:
        return found[key]
    line = None
    if not _holds_line_break(key):
        offset = linear_find(raw, key)
        if offset >= 0:
            line = bisect_right(_line_ends(raw, entry), offset) + 1
    found[key] = line
    return line


# `find_line_numbers` searches key by key while that costs less than one
# Aho-Corasick pass, whose Python loop is several hundred times slower per
# character than `str.find` but reads the text once for every key. Measured on a
# loaded machine: `str.find` 0.6 ns a character, up to 4 ns on text built to
# defeat it; building the automaton about 0.5 us a key character, scanning
# 0.05 us a text character. A pass is chosen once the keys outnumber
# `12 + 150 x key characters / text characters`, which keeps either path within
# about one pass of the other on any input. Before Python 3.10 a key of up to
# `_LITERAL_LONGEST` characters searched for on its own is compiled first (see
# `linear_find`), at about 1 us a key character, near what the automaton costs to
# build, so the choice stands.
_ONE_PASS_KEYS = 12
_ONE_PASS_KEY_CHARS = 150
# A pass holds about 30 bytes a node of the automaton for keys in Latin-1
# (arrays for a node's only child, a dict only where it branches, then a failure
# link, an output link and a queue slot), and 90 to 110 for keys beyond it,
# whose every character is an object of its own: a full batch peaks near 63 MB,
# or up to 230 MB. So it is built from as many keys as fit in this many nodes,
# with one pass over the text per batch; keys that share a prefix share its
# nodes. A key longer than `_ONE_PASS_LONGEST` is searched for on its own
# instead: a text holds few of them, and one could fill a batch alone.
_ONE_PASS_NODES = 1 << 21
_ONE_PASS_LONGEST = 4096
# Before 3.10 `linear_find` compiles only a key the automaton would also take:
# compiling every key up to 1 MiB made eight quiet task labels of that size take
# 9.25 s and 136 MB on 3.9.
_LITERAL_LONGEST = _ONE_PASS_LONGEST


def find_line_numbers(raw: str, keys: Iterable[object]) -> dict[str, int | None]:
    """`find_line_number(raw, key)` for every key, the new ones found in one pass.

    Call it before a loop that looks up one key per item, with the keys the loop
    will ask for: each later `find_line_number(raw, key)` is then answered from
    what this found, so N items cost one pass over `raw` instead of N searches
    of it. A key the loop asks for that is not passed here is still found
    exactly, by its own search, so the keys only decide how fast the loop runs.
    """
    entry = _lookups(raw)
    found = entry.found
    asked: dict[str, None] = {}
    for key in keys:
        asked[key if isinstance(key, str) else str(key)] = None
    new: list[str] = []
    for key in asked:
        if key in found:
            continue
        if not key or _holds_line_break(key):
            found[key] = None
        else:
            new.append(key)
    if new:
        ends = _line_ends(raw, entry)
        for key, offset in zip(new, first_offsets(raw, new)):
            found[key] = bisect_right(ends, offset) + 1 if offset >= 0 else None
    return {key: found[key] for key in asked}


def placed(raw: str, unplaced: Iterable[tuple[Finding, object]]) -> list[Finding]:
    """The findings, each given the line `find_line_number(raw, key)` gives its key.

    A loop that reports one finding per item makes each without a line and keeps
    the key it is placed by (a server's URL, a tool's name); this then looks those
    keys up together, in one pass over `raw` (`find_line_numbers`). The keys are
    exactly those of the findings made, so a key no finding needs, such as an
    argument of a server no rule reports, is never searched for.
    """
    pending = list(unplaced)
    if not pending:
        return []
    lines = find_line_numbers(raw, (key for _, key in pending))
    for finding, key in pending:
        finding.line_number = lines[key if isinstance(key, str) else str(key)]
    return [finding for finding, _ in pending]


def first_offsets(text: str, keys: list[str]) -> list[int]:
    """`[text.find(key) for key in keys]`, the keys searched for together when that costs less.

    Key by key (`linear_find`) while that is cheaper than one Aho-Corasick pass
    (see the constants above), otherwise in passes over batches of keys, with
    any key longer than `_ONE_PASS_LONGEST` searched for on its own.
    """
    distinct = list(dict.fromkeys(key for key in keys if key))
    key_chars = sum(map(len, distinct))
    if len(distinct) <= _ONE_PASS_KEYS + _ONE_PASS_KEY_CHARS * key_chars // max(len(text), 1):
        found = {key: linear_find(text, key) for key in distinct}
    else:
        short = [key for key in distinct if len(key) <= _ONE_PASS_LONGEST]
        found = dict(zip(short, _first_offsets(text, short)))
        for key in distinct:
            if len(key) > _ONE_PASS_LONGEST:
                found[key] = linear_find(text, key)
    return [found[key] if key else 0 for key in keys]


def _first_offsets(text: str, keys: list[str]) -> list[int]:
    """Where each of `keys` first occurs in `text`, or -1: one pass per batch of keys."""
    offsets: list[int] = []
    start = 0
    while start < len(keys):
        trie = _Trie()
        stop = start
        while stop < len(keys) and trie.size() < _ONE_PASS_NODES:
            trie.add(keys[stop], stop - start)
            stop += 1
        offsets.extend(trie.first_offsets(text, [len(key) for key in keys[start:stop]]))
        start = stop
    return offsets


# A node's character when it has more than one child: two characters, so it never
# equals the one being looked for.
_BRANCHES = "\0\0"


class _Trie:
    """The keys of one Aho-Corasick batch, a node's only child kept in arrays.

    Most nodes of a trie built from file contents have one child, a run of a
    key no other key shares, so a dict per node would cost eight times the
    memory (273 MB against 34 MB for a million such nodes) and an eighth of
    the keys per pass.
    """

    def __init__(self) -> None:
        self.char = [""]  # the only child's character, "" for none, _BRANCHES for several
        self.child = array("i", [0])  # the only child
        self.branches: dict[int, dict[str, int]] = {}
        self.key_at = array("i", [-1])  # the key that ends at a node, or -1

    def size(self) -> int:
        return len(self.char)

    def step(self, node: int, char: str) -> int:
        """The child of `node` along `char`, or 0 (the root is no one's child)."""
        mine = self.char[node]
        if mine == char:
            return self.child[node]
        if mine is _BRANCHES:
            return self.branches[node].get(char, 0)
        return 0

    def children(self, node: int) -> Iterable[tuple[str, int]]:
        mine = self.char[node]
        if not mine:
            return ()
        if mine is _BRANCHES:
            return self.branches[node].items()
        return ((mine, self.child[node]),)

    def add(self, key: str, index: int) -> None:
        char_of, child_of, branches, key_at = self.char, self.child, self.branches, self.key_at
        node = 0
        for char in key:
            mine = char_of[node]
            if mine == char:
                node = child_of[node]
                continue
            if mine is _BRANCHES:
                nxt = branches[node].get(char)
                if nxt is not None:
                    node = nxt
                    continue
            nxt = len(char_of)
            char_of.append("")
            child_of.append(0)
            key_at.append(-1)
            if not mine:
                char_of[node] = char
                child_of[node] = nxt
            elif mine is _BRANCHES:
                branches[node][char] = nxt
            else:
                branches[node] = {mine: child_of[node], char: nxt}
                char_of[node] = _BRANCHES
            node = nxt
        key_at[node] = index

    def first_offsets(self, text: str, lengths: list[int]) -> list[int]:
        """Aho-Corasick: where each key first occurs in `text`, or -1.

        `lengths[i]` is the length of the key whose index is i. A key is
        reported where it first ends, which for a key of fixed length is also
        where it first starts, and the scan stops once every key has been seen.
        Reaching a key already seen ends the walk along the suffix links, since
        every shorter key on that walk is a suffix of it and was seen where it
        was.
        """
        size = len(self.char)
        fail = array("i", bytes(4 * size))
        # The nearest node on the fail chain that ends a key (0: none).
        next_key = array("i", bytes(4 * size))
        key_at = self.key_at
        queue = array("i", (child for _, child in self.children(0)))
        head = 0
        while head < len(queue):
            node = queue[head]
            head += 1
            for char, child in self.children(node):
                back = fail[node]
                target = self.step(back, char)
                while back and not target:
                    back = fail[back]
                    target = self.step(back, char)
                fail[child] = target
                next_key[child] = target if key_at[target] >= 0 else next_key[target]
                queue.append(child)

        char_of, child_of, branches = self.char, self.child, self.branches
        # Most characters start no key, so the root's step is one dict lookup and
        # a character that leaves the scan at the root cannot end a key.
        root = dict(self.children(0))
        offsets = [-1] * len(lengths)
        left = len(lengths)
        node = 0
        for end, char in enumerate(text):
            if not node:
                node = root.get(char, 0)
                if not node:
                    continue
            else:
                while True:
                    mine = char_of[node]
                    if mine == char:
                        node = child_of[node]
                        break
                    if mine is _BRANCHES:
                        nxt = branches[node].get(char)
                        if nxt is not None:
                            node = nxt
                            break
                    node = fail[node]
                    if not node:
                        node = root.get(char, 0)
                        break
            hit = node if key_at[node] >= 0 else next_key[node]
            while hit:
                index = key_at[hit]
                if offsets[index] >= 0:
                    break
                offsets[index] = end - lengths[index] + 1
                left -= 1
                hit = next_key[hit]
            if not left:
                break
        return offsets


def line_at(text: str, offset: int) -> int:
    """The line `offset` falls on, counted as `splitlines` counts them.

    It is the number of lines `splitlines` makes of `text[:offset]` with one
    more character after it, which is how `agent_config` placed a regex match
    by its offset: `len((text[:offset] + "\\0").splitlines())`. That rebuilt
    the prefix for every match, so a file of N matches cost N x its size.
    """
    line = bisect_right(_line_ends(text, _lookups(text)), offset) + 1
    if 0 < offset < len(text) and text[offset - 1] == "\r" and text[offset] == "\n":
        line += 1  # `text[:offset]` ends in a lone `\r`, a line break of its own
    return line


def newline_line(text: str, offset: int) -> int:
    """`text.count("\\n", 0, offset) + 1`, from where the text's newlines are, found once.

    Counting from the top of the file for every match made a file of N matches
    cost N times its size.
    """
    entry = _lookups(text)
    if entry.past_newlines is None:
        entry.past_newlines = array("q", accumulate(len(part) + 1 for part in text.split("\n")[:-1]))
    return bisect_right(entry.past_newlines, offset) + 1


def source_lines(text: str) -> tuple[str, ...]:
    """`text.splitlines()`, split once per text however often a scanner asks.

    A scanner that cuts each function's source out of its file by line number
    used to split the whole file once per function, so N functions cost N x the
    file. The lines are a tuple because they are shared between callers.
    """
    entry = _lookups(text)
    if entry.lines is None:
        entry.lines = tuple(text.splitlines())
    return entry.lines


# A source line as `ast.get_source_segment` splits them: up to `\r\n`, `\n` or `\r`.
_PY_LINE_RE = re.compile(r".*?(?:\r\n|\n|\r|$)")


class PySource:
    """`ast.get_source_segment` for many nodes of one file, its lines split once.

    `get_source_segment` splits the whole source into lines on every call, and
    `quoted_shell_interp` asks it for every tool function and for every template
    it cannot rebuild: 227 KB of tool functions took 7.6 seconds, growing with
    the square of the file. The lines are split where it splits them, and a
    segment is cut from them the way it cuts one, from each line encoded once.
    """

    def __init__(self, text: str) -> None:
        self._lines = [m.group() for m in _PY_LINE_RE.finditer(text)]
        self._encoded: dict[int, bytes] = {}

    def _line(self, i: int) -> bytes:
        line = self._encoded.get(i)
        if line is None:
            line = self._encoded[i] = self._lines[i].encode()
        return line

    def segment(self, node: ast.AST) -> str | None:
        lineno, end_lineno = getattr(node, "lineno", None), getattr(node, "end_lineno", None)
        col, end_col = getattr(node, "col_offset", None), getattr(node, "end_col_offset", None)
        if lineno is None or end_lineno is None or col is None or end_col is None:
            return None
        first, last = lineno - 1, end_lineno - 1
        if first == last:
            return self._line(first)[col:end_col].decode()
        return (
            self._line(first)[col:].decode()
            + "".join(self._lines[first + 1 : last])
            + self._line(last)[:end_col].decode()
        )


def source_segment(text: str, node: ast.AST) -> str | None:
    """`ast.get_source_segment(text, node)`, from lines split once per text."""
    entry = _lookups(text)
    if entry.py_source is None:
        entry.py_source = PySource(text)
    return entry.py_source.segment(node)


def make_finding(
    rule_id: str,
    file_path: str,
    evidence: str,
    line_number: int | None = None,
    related_locations: list[dict] | None = None,
) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id,
        title=rule.title,
        description=rule.description,
        severity=rule.severity,
        category=rule.category,
        file_path=file_path,
        line_number=line_number,
        evidence=evidence,
        remediation=rule.remediation,
        cve_references=rule.cve_references,
        owasp_mcp_references=rule.owasp_mcp_references,
        owasp_agentic_references=rule.owasp_agentic_references,
        adversa_references=rule.adversa_references,
        incident_references=rule.incident_references,
        aicm_references=rule.aicm_references,
        owasp_ast_references=rule.owasp_ast_references,
        related_locations=related_locations or [],
    )


_C0_CONTROL_OR_SPACE = "".join(chr(c) for c in range(0x21))
_HOSTNAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-.")

# ---- URL hosts: the two ways a client reads one -----------------------------
#
# The clients that consume what AAK scans read a URL's host two ways, and the two
# disagree on exactly the input an attacker writes. Node's `new URL()` (Claude
# Code, VS Code, Cursor, the MCP TypeScript SDK), urllib3 under requests, and
# Rust's `url` follow the WHATWG URL Standard, where a backslash ends an http(s)
# authority. Python's urlsplit, httpx, yarl and curl keep the backslash inside
# the authority and take the host after its last `@`. So
# `http://localhost\@evil.example/` is localhost to Node and evil.example to curl
# (which dials it), and `http://evil.example\@localhost/` is the other way round.
# A rule that exempts or allowlists a host on one reading is bypassed through the
# other, so the exemptions here hold only when every reading agrees.

#: The schemes WHATWG calls special that MCP, A2A and HTTP clients connect with,
#: and their default ports. `ftp` and `file` are special too, but no rule here
#: judges one.
_SPECIAL_SCHEME_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_TAB_OR_NEWLINE_RE = re.compile(r"[\t\n\r]")
#: Where an authority ends: WHATWG also stops at a backslash, RFC 3986 does not.
_AUTHORITY_END_RE = {False: re.compile(r"[/\\?#]"), True: re.compile(r"[/?#]")}
#: WHATWG's forbidden domain code points: a host that holds one is no host.
_FORBIDDEN_DOMAIN_RE = re.compile(r"[\x00-\x20#%/:<>?@\[\\\]^|\x7f]")
#: The code points UTS #46 maps to nothing (soft hyphen, zero-width space,
#: variation selectors, ...), so Node reads `local` + U+00AD + `host` as
#: `localhost`. Read off Node 22's `url.domainToASCII` over every code point.
_IDNA_IGNORED = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x180B, 0x180D), (0x180F, 0x180F),
    (0x200B, 0x200B), (0x2060, 0x2060), (0x2064, 0x2064), (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF), (0x1BCA0, 0x1BCA3), (0xE0100, 0xE01EF),
)
_IDNA_IGNORED_RE = re.compile(
    "[" + "".join(f"{chr(first)}-{chr(last)}" for first, last in _IDNA_IGNORED) + "]"
)
_ENDS_IN_NUMBER_RE = re.compile(r"[0-9]+|0x[0-9a-f]*")
_IPV4_DIGITS_RE = {10: re.compile(r"[0-9]+"), 8: re.compile(r"[0-7]+"), 16: re.compile(r"[0-9a-f]+")}


class UrlReading(NamedTuple):
    """One parser family's reading of an http(s) or ws(s) URL."""
    scheme: str        # `http`, `https`, `ws` or `wss`
    host: str          # see `_read_host`
    port: int | None   # None when absent, the scheme's default, or not a port number


def url_readings(value: str) -> tuple[UrlReading, ...]:
    """How the two parser families read `value`: one reading when they agree,
    the WHATWG one first and then the RFC 3986 one when they differ, and none
    when neither finds an http(s) or ws(s) URL with a host.

    WHATWG, as Node reads it: leading and trailing C0 controls and spaces are
    stripped and every tab, CR and LF removed; the scheme is case-blind and any
    run of `/` and `\\` after it is skipped, so `http:/host`, `http:\\\\host` and
    ` HTTP://host` are all http URLs; the authority ends at `/`, `\\`, `?` or
    `#`. RFC 3986, as urlsplit and httpx read it: leading C0 controls and spaces
    stripped and tab, CR and LF removed, as urlsplit does; the authority needs
    `//` and ends at `/`, `?` or `#`, so a backslash stays inside it. Both take
    the host after the authority's last `@` and read it as `_read_host` does. A
    port that is not a number leaves the host standing where WHATWG fails the
    URL, because it is usually a template (see `_split_host_port`).

    For a URL with no backslash, no tab or newline and `//` after its scheme the
    two readings are the same reading.
    """
    readings: list[UrlReading] = []
    for rfc3986 in (False, True):
        reading = _read_url(value, rfc3986)
        if reading is not None and reading not in readings:
            readings.append(reading)
    return tuple(readings)


def url_hosts(value: str) -> tuple[str, ...]:
    """The distinct hosts of `url_readings(value)`, WHATWG's first.

    A value with no `://` that does not open with a slash is read as a bare
    authority first (`api.anthropic.com/v1`, `localhost:8080`), as a scheme-less
    `ANTHROPIC_BASE_URL` or server address is meant. Empty when no reading finds
    a host, which every caller treats as "not loopback, not allowlisted".
    """
    readings = url_readings(value)
    stripped = value.strip(_C0_CONTROL_OR_SPACE)
    if not readings and "://" not in stripped and not stripped.startswith(("/", "\\")):
        readings = url_readings("http://" + stripped)
    return tuple(dict.fromkeys(reading.host for reading in readings))


def url_host(value: str) -> str | None:
    """The one host every client would connect to for `value`, or None.

    None when there is no host, when the two readings of `url_readings` name
    different hosts, or when the host is not a plain DNS name or IPv4 address (an
    IPv6 literal, a non-ASCII or underscored name). A caller comparing it with an
    allowlist therefore fails closed on all three. ``https://evil.example\\@
    api.anthropic.com`` is evil.example to Claude Code and api.anthropic.com to a
    Python SDK inheriting the same environment, and ``https://api.anthropic.com
    \\@evil.example`` the reverse, so neither has a host here. The host comes
    back lower-cased without a trailing dot.
    """
    hosts = url_hosts(value)
    if len(hosts) != 1:
        return None
    host = hosts[0].rstrip(".")
    if not host or not set(host) <= _HOSTNAME_CHARS:
        return None
    return host


def host_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address a `url_hosts` host names, or None when it is a domain.

    An IPv4-mapped IPv6 address (`::ffff:7f00:1`) comes back as its IPv4
    address, which is where a dual-stack socket sends it.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def is_loopback_url(value: str) -> bool:
    """True for a URL on this machine: `localhost`, 127.0.0.0/8, `::1` or 0.0.0.0.

    One definition for every rule that treats a local server differently.
    TRANSPORT-001 exempted these from "cleartext" with an anchored regex that
    knew only 127.0.0.1 and an `http`/`ws` scheme, while AAK-MCP-001 reported a
    developer's own `http://localhost:8001/mcp` as a remote server without
    authentication (CRITICAL) and AAK-MCP-009 reported it again as an internal
    network address. On 190 real `.vscode/mcp.json` files that was 51 findings
    and not one true positive.

    Every host in `url_hosts` has to be local, so neither
    `http://evil.example\\@localhost/` (evil.example to Node) nor
    `http://localhost\\@evil.example/` (evil.example to curl and httpx) is. The
    host is read as the client reads it, so `http://127.1/`, `http://0x7f.1/`,
    `http://[::ffff:127.0.0.1]/` and `http://%6c%6f%63%61%6c%68%6f%73%74/` are.
    """
    hosts = url_hosts(value)
    return bool(hosts) and all(_is_loopback_host(host) for host in hosts)


def _is_loopback_host(host: str) -> bool:
    if host.rstrip(".") == "localhost":
        return True
    address = host_ip(host)
    return address is not None and (
        address.is_loopback or (address.version == 4 and address.is_unspecified)
    )


def _read_url(value: str, rfc3986: bool) -> UrlReading | None:
    """`value` as one parser family reads it (see `url_readings`), or None."""
    url = value.lstrip(_C0_CONTROL_OR_SPACE) if rfc3986 else value.strip(_C0_CONTROL_OR_SPACE)
    url = _TAB_OR_NEWLINE_RE.sub("", url)
    scheme_match = _SCHEME_RE.match(url)
    if scheme_match is None:
        return None
    scheme = scheme_match.group()[:-1].lower()
    default_port = _SPECIAL_SCHEME_PORTS.get(scheme)
    if default_port is None:
        return None
    rest = url[scheme_match.end():]
    if rfc3986:
        if not rest.startswith("//"):
            return None
        rest = rest[2:]
    else:
        rest = rest.lstrip("/\\")
    end = _AUTHORITY_END_RE[rfc3986].search(rest)
    authority = rest if end is None else rest[:end.start()]
    host_port = _split_host_port(authority.rpartition("@")[2])
    if host_port is None:
        return None
    host = _read_host(host_port[0], rfc3986)
    if host is None:
        return None
    port = host_port[1]
    return UrlReading(scheme, host, None if port == default_port else port)


def _split_host_port(host_port: str) -> tuple[str, int | None] | None:
    """``(host, port)``, or None for text between an IPv6 literal's `]` and its
    port (`[::1]evil.example`), which leaves no host.

    A port that is not a number up to 65535 comes back as None and leaves the
    host standing. WHATWG fails such a URL, but the value scanned is often a
    template the client fills in before it parses: Claude Code expands
    `http://localhost:${JETBRAINS_MCP_PORT:-64342}/sse` to a loopback URL, and an
    instruction file writes `http://localhost:$PORT/`. Which host is contacted
    never depends on the port.
    """
    if host_port.startswith("["):
        close = host_port.find("]")
        if close < 0:
            return None
        host, rest = host_port[:close + 1], host_port[close + 1:]
        if rest and not rest.startswith(":"):
            return None
        port_text = rest[1:]
    else:
        host, _, port_text = host_port.partition(":")
    if not (port_text.isascii() and port_text.isdigit()):
        return host, None
    digits = port_text.lstrip("0") or "0"
    if len(digits) > 5 or int(digits) > 65535:
        return host, None
    return host, int(digits)


def _read_host(text: str, rfc3986: bool) -> str | None:
    """A URL's host the way WHATWG's host parser reads it, or None where it fails.

    An IPv6 literal must fill its brackets and take no zone id, and comes back
    compressed without them (`[0:0:0:0:0:0:0:1]` is `::1`). Anything else is
    percent-decoded and mapped as `_map_domain` maps it, and fails on a forbidden
    domain code point; then, when its last label is a number, it is an IPv4
    address and must parse as one (`_read_ipv4`). A domain is otherwise returned
    as mapped, lower-cased, with any trailing dot kept.

    The RFC 3986 reading differs in one place, the resolver behind it: macOS
    reads a four-part all-digit address as decimal, leading zeros and all, so
    `0177.0.0.1` is 177.0.0.1 to curl and httpx there and 127.0.0.1 to Node
    (`_decimal_dotted_quad`). That reading is the RFC 3986 one, so the two
    disagree and no exemption holds on either.
    """
    if text.startswith("["):
        inner = text[1:-1] if text.endswith("]") else ""
        if not inner or "%" in inner:
            return None
        try:
            return _ipv6_serialized(ipaddress.IPv6Address(inner))
        except ValueError:
            return None
    host = _map_domain(unquote(text, errors="replace"))
    if not host or _FORBIDDEN_DOMAIN_RE.search(host) or chr(0xFFFD) in host:
        return None
    labels = host.split(".")
    if labels[-1] == "" and len(labels) > 1:
        labels.pop()
    if _ENDS_IN_NUMBER_RE.fullmatch(labels[-1]):
        quad = _decimal_dotted_quad(labels) if rfc3986 else None
        return quad or _read_ipv4(labels)
    return host


def _ipv6_serialized(address: ipaddress.IPv6Address) -> str:
    """The URL Standard's IPv6 serializer: lower-case hex, the first longest run
    of two or more zero pieces written `::`, and never an embedded IPv4 address.

    `IPv6Address.compressed` is not that, and not stable either: Python 3.13
    (and later 3.12 releases) write an IPv4-mapped address as
    `::ffff:127.0.0.1` where 3.12.7 wrote `::ffff:7f00:1`, so the same URL got
    a different host on different interpreters. This writes the pieces itself.
    """
    pieces = [int.from_bytes(address.packed[i:i + 2], "big") for i in range(0, 16, 2)]
    compress, longest, run_start, run = None, 1, 0, 0
    for i, piece in enumerate(pieces + [1]):  # the sentinel ends a trailing run
        if piece == 0:
            if run == 0:
                run_start = i
            run += 1
            continue
        if run > longest:
            compress, longest = run_start, run
        run = 0
    out: list[str] = []
    ignore_zero = False
    for i, piece in enumerate(pieces):
        if ignore_zero and piece == 0:
            continue
        ignore_zero = False
        if compress == i:
            out.append("::" if i == 0 else ":")
            ignore_zero = True
            continue
        out.append(format(piece, "x"))
        if i != 7:
            out.append(":")
    return "".join(out)


def _map_domain(text: str) -> str:
    """`text` mapped the way UTS #46 maps a domain wherever the result is ASCII.

    Its ignored code points are dropped, then a non-ASCII name is NFKC-normalised
    with U+3002 as a dot, then lower-cased. Checked against Node's
    `url.domainToASCII` over every code point: for each one Node maps into ASCII
    this gives the same text (U+1E9E, which NFKC keeps and UTS #46 makes `ss`, is
    the one special case). A name still non-ASCII is a real IDN; it is returned
    as mapped, never punycoded, so it cannot equal an ASCII allowlist entry. For a
    handful of compatibility characters UTS #46 disallows (dot leaders, `1.`-style
    digits) this reads an ASCII host where Node fails the URL, which only matters
    for a URL no client can open.
    """
    text = _IDNA_IGNORED_RE.sub("", text)
    if not text.isascii():
        text = unicodedata.normalize("NFKC", text.replace(chr(0x1E9E), "ss"))
        text = text.replace(chr(0x3002), ".")
    return text.lower()


def _read_ipv4(labels: list[str]) -> str | None:
    """WHATWG's IPv4 parser over a host's labels, or None where it fails the URL.

    Up to four numbers, each decimal, octal (a leading `0`) or hex (`0x`), the
    last filling the bytes the others leave, so `127.1`, `0x7f.1`, `2130706433`
    and `0177.0.0.1` are all 127.0.0.1. `inet_aton`, which the resolver behind
    curl and httpx falls back to, reads these forms the same way.
    """
    if len(labels) > 4:
        return None
    numbers: list[int] = []
    for label in labels:
        number = _ipv4_number(label)
        if number is None:
            return None
        numbers.append(number)
    if any(number > 255 for number in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        return None
    address = numbers[-1]
    for index, number in enumerate(numbers[:-1]):
        address += number * 256 ** (3 - index)
    return str(ipaddress.IPv4Address(address))


def _decimal_dotted_quad(labels: list[str]) -> str | None:
    """The address macOS's resolver reads in four all-digit labels, each read as
    decimal, or None when that read fails (a label over 255, as in
    `0300.0250.1.1`) and it falls back to `inet_aton`, which reads them as
    `_read_ipv4` does."""
    if len(labels) != 4:
        return None
    octets: list[int] = []
    for label in labels:
        digits = label.lstrip("0") or "0"
        if _IPV4_DIGITS_RE[10].fullmatch(label) is None or len(digits) > 3 or int(digits) > 255:
            return None
        octets.append(int(digits))
    return ".".join(map(str, octets))


def _ipv4_number(label: str) -> int | None:
    if not label:
        return None
    radix = 10
    if label.startswith("0x"):
        label, radix = label[2:], 16
    elif len(label) > 1 and label.startswith("0"):
        label, radix = label[1:], 8
    if not label:
        return 0
    if _IPV4_DIGITS_RE[radix].fullmatch(label) is None:
        return None
    digits = label.lstrip("0") or "0"
    # 2**32 takes 11 octal digits, so a longer number fails the range checks
    # anyway, and int() of a long digit string is quadratic before Python 3.11.
    if len(digits) > 11:
        return None
    return int(digits, radix)


# The variables VS Code substitutes itself, per its variables reference: the 20
# predefined ones (each may take a `:FolderName` scope in a multi-root
# workspace) and the `env:`, `config:`, `command:` and `input:` forms. Longer
# names come first so a prefix such as `file` never shadows `fileDirname`. The
# argument class excludes `{` as well as `}`: with `[^}]*`, every `${env:` with
# no closer rescanned to the end of the string, so a crafted command grew
# quadratically (56,000 characters of `${file:` took 1.6 seconds). No VS Code
# variable has a brace inside it.
_VSCODE_VARIABLE_RE = re.compile(
    r"\$\{(?:(?:fileBasenameNoExtension|fileDirnameBasename|fileWorkspaceFolder"
    r"|workspaceFolderBasename|relativeFileDirname|defaultBuildTask|workspaceFolder"
    r"|pathSeparator|selectedText|fileBasename|columnNumber|relativeFile|fileDirname"
    r"|fileExtname|lineNumber|execPath|userHome|file|cwd)(?::[^{}]*)?"
    r"|/|(?:env|config|command|input):[^{}]*)\}"
)


def strip_vscode_variables(text: str) -> str:
    """`text` without the VS Code variables in it (`${workspaceFolder}`,
    `${userHome}`, `${env:X}`, `${input:X}`, ...).

    VS Code substitutes these itself before it spawns the server, with no
    shell, so their `$`, `{` and `:` are not shell expansion or template
    interpolation. AAK-MCP-002 read `${workspaceFolder}/run.sh` as a shell
    metacharacter, and AAK-MCP-STDIO-LAUNCHER-INJECT-001 read `${input:token}`
    as a non-pinned interpolation token: 31 of its 32 findings on 190 real
    `.vscode/mcp.json` files were a VS Code variable.
    """
    return _VSCODE_VARIABLE_RE.sub("", text)


# JSONC tokens outside a string: a run of anything that is not JSON whitespace
# or one of the characters that change state, or one of those characters. JSON
# whitespace is the four characters the search skips between two tokens.
_JSONC_TOKEN_RE = re.compile(r'[^ \t\r\n"/,\]}]+|["/,\]}]')
_JSON_STRING_SPECIAL_RE = re.compile(r'["\\]')
_LINE_BREAK_RE = re.compile(r"[\r\n]")
_NOT_LINE_BREAK_RE = re.compile(r"[^\r\n]")
# The last token before a comma that leaves no value for the comma to follow:
# the start of the text, an opening bracket, a colon or another comma.
_JSONC_NO_VALUE_BEFORE = frozenset({"", "{", "[", ":", ","})


def _json_string_end(text: str, start: int) -> int:
    """Index just past the string opened by the quote at `start`.

    A backslash escapes the next character, so `"a\\"b"` is one string. A
    string that never closes raises the error `json.loads` gives for one.
    """
    i = start + 1
    while True:
        m = _JSON_STRING_SPECIAL_RE.search(text, i)
        if m is None:
            raise json.JSONDecodeError("Unterminated string starting at", text, start)
        if m.group() == "\\":
            i = m.start() + 2
        else:
            return m.end()


def strip_jsonc(text: str) -> str:
    """`text` with its JSONC comments and trailing commas blanked out.

    VS Code reads `.vscode/mcp.json`, `settings.json`, `tasks.json` and
    `launch.json` as JSONC: JSON plus `//` and `/* */` comments and a comma
    before a closing `}` or `]`. The MCP config readers here called
    `json.loads`, which raises on either, and skipped the file, so a VS Code
    config with one comment in it scanned clean.

    Strings are tracked first: a `"` opens one, a backslash escapes the next
    character, and only outside a string does `//` or `/*` start a comment, so
    `"url": "http://x"` keeps its `//`. Two regexes that do not know what a
    string is broke the TS/JS SSRF comment stripper on exactly that (see
    `blank_js_comments`). A comma is a trailing comma only when a value comes
    before it and, past whitespace and comments, a `}` or `]` comes after it,
    so `[,]` and `{"a": 1,,}` stay invalid, as VS Code reports them. A
    byte-order mark at the start goes too.

    Every removed character becomes a space and every line break stays, so
    offsets and line numbers, those in a `json.JSONDecodeError` included, still
    match the raw text. It is linear: every search resumes where the last one
    stopped, and a comma is settled by the next token after it.

    Raises:
        json.JSONDecodeError: a block comment or a string runs to the end of
            the text. That is a parse failure, the same as invalid JSON.
    """
    n = len(text)
    i = 1 if text.startswith("\ufeff") else 0
    blanks: list[tuple[int, int]] = [(0, 1)] if i else []
    pending_comma = -1  # a comma no token has followed yet
    prev = ""  # the last character of the last token, "" before the first
    while True:
        m = _JSONC_TOKEN_RE.search(text, i)
        if m is None:
            break
        at, token = m.start(), m.group()
        if token == '"':
            i = _json_string_end(text, at)
            prev, pending_comma = '"', -1
        elif text.startswith("//", at):
            eol = _LINE_BREAK_RE.search(text, at)
            i = n if eol is None else eol.start()
            blanks.append((at, i))
        elif text.startswith("/*", at):
            close = text.find("*/", at + 2)
            if close == -1:
                raise json.JSONDecodeError("Unterminated comment starting at", text, at)
            i = close + 2
            blanks.append((at, i))
        elif token == ",":
            pending_comma = -1 if prev in _JSONC_NO_VALUE_BEFORE else at
            prev, i = ",", at + 1
        elif token in ("]", "}"):
            if pending_comma != -1:
                blanks.append((pending_comma, pending_comma + 1))
            prev, pending_comma, i = token, -1, at + 1
        else:  # a number, a literal, `{`, `[`, `:`, or a `/` no JSON allows
            prev, pending_comma, i = token[-1], -1, m.end()
    if not blanks:
        return text
    blanks.sort()
    parts: list[str] = []
    last = 0
    for start, end in blanks:
        parts.append(text[last:start])
        parts.append(_NOT_LINE_BREAK_RE.sub(" ", text[start:end]))
        last = end
    parts.append(text[last:])
    return "".join(parts)


# The deepest a JSON or JSONC text may nest its arrays and objects. Python's
# parser stops at a depth that differs by version (about 990 levels on 3.9 to
# 3.11, about 9,970 on 3.12 and 3.13, and on 3.14 whatever the thread's stack
# holds: about 116,000 on macOS's main thread, under 58,000 on an 8 MB stack),
# and a reader that recursed over what it parsed met its own limit at 1,000
# frames, so one file was read on one version and took a scanner down on
# another. Every version now refuses JSON nested past this depth (see
# `_parse_json`); real configs nest under 20.
JSON_MAX_NESTING = 500

# What the depth count keeps of a text, as ASCII bytes: quotes and brackets,
# and how each bracket moves the depth. It reads the text this many characters
# at a time.
_JSON_NOT_MARKS = bytes(b for b in range(256) if b not in b'"[]{}')
_JSON_BRACKET_STEP = tuple(1 if b in b"[{" else -1 if b in b"]}" else 0 for b in range(256))
_JSON_COUNT_CHUNK = 1 << 16


def _json_nesting(text: str) -> int:
    """The deepest nesting of `[` and `{` in `text` outside strings. On JSON, and
    on the part of a text `json.loads` read before an error, it is the depth the
    parser descended to.

    The text is read a chunk at a time. In each, escaped backslashes and then
    escaped quotes are dropped, pairing backslashes from the left as JSON
    does, so every quote left opens or closes a string; then everything but
    quotes and brackets, and the brackets outside strings, those after an
    even number of quotes, are summed. An escape cut by the end of a chunk and
    the parity of the quotes carry over to the next, so an unterminated
    string runs to the end and no bracket after it counts. Each step is a C
    pass over one chunk, so the count takes time linear in the text and
    memory for a chunk: a regex that skipped strings kept a backtracking
    record of about 140 bytes for every escape, so 30 MB of JSON whose one
    string held 15 million `\\n` took 2.1 GB to count.
    """
    best = depth = 0
    inside = escaped = False
    for start in range(0, len(text), _JSON_COUNT_CHUNK):
        chunk = text[start:start + _JSON_COUNT_CHUNK]
        if escaped and chunk[0] in '\\"':
            chunk = chunk[1:]  # the second half of an escape the last chunk began
        chunk = chunk.replace("\\\\", "")
        escaped = chunk.endswith("\\")
        marks = chunk.replace('\\"', "").encode("ascii", "ignore").translate(None, _JSON_NOT_MARKS)
        parts = marks.split(b'"')
        brackets = b"".join(parts[1::2] if inside else parts[0::2])
        if brackets:
            best = max(best, max(accumulate(map(_JSON_BRACKET_STEP.__getitem__, brackets), initial=depth)))
            depth += brackets.count(b"[") + brackets.count(b"{") - brackets.count(b"]") - brackets.count(b"}")
        inside ^= len(parts) % 2 == 0
    return best


# Python's limit on the digits `int()` converts from text: 4,300 by default since
# 3.9.14, 3.10.7 and 3.11, and none before (0 also means none). `json.loads`
# converts each integer with `int()`, so one longer than the limit raised a plain
# ValueError, which no reader catches as a parse error: a 5,000-digit number in
# one file took 29 scanners down, with their findings on every other file.
_INT_MAX_STR_DIGITS: Callable[[], int] | None = getattr(sys, "get_int_max_str_digits", None)


def _json_int(digits: str) -> int | float:
    """An integer of a JSON text: `int(digits)` where Python converts it, as
    `json.loads` does, and otherwise `float(digits)`, the nearest value a reader
    can still compare (inf past 309 digits) where `int()` would raise."""
    limit = _INT_MAX_STR_DIGITS() if _INT_MAX_STR_DIGITS is not None else 0
    if limit and len(digits) - digits.startswith("-") > limit:
        return float(digits)
    return int(digits)


def _json_loads(text: str) -> Any:
    """`json.loads(text)`, an integer past Python's digit limit read by
    `_json_int`. The hook is a Python call for every integer, which made a text
    of a million integers four times as slow to parse, so it is used only in a
    second parse, after the first raised a ValueError that is no
    JSONDecodeError: only such an integer raises one."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise
    except ValueError:
        return json.loads(text, parse_int=_json_int)


def _json_past_limit(text: str) -> bool:
    """Whether `text` nests past `JSON_MAX_NESTING`. A text with no more opening
    brackets than the limit cannot, so most texts are not counted at all."""
    return text.count("[") + text.count("{") > JSON_MAX_NESTING and _json_nesting(text) > JSON_MAX_NESTING


def _too_deep(text: str, path: Path | str | None) -> Exception:
    """The refusal of JSON nested past `JSON_MAX_NESTING`: recorded against
    `path` and returned as a `RefusedJSON`, or, without a path, a RecursionError
    (`_TooDeepToParse`, whose message is the reason), as the parser's own
    overflow propagates."""
    reason = f"JSON nested deeper than {JSON_MAX_NESTING} levels"
    if path is None:
        return _TooDeepToParse(reason)
    refuse(path, reason)
    return RefusedJSON(reason, text, 0)


def _parse_json(text: str, path: Path | str | None) -> Any:
    """`json.loads(text)`, refused when it nests past `JSON_MAX_NESTING`.

    The parser reads first, and then how deep it went is counted: the whole
    text when it read it, the part before the error when it stopped at one,
    and the whole text when it ran out of stack. So every version refuses the
    same texts, and a text that stops being JSON before the limit raises its
    JSONDecodeError as before, however many brackets follow: 60,000
    `capabilities: {` are no JSON from the first character, not JSON nested
    60,000 deep. Without a path, an overflow the count does not explain (the
    caller's own stack was deep) propagates as it did.
    """
    try:
        data = _json_loads(text)
    except json.JSONDecodeError as exc:
        if _json_past_limit(text[: exc.pos]):
            raise _too_deep(text, path) from None
        raise
    except _OVERFLOW as exc:
        if _json_past_limit(text):
            raise _too_deep(text, path) from None
        if path is None:
            raise
        raise _refused_json(text, path, exc) from None
    if _json_past_limit(text):
        raise _too_deep(text, path)
    return data


def loads_jsonc(text: str, path: Path | str | None = None) -> Any:
    """Parse `text` as JSON or, when that fails, as JSONC (see `strip_jsonc`).

    The one reader for MCP client configs and the VS Code files beside them.
    Valid JSON is parsed by `json.loads` alone, so a reader that switches to
    this returns what it did for every file it could read before, and only
    stops skipping the ones with comments or trailing commas. A file that is
    invalid even as JSONC raises `json.JSONDecodeError` as before, with a
    position that matches the raw text. One nested deeper than
    `JSON_MAX_NESTING`, read either way, is refused against `path`, as
    `loads_json` refuses it, and without a path a RecursionError propagates,
    as it did.
    """
    try:
        return _parse_json(text, path)
    except RefusedJSON:
        raise
    except json.JSONDecodeError:
        pass
    return _parse_json(strip_jsonc(text), path)


#: The keys an MCP client config keeps its server map under. `mcpServers` is the
#: key of Claude Code, Cursor, Windsurf, Gemini CLI and most other clients; VS
#: Code's `.vscode/mcp.json` keeps the same map under `servers`.
MCP_SERVER_KEYS: tuple[str, ...] = ("mcpServers", "servers")

#: The map key ZCode's config files use: the server map sits one level down,
#: under `mcp.servers`, which is how ZCode's own source names it.
ZCODE_SERVER_KEY = "mcp.servers"

#: The workspace config files ZCode reads, in every directory from the git root
#: down to the folder it opens (`workspace-hook-config.ts`, v3.15.1).
ZCODE_WORKSPACE_CONFIG_NAMES: tuple[str, ...] = ("zcode.json", ".zcode/config.json")


def mcp_server_maps(data: object, path: Path | None = None) -> list[tuple[str, dict[str, Any]]]:
    """Return ``(key, servers)`` for each server map at the top of an MCP config.

    A scanner that read only ``mcpServers`` passed every server in a VS Code
    ``.vscode/mcp.json`` unread, so a cleartext URL, a literal token or an
    unpinned ``npx`` package there came back clean. This is the one place that
    knows both keys; ``mcp_stdio_launcher`` read both already.

    Only a JSON object counts as a map, and only at the top level: a ``servers``
    array (an MCP Registry listing) is not one, and neither is a map nested under
    another key, such as a utcp call template's ``config.mcpServers``
    (``test_utcp_call_template_is_not_seen_by_the_cleartext_class_rule`` pins
    that). When a file has both keys each map comes back on its own, because a
    client loads one of them, not both.

    ZCode's own files are the exception, so a caller that has the file's `path`
    passes it. ZCode keeps the map of ``zcode.json`` and ``.zcode/config.json``
    under ``mcp.servers`` and reads nothing else there, and it connects every
    server in it when a workspace is opened (CVE-2026-88755). That map alone
    comes back, under `ZCODE_SERVER_KEY`, which no file spells literally, so a
    caller that looks the key up in the text looks for ``"servers"``. Anywhere
    else the nesting is no client's map: in a ``.vscode/mcp.json`` VS Code reads
    the top-level ``servers`` only, and ``test_supply_chain`` pins that it stays
    unread.
    """
    if not isinstance(data, dict):
        return []
    if path is not None and is_zcode_workspace_config(path):
        nested = data.get("mcp")
        servers = nested.get("servers") if isinstance(nested, dict) else None
        return [(ZCODE_SERVER_KEY, servers)] if isinstance(servers, dict) else []
    return [(key, data[key]) for key in MCP_SERVER_KEYS if isinstance(data.get(key), dict)]


def is_zcode_workspace_config(path: Path) -> bool:
    """Whether `path` is one of the workspace config files ZCode reads."""
    if path.name == "zcode.json":
        return True
    return path.name == "config.json" and path.parent.name == ".zcode"


def zcode_workspace_configs(project_root: Path) -> list[Path]:
    """Every ZCode workspace config file below `project_root`, sorted.

    ZCode reads both names in every directory from the git root down to the
    folder it is opened in, so a nested one loads when a subdirectory is opened,
    and every level is returned. Neither name matches the ``*mcp*.json`` glob the
    MCP config readers use. The user's own ``~/.zcode/cli/config.json`` sits in a
    ``cli`` directory and is not a workspace file.
    """
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        here = Path(dirpath)
        if "zcode.json" in filenames:
            found.append(here / "zcode.json")
        if here.name == ".zcode" and "config.json" in filenames:
            found.append(here / "config.json")
    return sorted(found)


def iter_mcp_servers(data: object) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(name, server)`` for every server object in a config's server maps.

    The maps come from `mcp_server_maps`, in key order and each on its own,
    never merged. An entry that is not a JSON object is skipped, and a top
    level that is not an object yields nothing: the scanners glob `*mcp*.json`,
    which reaches files holding a JSON array, and `data.get` on one raised
    `AttributeError` and took the scanner down.

    A module that reads both maps does it through here or `mcp_server_maps`.
    pinning, toxic_flow, supply_chain, tool_poisoning and mcp_stdio_launcher
    each kept a copy of this loop until they were routed here, and
    `tests/test_mcp_config.py` fails on a module that writes another.
    """
    for _key, servers in mcp_server_maps(data):
        for name, server in servers.items():
            if isinstance(server, dict):
                yield str(name), server


def _entry_handlers(entry: object) -> Iterator[dict[str, Any]]:
    """Yield the hook handlers one entry of an event's list contributes.

    An entry with a ``hooks`` array is a matcher group and contributes each
    object in that array. Any other object entry is itself a handler, the flat
    shape. A group that also carries its own ``command`` contributes that entry
    as well: a command string in a hook entry is read wherever it sits, rather
    than guessing which of the two a client would run.
    """
    if not isinstance(entry, dict):
        return
    nested = entry.get("hooks")
    if isinstance(nested, list):
        for handler in nested:
            if isinstance(handler, dict):
                yield handler
        if "command" in entry:
            yield entry
    else:
        yield entry


def iter_hook_handlers(hooks: object) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(event, handler)`` for every handler in a settings ``hooks`` block.

    Claude Code documents three levels: an event maps to a list of matcher
    groups, and each group's own ``hooks`` array holds the handlers that run::

        {"hooks": {"PreToolUse": [{"matcher": "Bash",
                                   "hooks": [{"type": "command", "command": "..."}]}]}}

    The hook scanner used to read only a flat ``{"command": ...}`` placed straight
    under the event, which is not a shape Claude Code documents, so a hook written
    the way the documentation shows was never analysed. A matcher group has no
    ``command`` of its own, so every AAK-HOOK rule passed it, and AAK-HOOK-007
    counted a group of twelve hooks as one.

    Both shapes are read, in any mix, as are an event mapped to a single object
    instead of a list, and a top-level list of entries that name their own
    ``event``. A handler of any ``type`` is yielded (``command``, ``http``,
    ``prompt``, ``agent``, ``mcp_tool``): a counter wants all of them, and a
    command rule asks ``hook_command`` for the text, which only a command has.
    """
    if isinstance(hooks, dict):
        for event, entries in hooks.items():
            if isinstance(entries, dict):
                entries = [entries]
            if not isinstance(entries, list):
                continue
            for entry in entries:
                for handler in _entry_handlers(entry):
                    yield str(event), handler
    elif isinstance(hooks, list):
        for entry in hooks:
            if isinstance(entry, dict):
                event = str(entry.get("event", "unknown"))
                for handler in _entry_handlers(entry):
                    yield event, handler


def hook_command(handler: dict[str, Any]) -> str:
    """The command line a hook handler runs, or "" when it runs none.

    That is ``command``, followed by ``args`` when it is set. With ``args`` Claude
    Code runs exec form: ``command`` is only the executable, spawned directly
    with ``args`` as its argument vector, so ``{"command": "bash", "args": ["-c",
    "curl ..."]}`` keeps the whole payload in ``args``. Joining them gives the
    command rules the same text the shell form would have carried. A handler
    without a string ``command`` (``http``, ``prompt``, ``agent``, ``mcp_tool``)
    runs no command line.
    """
    command = handler.get("command")
    if not isinstance(command, str) or not command:
        return ""
    args = handler.get("args")
    if isinstance(args, list):
        words = [str(a) for a in args if isinstance(a, (str, int, float))]
        if words:
            return " ".join([command, *words])
    return command


# The characters that change state in TS/JS code, in a quoted string, in a
# template literal's text and in a regex literal. Everything between two of them
# is copied unread, so the scan jumps from one to the next in C.
_JS_CODE_SPECIAL_RE = re.compile(r"""[/'"`{}]""")
_JS_QUOTED_SPECIAL_RE = {"'": re.compile(r"['\\\n]"), '"': re.compile(r'["\\\n]')}
_JS_TEMPLATE_SPECIAL_RE = re.compile(r"[`\\$]")
_JS_REGEX_SPECIAL_RE = re.compile(r"[/\\\[\]\n]")
_JS_IDENT_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"
)
# A `/` after one of these words starts a regex literal, not a division.
_JS_REGEX_AFTER_WORDS = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await",
})
# Stands for the end of a literal operand (string, template, regex): a `/`
# after it is a division.
_JS_OPERAND = "a"


def _js_regex_allowed(prev: str, word: str) -> bool:
    """Whether a `/` read after `prev` (and the word ending in it) opens a regex.

    The usual tokenizer heuristic: after an operand (an identifier, a number, a
    literal, `)`, `]`, `}`) a slash divides; after an operator, an opening
    bracket, a separator, a keyword such as `return`, or at the start of the
    file it opens a regex literal.
    """
    if prev in _JS_IDENT_CHARS:
        return word in _JS_REGEX_AFTER_WORDS
    return prev not in (")", "]", "}")


def _js_skip_quoted(text: str, start: int) -> int:
    """Index just past the string literal opened by the quote at `start`.

    A backslash escapes the next character, an escaped newline included. An
    unescaped newline ends an unterminated string where it stands, since a
    quoted string cannot cross a line.
    """
    special = _JS_QUOTED_SPECIAL_RE[text[start]]
    i = start + 1
    while True:
        m = special.search(text, i)
        if m is None:
            return len(text)
        if m.group() == "\\":
            i = m.start() + 2
        elif m.group() == "\n":
            return m.start()
        else:
            return m.start() + 1


def _js_skip_regex(text: str, start: int, stop: int | None = None) -> int:
    """Index just past the regex literal (and its flags) opened at `start`.

    `[...]` is a class, inside which `/` does not close. A newline before the
    closing `/` means the slash was a division after all: stop there, having
    blanked nothing, and let the caller carry on. With `stop`, the scan ends
    there at the latest: a caller reading a bounded span would otherwise read
    to the end of the file from an unclosed `[`, once per span.
    """
    n = len(text) if stop is None else stop
    i = start + 1
    in_class = False
    while True:
        m = _JS_REGEX_SPECIAL_RE.search(text, i, n)
        if m is None:
            return n
        c, at = m.group(), m.start()
        if c == "\\":
            i = at + 2
        elif c == "\n":
            return at
        elif c == "[":
            in_class, i = True, at + 1
        elif c == "]":
            in_class, i = False, at + 1
        elif in_class:
            i = at + 1
        else:
            end = at + 1
            while end < n and text[end] in _JS_IDENT_CHARS:
                end += 1
            return end


def blank_js_comments(text: str) -> str:
    """Blank TS/JS comments with spaces, leaving every literal intact.

    `_ssrf_reach` stripped comments with two regexes, `/\\*.*?\\*/` and
    `//[^\\n]*`, which do not know what a string is, and seven other scanners
    still carry the same pair. `//` inside a literal therefore started a
    "comment" that ran to the end of the line, and every URL with a scheme
    carries one: `fetch("http://169.254.169.254/latest/meta-data/")` came out as
    `fetch("http:` followed by spaces, the call lost its closing parenthesis, and
    no call site was found. AAK-SSRF-002 and 003 never saw a TS literal URL with
    a scheme, and AAK-SSRF-001 and 005 lost a caller-controlled host as soon as
    it followed `http://` in a template literal. The Python backend, which reads
    `ast`, was unaffected.

    This scan tracks the token a `/` sits in: a quoted string (with escapes; an
    unescaped newline ends it), a template literal (its text is literal, and the
    code in each `${...}` is scanned as code, nested templates included), a regex
    literal (by the usual operand/operator heuristic, so a URL pattern such as
    `/^https?:\\/\\//` does not eat the rest of its line either), and only then a
    comment. Comments become spaces and newlines stay, so offsets and line
    numbers still match the source. It is linear: every search resumes where
    the last one stopped.
    """
    n = len(text)
    out = list(text)
    expr_depths: list[int] = []  # brace depth inside each open `${ ... }`
    in_template = False
    prev, word = "", ""  # last significant code character, and the word it ends
    i = 0

    def blank(start: int, end: int) -> None:
        for k in range(start, end):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        if in_template:
            m = _JS_TEMPLATE_SPECIAL_RE.search(text, i)
            if m is None:
                break
            at, c = m.start(), m.group()
            if c == "\\":
                i = at + 2
            elif c == "`":
                in_template, i = False, at + 1
                prev, word = _JS_OPERAND, ""
            elif text.startswith("${", at):
                expr_depths.append(0)
                in_template, i = False, at + 2
                prev, word = "{", ""
            else:
                i = at + 1
            continue

        m = _JS_CODE_SPECIAL_RE.search(text, i)
        at = n if m is None else m.start()
        k = at - 1
        while k >= i and text[k].isspace():
            k -= 1
        if k >= i:
            prev = text[k]
            word = ""
            if prev in _JS_IDENT_CHARS:
                s = k
                while s > i and text[s - 1] in _JS_IDENT_CHARS:
                    s -= 1
                word = text[s:k + 1]
            elif prev in "+-" and k > i and text[k - 1] == prev:
                prev = _JS_OPERAND  # postfix `n++` / `n--`: a slash after it divides
        if m is None:
            break
        c = m.group()
        if c == "/":
            nxt = text[at + 1] if at + 1 < n else ""
            if nxt == "/":
                end = text.find("\n", at)
                end = n if end == -1 else end
                blank(at, end)
                i = end
            elif nxt == "*":
                end = text.find("*/", at + 2)
                end = n if end == -1 else end + 2
                blank(at, end)
                i = end
            elif _js_regex_allowed(prev, word):
                i = _js_skip_regex(text, at)
                prev, word = _JS_OPERAND, ""
            else:
                i = at + 1
                prev, word = "/", ""
        elif c in "'\"":
            i = _js_skip_quoted(text, at)
            prev, word = _JS_OPERAND, ""
        elif c == "`":
            in_template, i = True, at + 1
        elif c == "{":
            if expr_depths:
                expr_depths[-1] += 1
            i = at + 1
            prev, word = "{", ""
        else:  # "}"
            if expr_depths and expr_depths[-1] == 0:
                expr_depths.pop()
                in_template = True
            elif expr_depths:
                expr_depths[-1] -= 1
            i = at + 1
            prev, word = "}", ""
    return "".join(out)


#: MCP SDK distribution names on PyPI, PEP 503-normalised (lower case, any run
#: of `-`, `_` and `.` as one `-`).
MCP_PY_SDK_NAMES = frozenset({"mcp", "modelcontextprotocol", "model-context-protocol"})
MCP_TS_SDK_NAMES = (
    "@modelcontextprotocol/sdk",
    "@anthropic-ai/mcp",
    "@anthropic-ai/claude-agent-sdk",
)
_MCP_JAVA_SDK_TOKEN = "io.modelcontextprotocol"
_MCP_CARGO_LINE_RE = re.compile(r"^[ \t]*(?:mcp|modelcontextprotocol)[ \t]*=", re.MULTILINE)
# A PEP 508 requirement opens with the distribution name. Trailing `.`, `_`
# and `-` are trimmed in code rather than in the pattern, which keeps the
# pattern free of overlapping repeats.
_REQUIREMENT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_NAME_SEPARATORS_RE = re.compile(r"[-_.]+")


def _pep503(name: str) -> str:
    return _NAME_SEPARATORS_RE.sub("-", name).lower()


def _requirement_name(spec: object) -> str | None:
    """The normalised name a PEP 508 requirement string (`mcp[cli]>=1.2.0`) names."""
    if not isinstance(spec, str):
        return None
    m = _REQUIREMENT_NAME_RE.match(spec.strip())
    return _pep503(m.group().rstrip("._-")) if m else None


def _pyproject_dependency_names(data: dict[str, Any]) -> set[str]:
    """Every distribution a parsed pyproject.toml depends on, under the tables
    the common tools write: `[project]` dependencies and optional dependencies,
    PEP 735 `[dependency-groups]`, Poetry's dependency tables (main, dev and
    groups), and uv's and PDM's dev dependencies."""
    names: set[str] = set()

    def specs(value: object) -> None:
        if isinstance(value, list):
            names.update(n for n in map(_requirement_name, value) if n)

    def spec_lists(value: object) -> None:
        if isinstance(value, dict):
            for item in value.values():
                specs(item)

    def table(value: object) -> None:
        if isinstance(value, dict):
            names.update(_pep503(str(key)) for key in value)

    project = data.get("project")
    if isinstance(project, dict):
        specs(project.get("dependencies"))
        spec_lists(project.get("optional-dependencies"))
    spec_lists(data.get("dependency-groups"))
    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            table(poetry.get("dependencies"))
            table(poetry.get("dev-dependencies"))
            groups = poetry.get("group")
            if isinstance(groups, dict):
                for group in groups.values():
                    if isinstance(group, dict):
                        table(group.get("dependencies"))
        uv = tool.get("uv")
        if isinstance(uv, dict):
            specs(uv.get("dev-dependencies"))
        pdm = tool.get("pdm")
        if isinstance(pdm, dict):
            spec_lists(pdm.get("dev-dependencies"))
    return names


def _pyproject_declares_mcp(text: str, path: Path) -> bool:
    try:
        data = loads_toml(text, path)
    except (tomllib.TOMLDecodeError, ValueError):
        data = None
    if isinstance(data, dict) and _pyproject_dependency_names(data) & MCP_PY_SDK_NAMES:
        return True
    # The old test, kept so nothing it accepted is lost (an unparsable file
    # included): the bare quoted name anywhere in the file.
    return any(f'"{n}"' in text or f"'{n}'" in text for n in sorted(MCP_PY_SDK_NAMES))


def _requirements_declare_mcp(text: str) -> bool:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        if _requirement_name(line) in MCP_PY_SDK_NAMES:
            return True
    return False


def _read_text(path: Path) -> str | None:
    try:
        return read_text_capped(path, MANIFEST_MAX_BYTES, errors="replace")
    except OSError:
        return None


def declares_mcp_sdk(project_root: Path) -> tuple[bool, list[str]]:
    """Whether a manifest at the project root declares an MCP SDK, and which.

    The gate in front of AAK-MCP-STATELESS-001..004, the source half of
    AAK-MCP-SAMPLING-001, and AAK-ANTHROPIC-SDK-001. Its three copies took
    pyproject.toml only as the exact quoted string `"mcp"`, so
    `"mcp[cli]>=1.2.0"`, the way most servers declare it, and Poetry's
    `mcp = "^1.2.0"` never opened it, and the requirements reader cut a line
    at its first `=`, so `mcp~=1.2.0` came out as `mcp~`. Those rules never
    ran for a typical Python server.

    pyproject.toml is parsed and read through its dependency tables (see
    `_pyproject_dependency_names`), and each requirement's name is taken the
    PEP 508 way and compared PEP 503-normalised, so case, extras, any version
    operator, environment markers and `name @ url` all work. The old quoted
    string test still runs too, so nothing it accepted is lost. package.json,
    Maven and Gradle builds and Cargo.toml are read as before.

    Returns:
        ``(declared, manifests)``: manifests are paths relative to the root.
    """
    manifests: list[str] = []

    pyproject = project_root / "pyproject.toml"
    if pyproject.is_file():
        text = _read_text(pyproject)
        if text is not None and _pyproject_declares_mcp(text, pyproject):
            manifests.append("pyproject.toml")

    for req in sorted(project_root.glob("requirements*.txt")):
        text = _read_text(req)
        if text is not None and _requirements_declare_mcp(text):
            manifests.append(str(req.relative_to(project_root)))

    pkg = project_root / "package.json"
    if pkg.is_file():
        text = _read_text(pkg)
        try:
            data = loads_json(text, pkg) if text is not None else {}
        except json.JSONDecodeError:
            data = {}
        if isinstance(data, dict):
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                deps = data.get(section) or {}
                if isinstance(deps, dict) and any(n in deps for n in MCP_TS_SDK_NAMES):
                    manifests.append("package.json")
                    break

    for build in ("pom.xml", "build.gradle", "build.gradle.kts"):
        path = project_root / build
        if path.is_file():
            text = _read_text(path)
            if text is not None and _MCP_JAVA_SDK_TOKEN in text:
                manifests.append(build)

    cargo = project_root / "Cargo.toml"
    if cargo.is_file():
        text = _read_text(cargo)
        if text is not None and _MCP_CARGO_LINE_RE.search(text):
            manifests.append("Cargo.toml")

    return bool(manifests), manifests


# ---- Reading a file the scanned repository chose -------------------------------
#
# A repository can commit a symlink, and a checkout makes it one: `SKILL.md ->
# /dev/zero`, or a link to a FIFO. `Path.is_file()` follows it and says False for
# both, but `stat().st_size` says 0, so the 31 scanners that compared the size
# with a cap and then read, or only read, waited on the FIFO for a writer that
# never came, or would read /dev/zero until memory ran out. A regular file can be
# any size, and 20 scanners read it whole before comparing its length with their
# cap: a 200 MB file cost each of them 200 MB of memory before it was skipped,
# and two of them were still reading after 90 seconds.

#: The cap a reader of an MCP or agent config uses.
CONFIG_MAX_BYTES = 1_000_000
#: The cap a reader of a source file uses.
SOURCE_MAX_BYTES = 512_000
#: The cap the pin table puts on a dependency manifest (`_manifest_deps`'s
#: `MAX_MANIFEST_BYTES`, which imports this module).
MANIFEST_MAX_BYTES = 2_000_000

# Open without waiting, so a FIFO put in the file's place after the type check
# cannot hold the open, and without taking a terminal as the controlling one.
# Windows has neither flag, and neither applies there.
_READ_FLAGS = (
    os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0)
)


class FileNotRead(OSError):
    """A path `read_bytes_capped` does not read: not a regular file, or over its cap."""


def _check_readable(st: os.stat_result, path: Path | str, max_bytes: int) -> None:
    if not stat.S_ISREG(st.st_mode):
        raise FileNotRead(errno.EINVAL, "not a regular file", str(path))
    if st.st_size > max_bytes:
        raise FileNotRead(errno.EFBIG, f"larger than {max_bytes:,} bytes", str(path))


def read_bytes_capped(path: Path | str, max_bytes: int) -> bytes:
    """The bytes of `path`, when it is a regular file of at most `max_bytes`.

    A symlink is followed and its target judged. A FIFO, a device, a socket or
    a directory raises `FileNotRead`, an OSError, before it is opened, so a
    reader's `except OSError` skips it as it skips a file it cannot open:
    nothing can read one as a config, so the skip is silent. A file over
    `max_bytes`, the reader's stated cap, raises the same before a byte of it
    is read. Type and size are checked again on the open descriptor, and no
    more than `max_bytes + 1` bytes are ever read, so a size the system
    misreports, or a file that grows, still stops at the cap. Any other
    OSError propagates, as it does from `Path.read_bytes`.
    """
    _check_readable(os.stat(path), path, max_bytes)
    fd = os.open(path, _READ_FLAGS)
    try:
        st = os.fstat(fd)
        _check_readable(st, path, max_bytes)
        chunks: list[bytes] = []
        left = max_bytes + 1
        # The first read asks for the size `fstat` gives and one byte more, so
        # a file that is what it says is read in one buffer, not joined from
        # pieces: a 32 MB lockfile read in 1 MB pieces held them and their join
        # at once, twice the file. Any later read stays inside the cap.
        step = st.st_size + 1
        while left > 0:
            chunk = os.read(fd, min(left, step))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
            step = 1 << 20
    finally:
        os.close(fd)
    data = chunks[0] if len(chunks) == 1 else b"".join(chunks)
    if len(data) > max_bytes:
        raise FileNotRead(errno.EFBIG, f"larger than {max_bytes:,} bytes", str(path))
    return data


def read_text_capped(
    path: Path | str, max_bytes: int, encoding: str | None = "utf-8", errors: str | None = None
) -> str:
    """`Path(path).read_text(encoding, errors)` for a regular file of at most
    `max_bytes` bytes, and `FileNotRead` for any other path (see
    `read_bytes_capped`).

    The text is decoded as `read_text` decodes it, line endings translated, so
    a reader that switches to this sees the same text for every file it read
    before, and a decoding error raises as it did.
    """
    data = read_bytes_capped(path, max_bytes)
    return io.TextIOWrapper(io.BytesIO(data), encoding=encoding, errors=errors).read()


# ---- A file the parsers refuse ---------------------------------------------------
#
# Python's JSON and TOML parsers, PyYAML's composer and `ast.parse` all recurse,
# so a file nested a few thousand levels deep makes them raise RecursionError or
# MemoryError, and the scanners caught neither: the scanner died, and every
# finding it would have made on every other file died with it. One 200 KB
# `.mcp.json` blinded 12 scanners at once, so a crafted file could hide a
# CRITICAL finding in another, and `--allow-scanner-failure` then passed the
# scan. A file refused now costs that file alone. The refusal is never silent:
# a client may read what AAK refused (V8's JSON parser and Bun's YAML parser
# take inputs Python's recursive parsers reject), and a file skipped without a
# word would hide its servers and hooks from every rule. `run_scan` collects
# each scanner's refusals through `collecting_refusals` and reports each one as
# AAK-INTERNAL-SCANNER-FAIL against its file, so the scan is INCOMPLETE, as the
# crash left it, without the crash's cost to every other file.

_REFUSED: ContextVar[dict[str, str] | None] = ContextVar("aak_refused", default=None)
_OVERFLOW = (RecursionError, MemoryError)


@contextmanager
def collecting_refusals() -> Iterator[dict[str, str]]:
    """Collect `{path: reason}` for every file refused while the block runs."""
    refused: dict[str, str] = {}
    token = _REFUSED.set(refused)
    try:
        yield refused
    finally:
        _REFUSED.reset(token)


def refuse(path: Path | str | None, reason: str) -> None:
    """Record that the running scanner did not read `path`, and why.

    Once per file, with its first reason. Nothing is recorded outside
    `collecting_refusals`; the caller's own error handling then decides, as it
    did for any file it could not parse. The parse helpers below take the
    path, and without one let the RecursionError or MemoryError propagate, so
    a refusal is never lost to a missing path: the caller contains it with
    `refusing_overflow`, or the scanner fails as it did.
    """
    refused = _REFUSED.get()
    if refused is not None and path is not None:
        refused.setdefault(str(path), reason)



@contextmanager
def refusing_overflow(path: Path | str, what: str = "syntax tree") -> Iterator[None]:
    """Contain a RecursionError or MemoryError from the block to `path`.

    For a scanner's per-file analysis that recurses over what it parsed (an
    `ast.NodeVisitor`, a helper that follows an attribute chain): a 3,000-term
    expression parses, then takes the visitor past the recursion limit. The
    file is refused, its findings so far are dropped with the block, and the
    scanner goes on with the next file.
    """
    try:
        yield
    except _OVERFLOW as exc:
        if isinstance(exc, _TooDeepToParse):
            refuse(path, str(exc))
        else:
            refuse(path, f"{what} too deep for this scanner to walk ({type(exc).__name__})")


class RefusedJSON(json.JSONDecodeError):
    """A JSON text the parse helpers refused, raised as the error a reader catches."""


class RefusedSource(SyntaxError):
    """A Python source `parse_python` refused, raised as the error a reader catches."""


class RefusedTOML(tomllib.TOMLDecodeError):
    """A TOML text `loads_toml` refused, raised as the error a reader catches."""


class RefusedYAML(yaml.YAMLError):
    """A YAML text the YAML loaders refused, raised as the error a reader catches."""


def _refused_json(text: str, path: Path | str, exc: BaseException) -> RefusedJSON:
    reason = f"JSON nested too deep for Python's parser ({type(exc).__name__})"
    refuse(path, reason)
    return RefusedJSON(reason, text, 0)


def loads_json(text: str | bytes, path: Path | str | None) -> Any:
    """`json.loads(text)`, refusing a text nested deeper than
    `JSON_MAX_NESTING` (see `_parse_json`), or too deep for Python's parser.

    The refusal is recorded against `path` and raised as `RefusedJSON`, a
    `json.JSONDecodeError`, so the reader skips the file as it skips invalid
    JSON while `run_scan` reports it. Without a path a RecursionError
    propagates (see `refuse`). Bytes are decoded as `json.loads` decodes them.
    """
    doc = text if isinstance(text, str) else text.decode(json.detect_encoding(text), "surrogatepass")
    return _parse_json(doc, path)


# A filename no file can have, for `ast.parse`. On a SyntaxError CPython reads
# the offending line back from the file it was given, and 3.9 (3.9.6 and
# 3.9.25, which CI installs) reads it into a 1,000-byte buffer, then decodes as
# many bytes from that buffer as the error's column: an out-of-bounds read as
# long as the line. A crafted `.py` parsed under its own path crashed the
# process 1 run in 24 inside ssrf_toctou's 1 MB source cap, and every run at
# 1.1 MB, whatever a caller caught. A relative name such as "<unknown>" is no
# answer: a scan runs inside the repository, which can commit a file of that
# name. `/dev/null` is not a directory, and `<` and `>` are not allowed in a
# Windows file name.
_PARSE_FILENAME = "/dev/null/<aak>"

# Before 3.11 CPython parses and builds the syntax tree recursively in C with no
# depth check, so a deep enough source overflows the C stack and the process
# dies (exit 139), past any `except`: 3.9.6 on a 120,000-term `a**a**...` chain
# or 42,000 nested lambda defaults, 3.10.19 on a flat 132,000-term `a+a+...`
# chain (263 KB).
# 3.9.25 and 3.10 refuse a deep recursive rule (MemoryError) but still build a
# left-recursive chain's tree recursively. 3.11 checks the depth and raises
# RecursionError or MemoryError instead. Before 3.11 a source therefore goes
# through `python_nesting_bound` first, and one whose bound passes
# `_PY_MAX_NESTING` is refused unparsed. The lowest crash measured, on 3.9.6,
# 3.9.25 and 3.10.19 with the default 8 MB stack, came at a bound of 120,000
# (that `a**a**...` chain; the lambda defaults, three levels each, came next at
# 126,000); the highest bound in 100,303 real files was 4,585 (see
# tests/test_refused_files.py). A source under the bound is parsed and walked
# like any other, and costs what its size does rather than its depth: in `aak
# scan` on 3.9.6, with every Python scanner's gate open (main's new gates
# included), 480 to 500 KB of chains just under 10,000 levels took 10 to 31 s
# of CPU and 508 KB of shallow chains, 100 terms each, 40 s; on 3.9.25, whose
# parser refuses the unary chains, 8 to 25 s and 33 s. Measured on the head
# rebased onto b189db60, best of two runs at a load average under 4. The same
# file's CPU time has moved by up to 60% from run to run on the machine
# measured, with its load and the cores a run landed on.
_SCREEN_SOURCES = sys.version_info < (3, 11)
_PY_MAX_NESTING = 10_000
# Defense in depth for a shape the screen does not foresee: before 3.11 the
# parse runs on a worker thread with 32 times the main thread's stack. The
# deepest crafted 1 MB sources overflow 64 MB and parse in 256 MB; one of
# 500 KB cost 0.2 to 0.35 s and 250 to 380 MB a parse on 3.9.6, once for each
# scanner that parsed it, which the screen spares.
_PARSE_STACK_BYTES = 256 * 1024 * 1024
# The worker, as (process id, executor, worker thread id), or (process id, None,
# 0) where no thread with that stack could start: a forked child has no threads
# and starts its own. It is started under the lock, which a forked child
# replaces, since a parent's thread may have held it at the fork.
_parse_worker: tuple[int, ThreadPoolExecutor | None, int] | None = None
_parse_worker_lock = threading.Lock()
_PARSE_ON_WORKER = sys.version_info < (3, 11)


def _new_parse_worker_lock() -> None:
    global _parse_worker_lock
    _parse_worker_lock = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_new_parse_worker_lock)

# One token of Python source, for the screen. A string is only opened here; its
# end is found by `_py_string_end`. Numbers are spelled out so that `1..real`
# leaves its attribute dots to be counted. Python reads a CR, an LF and a CRLF
# alike as a line break, so a backslash before any of them joins the next line:
# read as a stray character and a new line, a 900-term chain joined with `\`
# and CR alone was bounded at 9 levels for its 905.
_PY_TOKEN_RE = re.compile(
    r"(?P<str>[rRbBuUfF]{0,2}(?:'''|\"\"\"|'|\"))"
    r"|(?P<name>[^\W\d]\w*)"
    r"|(?P<num>(?:0[xXoObB][0-9a-fA-F_]+|\d[\d_]*(?:\.[\d_]*)?(?:[eE][+-]?[\d_]+)?"
    r"|\.\d[\d_]*(?:[eE][+-]?[\d_]+)?)[jJ]?)"
    r"|(?P<comment>\#[^\r\n]*)"
    r"|(?P<cont>\\(?:\r\n?|\n))"
    r"|(?P<nl>\r?\n|\r)"
    r"|(?P<blank>[ \t\f]+)"
    r"|(?P<open>[(\[{])"
    r"|(?P<close>[)\]}])"
    r"|(?P<sep>[,;])"
    r"|(?P<colon>:(?!=))"
    r"|(?P<op>\*\*=?|//=?|>>=?|<<=?|->|:=|!=|[-+*/%@&|^=<>]=?|[~.!$?`])"
    r"|(?P<other>.)",
    re.DOTALL,
)
# Keywords that join or wrap an expression, each a level at most.
_PY_CHAIN_WORDS = frozenset({"and", "or", "not", "if", "else", "in", "is", "lambda", "await", "yield", "for", "async"})
_PY_STRING_END_RE = {
    quote: re.compile(r"\\(?:\r\n|.)|" + re.escape(quote) + ("" if len(quote) == 3 else r"|\r|\n"), re.DOTALL)
    for quote in ("'''", '"""', "'", '"')
}
_FSTRING_FIELD_RE = re.compile(r"\{\{|\}\}|\{")


def _py_string_end(src: str, start: int, quote: str, end: int) -> int:
    """Index past the string whose body starts at `start`. A backslash escapes
    the next character, or the CRLF after it, raw or not; a one-line string
    ends at a line break, CR or LF. Read as an escaped CR followed by a line
    break, a backslash and CRLF ended the string early, so its closing quote
    opened another and the rest of the line went uncounted: 905 levels of
    chain after `'a\\<CRLF>'` were bounded at 7."""
    pattern = _PY_STRING_END_RE[quote]
    while True:
        m = pattern.search(src, start, end)
        if m is None:
            return end
        if m.group()[0] != "\\":
            return m.end()
        start = m.end()


def _fstring_depth(src: str, start: int, end: int) -> int:
    """A number no smaller than how deep the replacement fields of the f-string
    body `src[start:end]` nest, nested f-strings included: two levels for each
    f-string and one for each operator, keyword, bracket, colon or comma in a
    field. Before 3.12 a field is one token to the tokenizer, but the parser
    parses its expression, as deep as it is (131,000 terms crashed 3.9).
    Iterative: a nested f-string's body goes on a work list."""
    total = 0
    bodies = [(start, end)]
    while bodies:
        pos, stop = bodies.pop()
        total += 2
        while True:
            brace = _FSTRING_FIELD_RE.search(src, pos, stop)
            if brace is None:
                break
            pos, depth = brace.end(), (1 if brace.group() == "{" else 0)
            while pos < stop and depth:
                m = _PY_TOKEN_RE.match(src, pos, stop)
                assert m is not None  # `other` matches any character
                kind, tok = m.lastgroup, m.group()
                pos = m.end()
                if kind == "open":
                    depth += 1
                    total += 1
                elif kind == "close":
                    depth -= 1
                    total += 1 if depth else 0
                elif kind in ("op", "colon", "sep") or (kind == "name" and tok in _PY_CHAIN_WORDS):
                    total += 1
                elif kind == "str":
                    quote = tok.lstrip("rRbBuUfF")
                    body_end = _py_string_end(src, pos, quote, stop)
                    if "f" in tok[: len(tok) - len(quote)].lower():
                        bodies.append((pos, max(pos, body_end - len(quote))))
                    pos = body_end
    return total


def _indent_width(blank: str) -> int:
    width = 0
    for char in blank:
        width = (width // 8 + 1) * 8 if char == "\t" else 0 if char == "\f" else width + 1
    return width


def _nesting_bound(src: str) -> int:
    """A number no smaller than the depth of the tree `ast.parse(src)` would
    build, read in one linear pass that never recurses.

    Within a bracket each element, between commas, counts one level for every
    operator, chaining keyword (`not`, `and`, `if` ... `else`, `lambda`, ...),
    colon and call or subscript trailer, plus its deepest bracket; the elements
    of a bracket are siblings, so the bracket counts its deepest element plus
    one. Commas of a lambda's parameters (until its `:`) do not end the element,
    because the body nests inside the lambda. A logical line adds the `elif`
    ladders around it, two levels for each enclosing indentation and four for
    the statement, and an f-string adds what its fields hold
    (`_fstring_depth`). Every way a tree can nest one level deeper is counted,
    and only siblings take the maximum rather than the sum, so the bound is
    never below the tree's depth; it was not on any of 100,303 real files, where
    it reached 4,585 at most and 65 at the 99.9th percentile (see
    `_PY_MAX_NESTING`).
    """
    best = 1  # the module
    frames = [[0, 0, 0, 0]]  # per open bracket: chain, deepest bracket, deepest element, lambdas awaiting `:`
    ladders: list[list[int]] = []  # [indent, elifs] of each open if-elif ladder, outermost first
    elifs = 0
    indents: list[int] = []
    at_line_start, line_indent, context = True, 0, 0
    pos, n = 0, len(src)
    while pos < n:
        m = _PY_TOKEN_RE.match(src, pos)
        assert m is not None  # `other` matches any character
        kind, tok = m.lastgroup, m.group()
        pos = m.end()
        if kind in ("blank", "comment", "cont"):
            if kind == "blank" and at_line_start and len(frames) == 1:
                line_indent = _indent_width(tok)
            continue
        if kind == "nl":
            if len(frames) == 1:
                if not at_line_start:
                    frame = frames[0]
                    best = max(best, context + max(frame[2], frame[0] + frame[1]))
                    frames[0] = [0, 0, 0, 0]
                at_line_start, line_indent = True, 0
            continue
        if at_line_start and len(frames) == 1:
            at_line_start = False
            while indents and indents[-1] > line_indent:
                indents.pop()
            if not indents or indents[-1] < line_indent:
                indents.append(line_indent)
            while ladders and ladders[-1][0] > line_indent:
                elifs -= ladders.pop()[1]
            word = tok if kind == "name" else ""
            if word == "elif":
                if not ladders or ladders[-1][0] != line_indent:
                    ladders.append([line_indent, 0])
                ladders[-1][1] += 1
                elifs += 1
            elif word != "else" and ladders and ladders[-1][0] == line_indent:
                elifs -= ladders.pop()[1]
            context = elifs + 2 * len(indents) + 4
        frame = frames[-1]
        if kind == "name":
            if tok in _PY_CHAIN_WORDS:
                frame[0] += 1
                if tok == "lambda":
                    frame[3] += 1
        elif kind == "op":
            frame[0] += 1
        elif kind == "str":
            quote = tok.lstrip("rRbBuUfF")
            end = _py_string_end(src, pos, quote, n)
            if "f" in tok[: len(tok) - len(quote)].lower():
                frame[0] += _fstring_depth(src, pos, max(pos, end - len(quote)))
            pos = end
        elif kind == "open":
            frames.append([0, 0, 0, 0])
        elif kind == "close":
            if len(frames) > 1:
                done = frames.pop()
                frame = frames[-1]
                frame[1] = max(frame[1], max(done[2], done[0] + done[1]) + 1)
                frame[0] += 1
        elif kind == "sep":
            if frame[3]:
                frame[0] += 1
            else:
                frame[2] = max(frame[2], frame[0] + frame[1])
                frame[0] = frame[1] = 0
        elif kind == "colon":
            frame[0] += 1
            if frame[3]:
                frame[3] -= 1
    while len(frames) > 1:  # brackets the text never closed
        done = frames.pop()
        frames[-1][1] = max(frames[-1][1], max(done[2], done[0] + done[1]) + 1)
    frame = frames[0]
    return max(best, context + max(frame[2], frame[0] + frame[1]))


# Each source's bound, by a digest of its text. Scanners run one after another
# over every file, so the screen is asked about a file once by each scanner that
# parses it, 27 for a file that opens every gate: a cache of the last few
# sources missed on any project with more files than it held. A 16-byte digest
# and an int a file keep 65,536 files to about 6 MB, and the table is emptied
# when full, so a long-lived process (`aak watch`, the language server) stays
# bounded.
_BOUNDS: dict[bytes, int] = {}
_BOUNDS_MAX = 65_536


def python_nesting_bound(src: str) -> int:
    """`_nesting_bound(src)`, computed once for each distinct text."""
    key = hashlib.blake2b(src.encode("utf-8", "surrogatepass"), digest_size=16).digest()
    bound = _BOUNDS.get(key)
    if bound is None:
        bound = _nesting_bound(src)
        if len(_BOUNDS) >= _BOUNDS_MAX:
            _BOUNDS.clear()
        _BOUNDS[key] = bound
    return bound


class _TooDeepToParse(RecursionError):
    """The screen's refusal, for a caller that contains it with `refusing_overflow`."""


def _parse_quietly(source: str | bytes, filename: str) -> ast.Module:
    """`ast.parse` with the compiler's warnings about the source ignored.

    A warning about the scanned code (an invalid escape sequence is a
    SyntaxWarning on 3.12 and a DeprecationWarning before) is not AAK's to
    show: every scanner that parsed the file printed it again, 21 lines for
    one escape on 3.12, and under `-W error` it turned a file that parses into
    one that does not, so the file's findings were dropped without a word.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ast.parse(source, filename)


def _large_stack_worker() -> ThreadPoolExecutor | None:
    """The worker thread with `_PARSE_STACK_BYTES` of stack, started on first
    use; None where a thread's stack size cannot be set or no such thread can
    start (an address-space or process limit), and the caller works in place
    with the default recursion limit, as `_ast_parse` and `walk_tree` do. A
    thread that could not start made every parse raise RuntimeError, and with
    it every Python scanner.

    The stack size is the process's while it is set, so the worker starts
    under a lock. Two threads parsing for the first time at once could each
    start one, the one kept having started under the size the other had
    already put back, and leave 256 MB as the size of every later thread.
    """
    global _parse_worker
    pid = os.getpid()
    worker = _parse_worker
    if worker is None or worker[0] != pid:
        with _parse_worker_lock:
            worker = _parse_worker
            if worker is None or worker[0] != pid:
                executor, thread_id = _start_parse_worker()
                worker = _parse_worker = (pid, executor, thread_id)
    return worker[1]


def _start_parse_worker() -> tuple[ThreadPoolExecutor | None, int]:
    try:
        previous = threading.stack_size(_PARSE_STACK_BYTES)
    except (ValueError, RuntimeError):
        return None, 0
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="aak-parse")
    try:
        thread_id = executor.submit(threading.get_ident).result()  # start the thread now, with the large stack
    except RuntimeError:  # "can't start new thread"
        executor.shutdown(wait=False, cancel_futures=True)
        return None, 0
    finally:
        threading.stack_size(previous)
    return executor, thread_id


def _on_large_stack() -> bool:
    """True on the worker thread itself, where a parse or a walk runs in place:
    handed to the worker, it would wait behind the task that handed it over."""
    worker = _parse_worker
    return worker is not None and worker[0] == os.getpid() and worker[2] == threading.get_ident()


def _ast_parse(source: str | bytes, filename: str) -> ast.Module:
    if not _PARSE_ON_WORKER or _on_large_stack():
        return _parse_quietly(source, filename)
    worker = _large_stack_worker()
    if worker is None:
        return _parse_quietly(source, filename)
    return worker.submit(_parse_quietly, source, filename).result()


def parse_python(source: str | bytes, path: Path | str | None) -> ast.Module:
    """`ast.parse(source)`, refusing a source the interpreter cannot parse safely.

    CPython's parser raises RecursionError on deep nesting (`"--a" * 12000` on
    3.11 and later) and MemoryError on a long run of unary operators (`"+" *
    36000` on 3.10 and later). Before 3.11 it can segfault instead, so a
    source whose `python_nesting_bound` passes `_PY_MAX_NESTING` is refused
    before it is parsed, and the parse runs where it cannot take the process
    down (see `_ast_parse`). The parse is given a filename no file has
    (`_PARSE_FILENAME`), never `path`. The refusal is recorded against `path`
    and raised as `RefusedSource`, a SyntaxError. A caller without the path
    passes None and contains the overflow, which then propagates, with
    `refusing_overflow` where it has the path.
    """
    if _SCREEN_SOURCES:
        text = source if isinstance(source, str) else source.decode("utf-8", errors="replace")
        bound = python_nesting_bound(text)
        if bound > _PY_MAX_NESTING:
            version = f"{sys.version_info[0]}.{sys.version_info[1]}"
            reason = (
                f"Python source nests deeper than Python {version}'s parser handles safely "
                f"(a bound of {bound:,} levels, over its {_PY_MAX_NESTING:,})"
            )
            if path is None:
                raise _TooDeepToParse(reason)
            refuse(path, reason)
            raise RefusedSource(reason)
    try:
        return _ast_parse(source, _PARSE_FILENAME)
    except _OVERFLOW as exc:
        if path is None:
            raise
        reason = f"Python source nested too deep to parse ({type(exc).__name__})"
        refuse(path, reason)
        raise RefusedSource(reason) from None


# ---- Walking a parsed tree ----------------------------------------------------
#
# A recursive walk takes a Python frame or more for each level of the tree it
# walks, an `ast.NodeVisitor` two (`visit` and `generic_visit`) and
# `ast.unparse` three, and the interpreter stops at 1,000 frames, which real code
# reaches. sympy's generated table of Galois resolvents (sympy/polys/
# numberfields/resolvent_lookup.py) holds a 562-term polynomial whose tree is 569
# levels deep: five scanners that walk every Python file could not walk it, nine
# once a header opened their gates, and DeepSeek's walker, which had no
# containment, took its scanner down. Of 100,303 real files (eight interpreters'
# standard libraries and the 2,000 packages installed beside them) it is the
# deepest: the next has 230 levels, and the 99.9th percentile 30.

#: The recursion limit a walk of a parsed tree runs under (see `walk_tree`): about
#: 3,300 levels of `ast.unparse`, the walk with the most frames a level.
WALK_RECURSION_LIMIT = 10_000
_WALK_ON_WORKER = sys.version_info < (3, 11)
_headroom_lock = threading.Lock()
# The walks in progress, by the thread that runs them.
_headroom_walks: dict[int, int] = {}
_headroom_restore = 0


@contextmanager
def _recursion_headroom() -> Iterator[None]:
    """The recursion limit at `WALK_RECURSION_LIMIT` for the block, or at the
    limit already set where that is higher. Walks in progress at once share one
    raise, and the limit goes back to what it was when the first began once the
    last ends, so one finishing never lowers it under another."""
    global _headroom_restore
    me = threading.get_ident()
    with _headroom_lock:
        if not _headroom_walks:
            _headroom_restore = sys.getrecursionlimit()
            sys.setrecursionlimit(max(_headroom_restore, WALK_RECURSION_LIMIT))
        _headroom_walks[me] = _headroom_walks.get(me, 0) + 1
    try:
        yield
    finally:
        with _headroom_lock:
            if _headroom_walks[me] == 1:
                del _headroom_walks[me]
            else:
                _headroom_walks[me] -= 1
            if not _headroom_walks:
                sys.setrecursionlimit(_headroom_restore)


def _headroom_after_fork() -> None:
    """A forked child runs only the thread that forked. A walk another thread
    had in progress never ends there, so the raised limit would stay for good,
    and a lock it held at the fork is never released, so the child's first
    walk would wait on it for ever. The child takes a fresh lock and keeps only
    its own thread's walks, putting the limit back if none is left.

    A child forked from inside a walk keeps that walk and its limit. Before
    3.11 a walk runs on the parse worker, so such a child is a copy of the
    worker thread: the walk's caller is not in it, and the walk never returns
    there. Fork outside a walk to go on with the caller's work.
    """
    global _headroom_lock, _headroom_walks
    _headroom_lock = threading.Lock()
    me = threading.get_ident()
    mine = _headroom_walks.get(me, 0)
    if _headroom_walks and not mine:
        sys.setrecursionlimit(_headroom_restore)
    _headroom_walks = {me: mine} if mine else {}


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_headroom_after_fork)


def _walk_with_headroom(
    context: Context, walk: Callable[..., _T], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> _T:
    with _recursion_headroom():
        return context.run(walk, *args, **kwargs)


def walk_tree(walk: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
    """`walk(*args, **kwargs)`, a recursive walk of a parsed tree, with room to recurse.

    For an `ast.NodeVisitor`'s `visit`, `ast.unparse` (see `unparse`) or a
    scanner's own helper that follows an expression down: anything whose
    recursion grows with the depth of the tree. The walk runs with the
    recursion limit raised to `WALK_RECURSION_LIMIT` and put back afterwards.
    From 3.11 a call from Python to Python takes no C stack, so the walk runs
    where it is called. Before 3.11 every call does, and 10,000 frames can
    overflow a thread's stack before the limit stops them, so the walk runs on
    the worker that parses (`_ast_parse`), with 256 MB of stack, in a copy of
    the caller's context, so that a refusal made inside it reaches the caller's
    `collecting_refusals`. Whatever the walk raises, it raises in the caller. A
    tree deeper than even the raised limit allows raises RecursionError, which
    the caller contains with `refusing_overflow`, and that file alone is
    refused.

    The limit is the interpreter's, not the thread's. While a walk runs, every
    other thread of the process may recurse as deep, so code recursing on
    another thread at that moment can overflow its thread's stack where the
    default limit would have stopped it: any recursion before 3.11, and from
    3.11 a recursion through C (a recursive `__repr__`, or a parse: 3.11 lets
    `ast.parse` build a tree three times as deep as the limit). `aak scan`
    runs its scanners one at a time on one thread, so nothing else runs during
    a walk; a host that scans, or recurses, on other threads at the same time
    shares the raised limit while a walk is in progress. For the same reason a
    walk does not parse.

    A walk lets RecursionError out, to the caller's `refusing_overflow`, rather
    than catching it and going on to the next node: after a RecursionError,
    3.9.6 aborts the process (exit 134, "Cannot recover from stack overflow")
    if the thread recurses more than 50 frames past the limit before its depth
    falls back under it, whatever the code catches. 3.9.25 and later do not.
    """
    if not _WALK_ON_WORKER or _on_large_stack():
        with _recursion_headroom():
            return walk(*args, **kwargs)
    worker = _large_stack_worker()
    if worker is None:  # no stack to raise the limit on; the default limit stops the walk
        return walk(*args, **kwargs)
    return worker.submit(_walk_with_headroom, copy_context(), walk, args, kwargs).result()


def unparse(node: ast.AST) -> str:
    """`ast.unparse(node)`, run as a walk (see `walk_tree`), or "" where the
    unparser cannot rebuild the node.

    The scanners that unparsed an expression either let RecursionError take the
    whole scanner down, or caught every exception and read the expression as
    empty, without a word. A tree too deep even for the raised limit now raises
    RecursionError, for the caller's `refusing_overflow`. Any other error is
    the unparser's own, and reads as "", as it did.

    Before 3.11 a walk is handed to the worker and waited on, which cost more
    than unparsing the small expressions scanners mostly ask about, once for
    every callee they judged. So outside a walk the unparse is tried first
    where it is called, under the default limit, and only an expression too
    deep for that is handed over. The RecursionError of that try is caught
    back at the caller's depth, so the retry, on another thread, starts clean
    (see `walk_tree` on what 3.9.6 does otherwise). On 3.9.6 that holds only
    for a caller shallower than about 950 frames, 50 under the default limit:
    caught deeper, the error leaves the thread's overflow state set, and the
    process aborts if the caller then recurses 50 frames more. The scanners
    call it from a few dozen frames down.
    """
    if _WALK_ON_WORKER and not _on_large_stack():
        try:
            return _unparse_or_empty(node)
        except RecursionError:
            pass
    return walk_tree(_unparse_or_empty, node)


def _unparse_or_empty(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except _OVERFLOW:
        raise
    except Exception:
        return ""


# Where `chain_ends` keeps a node's answer, on the node itself, so that it lives
# and dies with the tree.
_CHAIN_ENDS = "_aak_chain_ends"


def chain_ends(node: ast.AST) -> tuple[int, str, str]:
    """The dotted name an attribute chain spells, read through calls, as (how
    many parts, the first, the last): `a.b().c` and `a.b.c()` give (3, "a",
    "c"). A chain that does not start at a name has its attributes alone
    (`x[0].a` gives (1, "a", "a")), and anything else gives (0, "", "").

    These are the parts of the name the `_attr_chain` helpers of
    mcp_stdio_params and mcp_marketplace_fetch build, and all their checks of a
    callee need: its last part, its first, and the whole name only when it has
    two parts or one. Building it for every call read each nested chain to the
    bottom from each of its calls, the square of its depth, which a walk with
    `walk_tree`'s room now reaches: 3,000 levels took 0.5 to 1 s a chain.
    Each attribute and call keeps its answer as an attribute of its own, so a
    node is read once, however many calls above it ask.
    """
    path: list[ast.AST] = []
    cur = node
    while True:
        known: tuple[int, str, str] | None = getattr(cur, _CHAIN_ENDS, None)
        if known is not None:
            ends = known
            break
        if isinstance(cur, ast.Attribute):
            path.append(cur)
            cur = cur.value
        elif isinstance(cur, ast.Call):
            path.append(cur)
            cur = cur.func
        else:
            ends = (1, cur.id, cur.id) if isinstance(cur, ast.Name) else (0, "", "")
            break
    for step in reversed(path):
        if isinstance(step, ast.Attribute):
            count, first, _ = ends
            ends = (count + 1, first, step.attr) if count else (1, step.attr, step.attr)
        setattr(step, _CHAIN_ENDS, ends)
    return ends


def chain_is(node: ast.AST, names: AbstractSet[str]) -> bool:
    """`_attr_chain(node) in names`, for names of at most two parts, without
    building the name (see `chain_ends`)."""
    count, first, last = chain_ends(node)
    if count == 1:
        return first in names
    return count == 2 and f"{first}.{last}" in names


# How many dot-separated parts one TOML key may have. tomllib builds a dotted
# key a tuple concatenation at a time, so its cost grows with the square of the
# parts: 20,000 parts (129 KB) took 3.6 s on 3.12, and the 2 MB a manifest may
# be would hold a key that takes hours. Real keys have a handful
# (`[tool.hatch.build.targets.wheel.force-include]` has six).
_TOML_MAX_KEY_PARTS = 64
# A character that cannot continue a dotted key: anything but a bare-key
# character, a blank, or (for the parsers that take TOML 1.1) a non-ASCII one.
# The quotes, `#` and `.` that need handling of their own are in it too.
_TOML_KEY_STOP_RE = re.compile("[^A-Za-z0-9_\\- \\t\u0080-\U0010ffff]")
_TOML_BASIC_END_RE = re.compile(r'[\\"\n]')
_TOML_ML_BASIC_END_RE = re.compile(r'\\|"""')


def _toml_string_end(text: str, at: int) -> tuple[int, bool]:
    """Index past the string opened at `at`, and whether it spans lines (so it
    cannot be a key part). An unterminated string runs to the end of the text."""
    quote = text[at]
    if text.startswith(quote * 3, at):
        if quote == "'":
            close = text.find("'''", at + 3)
        else:
            pos = at + 3
            while True:
                m = _TOML_ML_BASIC_END_RE.search(text, pos)
                if m is None or m.group() == '"""':
                    break
                pos = m.end() + 1
            close = -1 if m is None else m.start()
        if close < 0:
            return len(text), True
        end = close + 3
        while end < len(text) and text[end] == quote and end - close < 5:
            end += 1  # up to two quotes just inside the closing delimiter
        return end, True
    if quote == "'":
        close = text.find("'", at + 1)
        newline = text.find("\n", at + 1)
        if close < 0 or 0 <= newline < close:
            return (len(text) if newline < 0 else newline), False
        return close + 1, False
    pos = at + 1
    while True:
        m = _TOML_BASIC_END_RE.search(text, pos)
        if m is None:
            return len(text), False
        if m.group() == "\\":
            pos = m.end() + 1
            continue
        return (m.end() if m.group() == '"' else m.start()), False


def _toml_longest_dotted_key(text: str) -> int:
    """The most parts any dotted key in `text` has, in one linear pass.

    Outside strings and comments a dot only ever joins two key parts (a float
    or a date carries one, which never makes a long run), so the longest run of
    dots separated only by key parts and blanks is the longest key, less one.
    A single-line string is a quoted key part; a multi-line string, a comment
    and any other character end the run.
    """
    best = run = 0
    pos, n = 0, len(text)
    while pos < n:
        m = _TOML_KEY_STOP_RE.search(text, pos)
        if m is None:
            break
        at, char = m.start(), m.group()
        if char == ".":
            run += 1
            best = max(best, run)
            pos = at + 1
        elif char in "\"'":
            pos, spans_lines = _toml_string_end(text, at)
            if spans_lines:
                run = 0
        elif char == "#":
            newline = text.find("\n", at)
            pos, run = (n if newline < 0 else newline), 0
        else:
            pos, run = at + 1, 0
    return best + 1


def loads_toml(text: str, path: Path | str | None) -> dict[str, Any]:
    """`tomllib.loads(text)`, refusing a text the parser cannot take.

    Deeply nested inline tables and arrays take the parser past the recursion
    limit, and a key of more than `_TOML_MAX_KEY_PARTS` dotted parts costs it
    time that grows with the square of the parts, so either is refused. The
    refusal is recorded against `path` and raised as `RefusedTOML`, a
    `TOMLDecodeError`. Without a path the RecursionError propagates (see
    `refuse`), and the key screen still refuses.
    """
    if _toml_longest_dotted_key(text) > _TOML_MAX_KEY_PARTS:
        reason = f"TOML key of more than {_TOML_MAX_KEY_PARTS} dotted parts"
        refuse(path, reason)
        raise RefusedTOML(reason, text, 0)
    try:
        return tomllib.loads(text)
    except _OVERFLOW as exc:
        if path is None:
            raise
        reason = f"TOML nested too deep for Python's parser ({type(exc).__name__})"
        refuse(path, reason)
        raise RefusedTOML(reason, text, 0) from None
    except tomllib.TOMLDecodeError:
        raise
    except ValueError as exc:
        # tomllib converts an integer with `int()` and lets its ValueError out
        # unwrapped, so one past Python's digit limit (see `_INT_MAX_STR_DIGITS`)
        # was no TOMLDecodeError, and a reader catching only that lost the
        # scanner. The value cannot be read, so the file is refused.
        reason = f"TOML value Python cannot convert ({type(exc).__name__})"
        refuse(path, reason)
        raise RefusedTOML(reason, text, 0) from None


# How deep block indentation, and separately flow collections (`[`, `{`), may
# nest in a YAML file. The deepest of 3,272 real files measured on 2026-10-17
# nests 37 block levels (cert-manager's Issuer CRD) and 5 flow levels: 1,523
# from MCP repositories, and compose files, Kubernetes manifests and CRDs
# (cert-manager, argo-cd, Gateway API, Crossplane and AWS controller CRDs), Helm
# values, CloudFormation templates, workflows and OpenAPI specs from 50 other
# projects. A second set, 11,640 files from 22 such projects, nests 38 block
# levels (the same CRD in Bitnami's chart) and 31 flow levels, in an Envoy
# config dump istio keeps as test data, which no scanner reads; the next
# deepest nests 15. Brackets get about twice the deepest real nesting. PyYAML's
# scanner revisits every open flow level on each token, so a flow structure
# costs more the deeper it nests, though less than its size costs: 990 KB of
# brackets in a workflow took 13.0 s to read 99 deep (the shared limit of 100
# before), and take 10.2 s 64 deep, 8.6 s 32 deep and 2.4 s 1 deep, while a
# scan of one nested past the limit ends in half a second. Its composer
# recurses about twice per level, which meets the recursion limit near 300
# levels, and the two limits together allow 164. Counting in the scanner,
# rather than in the text, keeps a `]` inside a quoted scalar from hiding a
# level.
YAML_MAX_NESTING = 100
YAML_MAX_FLOW_NESTING = 64
# How far aliases may grow a YAML stream: twice its length plus 1,000, and at
# least this many nodes. A node counts 1, a scalar 1 more per character, and a
# node an alias reaches counts again each time. Every reader of the result
# walks it with each alias expanded, and nothing else bounds that: a 6 KB
# "billion laughs" file stood for 9 ** 8 nodes and held `gha_hardening` past
# 15 s, and one level more past 300 s. No alias-free document comes near the
# bound, since each node and each scalar character takes at least a character
# of text. Compose files reuse an `x-` block in every service, so a small one
# grows most: 20 services merging 40 shared variables is 1,689 characters that
# read as 13,417 nodes. The largest real expansion measured, 67,929 nodes, and
# the largest ratio, 2.08, both sit inside the bound (getsentry/self-hosted's
# compose file, 32,323 characters read as 64,325, is the nearest to 2 x len).
_YAML_ALIAS_FLOOR = 200_000


class _NestedTooDeep(ScannerError):
    def __init__(self, reason: str, mark: Any) -> None:
        super().__init__(problem=reason, problem_mark=mark)
        self.reason = reason


class _BoundedLoader(yaml.SafeLoader):
    """`yaml.SafeLoader` that refuses nesting past `YAML_MAX_NESTING` block
    levels or `YAML_MAX_FLOW_NESTING` flow levels as it scans."""

    def fetch_flow_collection_start(self, TokenClass: type) -> None:
        if self.flow_level >= YAML_MAX_FLOW_NESTING:
            raise _NestedTooDeep(
                f"YAML [ ] or {{ }} nested deeper than {YAML_MAX_FLOW_NESTING} levels", self.get_mark()
            )
        super().fetch_flow_collection_start(TokenClass)

    def add_indent(self, column: int) -> bool:
        if self.indent < column and len(self.indents) >= YAML_MAX_NESTING:
            raise _NestedTooDeep(f"YAML nested deeper than {YAML_MAX_NESTING} levels", self.get_mark())
        return super().add_indent(column)


def _text_if_unconvertible(construct: Callable[[Any, Node], Any]) -> Callable[[Any, Node], Any]:
    """A scalar constructor that gives the scalar's own text where `construct`
    raises a conversion error, and `construct`'s value everywhere else.

    `SafeLoader` converts a plain scalar that looks like a date, an integer or
    a boolean, and one tagged as such, and its converters raise ValueError
    (`2026-13-01`, an integer past Python's digit limit, `!!int abc`), KeyError
    (`!!bool maybe`) or AttributeError (`!!timestamp x`), none of them a
    YAMLError, so a reader catching YAMLError lost the whole scanner on one
    such scalar: a release date of month 13 in a workflow took 5 scanners
    down, the always-on hook scanner among them. The text is what the file
    says, and nothing a reader compares it with can tell the difference.
    """

    def construct_or_text(loader: Any, node: Node) -> Any:
        try:
            return construct(loader, node)
        except (ValueError, KeyError, AttributeError, TypeError):
            return loader.construct_scalar(node)

    return construct_or_text


for _tag in ("int", "float", "bool", "timestamp"):
    _BoundedLoader.add_constructor(
        f"tag:yaml.org,2002:{_tag}",
        _text_if_unconvertible(yaml.SafeLoader.yaml_constructors[f"tag:yaml.org,2002:{_tag}"]),
    )


def _yaml_children(node: Node) -> list[Node]:
    if isinstance(node, SequenceNode):
        return list(node.value)
    if isinstance(node, MappingNode):
        return [part for pair in node.value for part in pair]
    return []


def yaml_expanded_size(root: Node, limit: int, cycles_ok: bool = False) -> int | None:
    """The size of `root` with every alias expanded, or None past `limit` or on
    a cycle. A node counts 1, a scalar 1 more per character, and a node an alias
    reaches counts again each time. Iterative, and each node is sized once, so
    the work is linear in the composed document whatever the aliases do. With
    `cycles_ok`, for a reader that visits each node once, an alias inside its
    own anchor counts once instead of refusing the document."""
    sizes: dict[int, int] = {}
    on_path: set[int] = set()
    stack: list[tuple[Node, bool]] = [(root, False)]
    while stack:
        node, children_sized = stack.pop()
        key = id(node)
        if children_sized:
            on_path.discard(key)
            # A child still unsized is a back edge, met only with `cycles_ok`.
            total = 1 + sum(sizes.get(id(child), 1) for child in _yaml_children(node))
            if total > limit:
                return None
            sizes[key] = total
            continue
        if key in sizes:
            continue
        if isinstance(node, ScalarNode):
            size = 1 + len(node.value)
            if size > limit:
                return None
            sizes[key] = size
            continue
        on_path.add(key)
        stack.append((node, True))
        for child in _yaml_children(node):
            if id(child) in on_path:
                if cycles_ok:
                    continue
                return None
            if id(child) not in sizes:
                stack.append((child, False))
    return sizes.get(id(root))


def _refused_yaml(path: Path | str | None, reason: str) -> RefusedYAML:
    refuse(path, reason)
    return RefusedYAML(reason)


def _yaml_overflow(path: Path | str | None, exc: BaseException) -> BaseException:
    if path is None:
        return exc
    return _refused_yaml(path, f"YAML nested too deep for the parser ({type(exc).__name__})")


def _yaml_documents(
    text: str, path: Path | str | None, single: bool, cycles_ok: bool = False
) -> Iterator[tuple[_BoundedLoader, Node]]:
    """Compose `text` document by document, sizing each against what is left of
    the stream's alias budget, and yield each with its loader."""
    budget = max(2 * len(text) + 1_000, _YAML_ALIAS_FLOOR)
    bound = budget
    loader = _BoundedLoader(text)
    try:
        while single or loader.check_node():
            # `safe_load` takes one document and raises on a second, as
            # `get_single_node` does; `safe_load_all` takes each in turn.
            node = loader.get_single_node() if single else loader.get_node()
            if node is not None:
                size = yaml_expanded_size(node, budget, cycles_ok)
                if size is None:
                    why = "" if cycles_ok else ", or one sits inside its own anchor"
                    raise _refused_yaml(path, f"YAML aliases expand past {bound:,} nodes{why}")
                budget -= size
                yield loader, node
            if single:
                return
    except _NestedTooDeep as exc:
        raise _refused_yaml(path, exc.reason) from None
    except _OVERFLOW as exc:
        raise _yaml_overflow(path, exc) from None
    finally:
        loader.dispose()


def load_yaml(text: str, path: Path | str | None, cycles_ok: bool = False) -> Any:
    """`yaml.safe_load(text)`, refusing a text that nests too deep or that
    aliases grow too large (see `YAML_MAX_NESTING`, `YAML_MAX_FLOW_NESTING`
    and `_YAML_ALIAS_FLOOR`).

    The refusal is recorded against `path` and raised as `RefusedYAML`, a
    `yaml.YAMLError`, so the reader skips the file as it skips invalid YAML
    while `run_scan` reports it. Anything `safe_load` accepts within the
    bounds comes back as `safe_load` returns it. A document that contains
    itself (`&a [*a]`) is refused unless `cycles_ok`, for a reader that visits
    each container once: every other reader would walk it forever.
    """
    for loader, node in _yaml_documents(text, path, single=True, cycles_ok=cycles_ok):
        try:
            return loader.construct_document(node)
        except _OVERFLOW as exc:
            raise _yaml_overflow(path, exc) from None
    return None


def load_yaml_all(text: str, path: Path | str | None) -> list[Any]:
    """`list(yaml.safe_load_all(text))`, bounded as `load_yaml` is, with one
    alias budget for the whole stream."""
    out: list[Any] = []
    for loader, node in _yaml_documents(text, path, single=False):
        try:
            out.append(loader.construct_document(node))
        except _OVERFLOW as exc:
            raise _yaml_overflow(path, exc) from None
    return out


def compose_yaml_all(text: str, path: Path | str | None) -> list[Node]:
    """The composed documents of `text`, as `yaml.compose_all` gives them,
    bounded as `load_yaml` is. A node an alias reaches is shared, not copied,
    so a walker of the result visits each node once (by `id`) to stay linear."""
    return [node for _loader, node in _yaml_documents(text, path, single=False, cycles_ok=True)]
