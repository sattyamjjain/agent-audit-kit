"""`_launchers.shell_tokens` splits exactly as the shlex call it replaced, in linear time.

The function was `shlex.shlex(line, posix=True, punctuation_chars=True)` with
`whitespace_split` on and no comment characters, falling back to `str.split()`
when shlex raised. shlex grows a token with `+=` on an attribute, so a word of n
characters cost about n squared: one 1 MB word took 7 to 20 s to split, and the CVE pin table
splits every package.json script and every MCP config argument that holds a
space. The replacement reads the same grammar in runs.

Splitting differently would change which package a launch names, so the old call
is kept here as the oracle and the new one must agree with it everywhere: on every
string up to three characters over an alphabet holding each character the grammar
treats specially, on tens of thousands of longer random strings, and on every
command line the repo's fixtures hold. "Agree" includes the fallback: the new
splitter must give up exactly where shlex raises. CI runs this on every Python in
its matrix, so a shlex that changed between versions would fail here.
"""

from __future__ import annotations

import itertools
import json
import random
import shlex
import time
from pathlib import Path
from typing import Callable, Iterable, Iterator

import pytest
import yaml

from agent_audit_kit.scanners._helpers import loads_jsonc
from agent_audit_kit.scanners._launchers import _shell_split, shell_tokens

REPO = Path(__file__).resolve().parent.parent

# Every character the grammar treats specially, then word characters of each kind:
# ASCII, a Latin-1 letter shlex counts as a word character, a symbol it does not,
# and a vertical tab, which `str.split()` (the fallback) treats as whitespace and
# shlex does not.
_ALPHABET = (
    " ", "\t", "\n", "\r", "'", '"', "\\", ";", "&", "|", "(", ")", "<", ">",
    "#", "~", "-", ".", "/", "*", "?", "=", "@", ":", "$", "`",
    "a", "b", "Z", "1", "é", "€", "\x0b", "_",
)


def _shlex_split(line: str) -> list[str] | None:
    """The old implementation's split, or None where shlex raised."""
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:
        return None


def _agrees(line: str, expected: list[str] | None) -> bool:
    if _shell_split(line) != expected:
        return False
    return shell_tokens(line) == (line.split() if expected is None else expected)


def _disagreements(lines: Iterable[str]) -> tuple[int, int, list[str]]:
    """(cases, fallbacks, the first few lines that disagree)."""
    cases = fallbacks = 0
    wrong: list[str] = []
    for line in lines:
        expected = _shlex_split(line)
        cases += 1
        fallbacks += expected is None
        if not _agrees(line, expected) and len(wrong) < 10:
            wrong.append(line)
    return cases, fallbacks, wrong


def test_every_short_string_splits_as_shlex_does() -> None:
    lines = ("".join(chars) for size in range(4) for chars in itertools.product(_ALPHABET, repeat=size))
    cases, fallbacks, wrong = _disagreements(lines)
    assert cases == sum(len(_ALPHABET) ** size for size in range(4))
    assert fallbacks > 1_000, "the alphabet must reach both of shlex's errors"
    assert not wrong, wrong


def test_random_strings_split_as_shlex_does() -> None:
    rng = random.Random(20261017)
    lines = ["".join(rng.choice(_ALPHABET) for _ in range(rng.randint(4, 40))) for _ in range(60_000)]
    # Strings rich in the characters that change state, and longer ones.
    heavy = ("'", '"', "\\", " ", "&", "|", ";", "a", "a", "a")
    lines += ["".join(rng.choice(heavy) for _ in range(rng.randint(10, 120))) for _ in range(20_000)]
    cases, fallbacks, wrong = _disagreements(lines)
    assert cases == 80_000
    assert 1_000 < fallbacks < cases - 1_000, "both outcomes must be well represented"
    assert not wrong, wrong


@pytest.mark.parametrize(("line", "expected"), [
    ("npx github:org/repo#abc1234 && echo 'a b'", ["npx", "github:org/repo#abc1234", "&&", "echo", "a b"]),
    ("''&&\"\"", ["", "&&", ""]),
    ("2>&1 |& (a);b", ["2", ">&", "1", "|&", "(", "a", ");", "b"]),
    ('"a\\"b\\\\c\\d" e\\ f', ['a"b\\c\\d', "e f"]),
    ("'a\\b' \"x'y\"", ["a\\b", "x'y"]),
    # shlex raises; the fallback is whitespace splitting, vertical tab included.
    ("npx 'unbalanced", ["npx", "'unbalanced"]),
    ("a\x0bb \"c", ["a", "b", '"c']),
    ("trailing\\", ["trailing\\"]),
    ('"inside\\', ['"inside\\']),
])
def test_known_lines(line: str, expected: list[str]) -> None:
    assert shell_tokens(line) == expected
    assert _agrees(line, _shlex_split(line))


# --- Every command line the repo's fixtures hold --------------------------------

_TREES = ("tests/fixtures", "examples", "benchmarks/sample_configs")


def _command_lines(node: object) -> Iterator[str]:
    """A config's `command`s, each argument, the whole command line, and scripts."""
    if isinstance(node, dict):
        command, args = node.get("command"), node.get("args")
        if isinstance(command, str):
            yield command
            if isinstance(args, list):
                words = [a for a in args if isinstance(a, str)]
                yield from words
                yield " ".join([command, *words])
        scripts = node.get("scripts")
        if isinstance(scripts, dict):
            yield from (line for line in scripts.values() if isinstance(line, str))
        for value in node.values():
            yield from _command_lines(value)
    elif isinstance(node, list):
        for item in node:
            yield from _command_lines(item)


def _fixture_command_lines() -> list[str]:
    found: set[str] = set()
    for tree in _TREES:
        for path in sorted((REPO / tree).rglob("*")):
            if path.suffix not in (".json", ".yaml", ".yml") or not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
                data = loads_jsonc(text) if path.suffix == ".json" else yaml.safe_load(text)
            except (ValueError, yaml.YAMLError, UnicodeDecodeError, RecursionError):
                continue
            found.update(_command_lines(data))
    return sorted(found)


def test_every_fixture_command_line_splits_as_shlex_does() -> None:
    lines = _fixture_command_lines()
    cases, _fallbacks, wrong = _disagreements(lines)
    assert cases > 500, f"only {cases} command lines found; the fixture walk is broken"
    assert not wrong, wrong


# --- Linear time ------------------------------------------------------------------
#
# Each shape is timed at two sizes ten times apart. Linear work takes about ten
# times as long; the bound allows forty, plus a fixed slack, under an absolute bound
# that is loose for slow CI runners. shlex took 0.12 s for one 100 KB word and 7 to
# 20 s for one 1 MB word.


def _seconds(run: Callable[[], object]) -> float:
    """Best of three, so one descheduled run cannot fail a timing test."""
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        run()
        best = min(best, time.perf_counter() - started)
    return best


_SHAPES: dict[str, Callable[[int], str]] = {
    "one word": lambda n: "a" * n,
    "many words": lambda n: "ab " * (n // 3),
    "one double-quoted word": lambda n: '"' + "a" * n + '"',
    "one single-quoted word": lambda n: "'" + "a" * n + "'",
    "escapes": lambda n: "\\a" * (n // 2),
    "quotes glued into one word": lambda n: "'a'\"b\"" * (n // 6),
    "operators": lambda n: "a&&" * (n // 3),
    "an unclosed quote": lambda n: '"' + "a " * (n // 2),
}


@pytest.mark.parametrize("shape", sorted(_SHAPES))
def test_splitting_grows_linearly(shape: str) -> None:
    line = _SHAPES[shape]
    small, large = line(100_000), line(1_000_000)
    t_small, t_large = _seconds(lambda: shell_tokens(small)), _seconds(lambda: shell_tokens(large))
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


def test_a_crafted_package_json_reads_in_linear_time(tmp_path: Path) -> None:
    """The pin table splits every script of a package.json up to its 2 MB limit."""
    from agent_audit_kit.scanners import mcp_cve_pins_2026_07

    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"x": "a" * 1_999_900}}), encoding="utf-8")
    started = time.perf_counter()
    mcp_cve_pins_2026_07.scan(tmp_path)
    assert time.perf_counter() - started < 5.0
