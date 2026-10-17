"""The shell splitter gives exactly what the shlex calls it replaced gave, in linear time.

`_launchers.shell_tokens` was `shlex.shlex(line, posix=True, punctuation_chars=True)`
with `whitespace_split` on and no comment characters, and `hook_injection._shell_words`
was the same lexer with a newline as punctuation, space, tab and carriage return
as whitespace, and `#` starting a comment. Both fell back to `str.split()` where
shlex raised. shlex grows a token with `+=` on an attribute, so a word of n
characters cost about n squared: one 1 MB word took 7 to 20 s to split, the CVE
pin table splits every package.json script and every MCP config argument that
holds a space, and hook_injection every hook command. Both now call
`_launchers.shell_words`, which reads the same grammar in runs.

Splitting differently would change which package a launch names or which command a
hook runs, so each old call is kept here, as it was written, as the oracle, and its
replacement must agree with it everywhere: on every string up to three characters
over an alphabet holding each character either grammar treats specially, on tens of
thousands of longer random strings, and on every command line the repo's fixtures
hold. "Agree" includes the fallback: the new splitter must give up exactly where
shlex raises. CI runs this on every Python in its matrix, so a shlex that changed
between versions would fail here.
"""

from __future__ import annotations

import itertools
import json
import random
import shlex
import time
from pathlib import Path
from typing import Callable, Iterable, Iterator, NamedTuple

import pytest
import yaml

from agent_audit_kit.scanners import hook_injection
from agent_audit_kit.scanners._helpers import loads_jsonc
from agent_audit_kit.scanners._launchers import _shell_split, _shell_syntax, shell_tokens

REPO = Path(__file__).resolve().parent.parent

# Every character either grammar treats specially, then word characters of each
# kind: ASCII, a Latin-1 letter shlex counts as a word character, a symbol it does
# not, and a vertical tab, which `str.split()` (the fallback) treats as whitespace
# and shlex does not.
_ALPHABET = (
    " ", "\t", "\n", "\r", "'", '"', "\\", ";", "&", "|", "(", ")", "<", ">",
    "#", "~", "-", ".", "/", "*", "?", "=", "@", ":", "$", "`",
    "a", "b", "Z", "1", "é", "€", "\x0b", "_",
)


def _old_shell_tokens(line: str) -> list[str] | None:
    """`_launchers.shell_tokens` before, or None where shlex raised."""
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:
        return None


def _old_hook_words(command: str) -> list[str] | None:
    """`hook_injection._shell_words` before, or None where shlex raised."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars="".join(sorted(hook_injection._PUNCTUATION)))
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:
        return None


class _Splitter(NamedTuple):
    split: Callable[[str], list[str]]  # the call site
    old: Callable[[str], list[str] | None]  # the shlex call it replaced
    punctuation: str
    whitespace: str
    commenters: str


_SPLITTERS = {
    "shell_tokens": _Splitter(shell_tokens, _old_shell_tokens, "();<>|&", " \t\r\n", ""),
    "hook commands": _Splitter(
        hook_injection._shell_words, _old_hook_words,
        "".join(sorted(hook_injection._PUNCTUATION)), " \t\r", "#",
    ),
}


def _agrees(splitter: _Splitter, line: str, expected: list[str] | None) -> bool:
    syntax = _shell_syntax(splitter.punctuation, splitter.whitespace, splitter.commenters)
    if _shell_split(line, syntax) != expected:
        return False
    return splitter.split(line) == (line.split() if expected is None else expected)


def _disagreements(splitter: _Splitter, lines: Iterable[str]) -> tuple[int, int, list[str]]:
    """(cases, fallbacks, the first few lines that disagree)."""
    cases = fallbacks = 0
    wrong: list[str] = []
    for line in lines:
        expected = splitter.old(line)
        cases += 1
        fallbacks += expected is None
        if not _agrees(splitter, line, expected) and len(wrong) < 10:
            wrong.append(line)
    return cases, fallbacks, wrong


@pytest.mark.parametrize("name", sorted(_SPLITTERS))
def test_every_short_string_splits_as_shlex_does(name: str) -> None:
    lines = ("".join(chars) for size in range(4) for chars in itertools.product(_ALPHABET, repeat=size))
    cases, fallbacks, wrong = _disagreements(_SPLITTERS[name], lines)
    assert cases == sum(len(_ALPHABET) ** size for size in range(4))
    assert fallbacks > 1_000, "the alphabet must reach both of shlex's errors"
    assert not wrong, wrong


@pytest.mark.parametrize("name", sorted(_SPLITTERS))
def test_random_strings_split_as_shlex_does(name: str) -> None:
    rng = random.Random(20261017)
    lines = ["".join(rng.choice(_ALPHABET) for _ in range(rng.randint(4, 40))) for _ in range(60_000)]
    # Strings rich in the characters that change state, and longer ones.
    heavy = ("'", '"', "\\", " ", "&", "|", ";", "#", "\n", "a", "a", "a")
    lines += ["".join(rng.choice(heavy) for _ in range(rng.randint(10, 120))) for _ in range(20_000)]
    cases, fallbacks, wrong = _disagreements(_SPLITTERS[name], lines)
    assert cases == 80_000
    assert 1_000 < fallbacks < cases - 1_000, "both outcomes must be well represented"
    assert not wrong, wrong


@pytest.mark.parametrize(("name", "line", "expected"), [
    ("shell_tokens", "npx github:org/repo#abc1234 && echo 'a b'", ["npx", "github:org/repo#abc1234", "&&", "echo", "a b"]),
    ("shell_tokens", "''&&\"\"", ["", "&&", ""]),
    ("shell_tokens", "2>&1 |& (a);b", ["2", ">&", "1", "|&", "(", "a", ");", "b"]),
    ("shell_tokens", '"a\\"b\\\\c\\d" e\\ f', ['a"b\\c\\d', "e f"]),
    ("shell_tokens", "'a\\b' \"x'y\"", ["a\\b", "x'y"]),
    # A comment runs through its newline, which is then not an operator.
    ("hook commands", "make && echo done # notify\nnext", ["make", "&&", "echo", "done", "next"]),
    ("hook commands", "a;\nb#c\n", ["a", ";\n", "b"]),
    ("hook commands", "echo 'a # b' \"#\" \\#", ["echo", "a # b", "#", "#"]),
    # shlex raises; the fallback is whitespace splitting, vertical tab included.
    ("shell_tokens", "npx 'unbalanced", ["npx", "'unbalanced"]),
    ("shell_tokens", "a\x0bb \"c", ["a", "b", '"c']),
    ("shell_tokens", "trailing\\", ["trailing\\"]),
    ("hook commands", '"inside\\', ['"inside\\']),
])
def test_known_lines(name: str, line: str, expected: list[str]) -> None:
    splitter = _SPLITTERS[name]
    assert splitter.split(line) == expected
    assert _agrees(splitter, line, splitter.old(line))


def test_overlapping_classes_are_refused() -> None:
    """shlex settles a character in two classes by the order of its checks; the
    splitter would not, so it refuses one rather than split differently."""
    with pytest.raises(ValueError):
        _shell_syntax("();<>|&\n", " \t\r\n", "")


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


@pytest.mark.parametrize("name", sorted(_SPLITTERS))
def test_every_fixture_command_line_splits_as_shlex_does(name: str) -> None:
    lines = _fixture_command_lines()
    cases, _fallbacks, wrong = _disagreements(_SPLITTERS[name], lines)
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
    "comments": lambda n: "a #c\n" * (n // 5),
    "an unclosed quote": lambda n: '"' + "a " * (n // 2),
    "words joined by no-break spaces": lambda n: "a\u00a0" * (n // 2),
}


@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize("name", sorted(_SPLITTERS))
def test_splitting_grows_linearly(name: str, shape: str) -> None:
    split, line = _SPLITTERS[name].split, _SHAPES[shape]
    small, large = line(100_000), line(1_000_000)
    t_small, t_large = _seconds(lambda: split(small)), _seconds(lambda: split(large))
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


def test_a_crafted_package_json_reads_in_linear_time(tmp_path: Path) -> None:
    """The pin table splits every script of a package.json up to its 2 MB limit."""
    from agent_audit_kit.scanners import mcp_cve_pins_2026_07

    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"x": "a" * 1_999_900}}), encoding="utf-8")
    started = time.perf_counter()
    mcp_cve_pins_2026_07.scan(tmp_path)
    assert time.perf_counter() - started < 5.0


def test_a_script_joined_by_no_break_spaces_reads_in_linear_time(tmp_path: Path) -> None:
    """sh and shlex read a no-break space as part of a word, while `str.split`
    splits at it; the 16 KiB word guard the old splitter needed split that way,
    so a script of short words joined by them passed the guard and reached
    shlex as one word. Both readers of package.json scripts are timed."""
    from agent_audit_kit.scanners import mcp_cve_pins_2026_07, supply_chain

    def scan_both(pairs: int) -> float:
        root = tmp_path / str(pairs)
        root.mkdir()
        script = "a\u00a0" * pairs
        text = json.dumps({"scripts": {"x": script}}, ensure_ascii=False)
        (root / "package.json").write_text(text, encoding="utf-8")
        return _seconds(lambda: (supply_chain.scan(root), mcp_cve_pins_2026_07.scan(root)))

    t_small, t_large = scan_both(20_000), scan_both(200_000)
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


@pytest.mark.parametrize("command", [
    "echo " + "a" * 999_600,
    'bash -c "echo ' + "a" * 999_500 + '"',  # split again at the next level
])
def test_a_crafted_hook_command_scans_in_linear_time(tmp_path: Path, command: str) -> None:
    """A settings file is read up to 1,000,000 characters, and each `sh -c` script
    in a hook is split again. The old split took 12 to 14 s, and 21 to 42 s inside
    `bash -c`."""
    hooks = {"PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": command}]}]}
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"hooks": hooks}), encoding="utf-8")
    started = time.perf_counter()
    hook_injection.scan(tmp_path)
    assert time.perf_counter() - started < 5.0
