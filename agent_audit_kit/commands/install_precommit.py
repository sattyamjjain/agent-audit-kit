"""The ``install-precommit`` command.

Moved out of ``cli.py`` (issue #701) when it learned to write only inside the
project, which took ``cli.py`` past the 1,300 lines ``tests/test_cli_scan_extraction.py``
holds it under. Its decorators and parameter are the ones it had there, and ``cli``
registers the command with ``add_command``, as it does ``scan``.

The hook's entry goes at the end of the file's ``repos`` list and nothing else in the
file changes. The command judged the file by substring: a file without ``repos:`` in
it was replaced by the entry, so a config holding only settings, or a JSON-style one
(``"repos":``), lost what it held; a config whose last key was not ``repos`` (the
``ci:`` block pre-commit.ci reads) got the entry under that key and stopped parsing;
and a comment naming agent-audit-kit read as the hook already being there. The file
is parsed now, the entry is inserted after the list's last item, and the result must
parse to the old file plus that one entry, or nothing is written.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable, Hashable
from pathlib import Path
from typing import Any, NoReturn

import click
import yaml

from agent_audit_kit import __version__
from agent_audit_kit.commands._common import EXIT_ERROR

__all__ = ["install_precommit_cmd"]

_REPO = "https://github.com/sattyamjjain/agent-audit-kit"
_HOOK_ID = "agent-audit-kit"
# Pin the release that is running this command. A literal here (it was
# v0.3.0) froze every new install on a months-old hook no matter which
# version wrote it.
_ENTRY = {"repo": _REPO, "rev": f"v{__version__}", "hooks": [{"id": _HOOK_ID}]}
# A real config is a few kilobytes. The parse is pure Python, so a crafted file is
# refused above this size rather than read for seconds.
_MAX_BYTES = 1_000_000
# Every line break YAML 1.1 reads: CR, LF, CRLF, NEL, LS and PS.
_BREAKS = "\r\n\x85\u2028\u2029"
_BREAK_RE = re.compile("\r\n|[\r\n\x85\u2028\u2029]")
_MERGE = "tag:yaml.org,2002:merge"
# libyaml composes in C and recurses without a limit: 60,000 nested `[` overflow an
# 8 MB stack and kill the process. Collections cannot nest deeper than a file has
# characters that can open one, and real configs have 17 to 329 of them.
_LIBYAML_MAX_OPENERS = 2_000


class _CannotAdd(Exception):
    """The entry cannot be added without changing the file otherwise; the message says why."""


class _MergeKey(Exception):
    """The file uses a YAML merge key (`<<`); ``line`` is the first one's, from 1."""

    def __init__(self, line: int) -> None:
        super().__init__(line)
        self.line = line


class _Loader(yaml.SafeLoader):
    """`yaml.SafeLoader` that refuses a mapping with a key written twice.

    `safe_load` keeps the last of two equal keys, so an entry added under the first
    `repos:` would sit in a list pre-commit never reads. Keys are compared as built,
    so `1` and `"1"`, an int and a string, are two keys.
    """

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        seen: set[Hashable] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                twice = key in seen
            except TypeError:
                continue  # an unhashable key, which the base class refuses with its own error
            if twice:
                raise yaml.constructor.ConstructorError(
                    None, None, f"found the key {key!r} twice", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _entry(indent: str, newline: str) -> str:
    """The hook's `repos` entry, its dash at ``indent``, each line ended by ``newline``."""
    lines = [f"- repo: {_REPO}", f"  rev: v{__version__}", "  hooks:", f"    - id: {_HOOK_ID}"]
    return "".join(f"{indent}{line}{newline}" for line in lines)


def _read_config(path: Path) -> bytes:
    """Up to one byte past the size cap of ``path``, read as `fix._read_bytes` reads:
    only a regular file, opened without following a link or waiting on a FIFO."""
    from agent_audit_kit.fix import _open_regular

    with open(_open_regular(path), "rb") as handle:
        return handle.read(_MAX_BYTES + 1)


def _merge_line(node: yaml.Node) -> int | None:
    """The line, from 1, of the first YAML merge key (`<<`) under ``node``, or None.

    PyYAML copies a merged mapping's keys into every mapping that merges it while it
    builds the data, so a chain of merges costs the square of its length and a large
    mapping merged many times its size times theirs: a 394 KB chain took 48 s and
    1.6 GB to build, twice over with the check of the result. The tree is walked once,
    each node of it once, before anything is built.
    """
    first, stack, seen = None, [node], set()
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, yaml.MappingNode):
            for key, value in current.value:
                if key.tag == _MERGE and (first is None or key.start_mark.index < first.index):
                    first = key.start_mark
                stack.extend((key, value))
        elif isinstance(current, yaml.SequenceNode):
            stack.extend(current.value)
    return None if first is None else first.line + 1


def _parse(text: str, loader_class: Callable[[str], Any] = _Loader) -> tuple[yaml.Node | None, object]:
    """``text``'s node tree, which says where each value is written, and its data.
    Raises `_MergeKey` for a file that uses a merge key, before building anything."""
    loader = loader_class(text)
    try:
        node = loader.get_single_node()
        if node is None:
            return None, None
        line = _merge_line(node)
        if line is not None:
            raise _MergeKey(line)
        return node, loader.construct_document(node)
    finally:
        loader.dispose()


def _configured_for_libyaml(text: str) -> bool:
    """Whether libyaml, which pre-commit reads its config with where PyYAML has it,
    reads ``text`` as already running the hook. libyaml takes some files PyYAML's own
    parser refuses, such as a tab after a value; the hook is there for pre-commit, so
    the command says so, as it did before it parsed the file. A merge key is refused
    before anything is built, as for PyYAML's parser.

    PyYAML's parser may have stopped long before the end of the file, so libyaml
    would meet whatever follows, and its composer recurses in C without a limit.
    It is asked only about a file with at most `_LIBYAML_MAX_OPENERS` characters
    that can open a collection (`[`, `{`, `:`, `?`, `-`), which bounds how deep
    anything in it can nest, whatever is quoted.
    """
    loader_class = getattr(yaml, "CSafeLoader", None)
    if loader_class is None or sum(text.count(c) for c in "[{:?-") > _LIBYAML_MAX_OPENERS:
        return False
    try:
        return _configured(_parse(text, loader_class)[1])
    except (yaml.YAMLError, RecursionError, _MergeKey):
        return False


def _problem(exc: BaseException) -> str:
    if isinstance(exc, RecursionError):
        return "nested too deeply to read"
    if isinstance(exc, yaml.MarkedYAMLError) and exc.problem:
        mark = exc.problem_mark
        return f"{exc.problem} on line {mark.line + 1}" if mark is not None else exc.problem
    return (str(exc).splitlines() or [type(exc).__name__])[0]


def _normalised(url: str) -> str:
    url = url.strip().rstrip("/")
    return (url[:-4] if url.endswith(".git") else url).rstrip("/").lower()


def _configured(data: object) -> bool:
    """Whether the parsed config already runs the hook: a repo whose URL is this
    project's, a trailing `.git` or `/` aside, or any hook whose id is the hook's."""
    repos = data.get("repos") if isinstance(data, dict) else None
    for repo in repos if isinstance(repos, list) else []:
        if not isinstance(repo, dict):
            continue
        if isinstance(repo.get("repo"), str) and _normalised(repo["repo"]) == _normalised(_REPO):
            return True
        hooks = repo.get("hooks")
        if isinstance(hooks, list) and any(isinstance(h, dict) and h.get("id") == _HOOK_ID for h in hooks):
            return True
    return False


def _content_end(node: yaml.Node) -> int:
    """Where ``node``'s last written character ends: its last scalar, or a flow
    collection's closing bracket. A block collection's own end mark lies past the
    comments and blank lines after it, at the next key, so it is not used. Walked
    once per node, since aliases make the tree a graph."""
    end, stack, seen = 0, [node], set()
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, yaml.ScalarNode) or getattr(current, "flow_style", False):
            end = max(end, current.end_mark.index)
        elif isinstance(current, yaml.SequenceNode):
            stack.extend(current.value)
        elif isinstance(current, yaml.MappingNode):
            stack.extend(part for pair in current.value for part in pair)
    return end


def _next_line(text: str, index: int) -> int:
    match = _BREAK_RE.search(text, index)
    return match.end() if match else len(text)


def _insert_at(text: str, end: int, column: int) -> int:
    """The start of the line after the content ending at ``end``, past comment lines
    indented deeper than ``column`` (a hook commented out under the last item), and
    before the blank lines and comments that belong to the next key."""
    at = end if end == 0 or text[end - 1] in _BREAKS else _next_line(text, end)
    while at < len(text):
        line = text[at:_next_line(text, at)]
        body = line.lstrip(" ")
        if not body.startswith("#") or len(line) - len(body) <= column:
            break
        at += len(line)
    return at


def _same(a: object, b: object, seen: set[tuple[int, int]]) -> bool:
    """Equality that compares each pair of collections once, so nested aliases
    (`b: &b [*a, *a]` over `a: &a [x, x]`, and so on) cost the file's size rather than
    the 2**depth paths through them, and a recursive alias ends. Iterative, so no
    depth of nesting the parser accepts can exhaust the recursion limit here."""
    stack = [(a, b)]
    while stack:
        x, y = stack.pop()
        if type(x) is not type(y):
            return False
        if not isinstance(x, (dict, list)):
            if x != y and not (x != x and y != y):  # `.nan` never equals itself
                return False
            continue
        if (id(x), id(y)) in seen:
            continue
        seen.add((id(x), id(y)))
        if isinstance(x, dict) and isinstance(y, dict):
            if x.keys() != y.keys():
                return False
            stack.extend((x[key], y[key]) for key in x)
        elif isinstance(x, list) and isinstance(y, list):
            if len(x) != len(y):
                return False
            stack.extend(zip(x, y))
    return True


def _adds_only_the_entry(old: object, new_text: str) -> bool:
    """Whether ``new_text`` parses to ``old`` plus the entry at the end of its repos
    list, every other key as it was."""
    try:
        _, new = _parse(new_text)
    except (yaml.YAMLError, RecursionError, _MergeKey):
        return False
    old = {} if old is None else old
    repos = old.get("repos") if isinstance(old, dict) else None
    seen: set[tuple[int, int]] = set()
    return (
        isinstance(old, dict)
        and isinstance(new, dict)
        and isinstance(repos, (list, type(None)))
        and set(new) == set(old) | {"repos"}
        and _same(new["repos"], [*(repos or []), _ENTRY], seen)
        and all(_same(new[key], old[key], seen) for key in old if key != "repos")
    )


def _with_hook(text: str, name: str) -> str | None:
    """``text`` with the hook's entry at the end of its repos list, or None when it
    already runs the hook. Raises `_CannotAdd` for a file it cannot add to without
    changing anything else: one that does not parse or is not a block mapping, a
    `repos` that is not a block list, or a result that reads as more than the entry."""
    try:
        root, data = _parse(text)
    except _MergeKey as exc:
        raise _CannotAdd(
            f"{name} uses a YAML merge key (<<) on line {exc.line}, which AAK does not edit"
        ) from exc
    except (yaml.YAMLError, RecursionError) as exc:
        if _configured_for_libyaml(text):
            return None
        raise _CannotAdd(f"{name} does not parse as YAML ({_problem(exc)})") from exc
    if _configured(data):
        return None
    if root is not None and not isinstance(root, yaml.MappingNode):
        raise _CannotAdd(f"{name} is not a YAML mapping")
    if root is not None and root.flow_style:
        raise _CannotAdd(f"{name} is written in flow style, like JSON")
    found = _BREAK_RE.search(text)
    newline = found.group() if found else os.linesep
    pairs = root.value if root is not None else []
    repos = next(((k, v) for k, v in pairs if isinstance(k, yaml.ScalarNode) and k.value == "repos"), None)
    if repos is None:
        column = pairs[0][0].start_mark.column if pairs else 0
        head = text if not text or text[-1] in _BREAKS else text + newline
        new = f"{head}{' ' * column}repos:{newline}{_entry(' ' * (column + 2), newline)}"
    else:
        key, value = repos
        if isinstance(value, yaml.SequenceNode) and not value.flow_style:
            at, indent = _insert_at(text, _content_end(value), value.start_mark.column), value.start_mark.column
        elif isinstance(value, yaml.ScalarNode) and value.tag == "tag:yaml.org,2002:null":
            at, indent = _insert_at(text, key.end_mark.index, key.start_mark.column), key.start_mark.column + 2
        else:
            raise _CannotAdd(f"{name} does not write repos as a block list")
        lead = "" if at == 0 or text[at - 1] in _BREAKS else newline
        new = text[:at] + lead + _entry(" " * indent, newline) + text[at:]
    if not _adds_only_the_entry(data, new):
        raise _CannotAdd(f"{name} would change beyond its repos list")
    return new


def _refuse(reason: str, by_hand: bool = False) -> NoReturn:
    click.echo(f"Cannot add the hook: {reason}. .pre-commit-config.yaml was not changed.", err=True)
    if by_hand:
        click.echo("Add this entry under repos: by hand:", err=True)
        click.echo(_entry("  ", "\n"), err=True, nl=False)
    sys.exit(EXIT_ERROR)


@click.command("install-precommit")
@click.version_option(version=__version__)
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
def install_precommit_cmd(path: str) -> None:
    """Add an agent-audit-kit entry to the project's .pre-commit-config.yaml.

    The entry goes at the end of the repos list, and nothing else in the file
    changes. Exits 2, leaving the file as it was, when it cannot be written inside
    the project, for instance because it is a link that leads out of it, or when the
    entry cannot be added without changing the file otherwise, as with a flow-style
    or unparseable file; the entry to add by hand is printed then.
    """
    from agent_audit_kit.fix import _replace_inside_project, _write_refusal

    project = Path(path)
    cfg_path = project / ".pre-commit-config.yaml"
    # The repository decides what sits at this path, and `is_file()`, `read_text`
    # and `write_text` followed a link: a config linked to a file outside the
    # project had the hook written into that file, a dangling link had the file it
    # named created, and a FIFO blocked the command forever. The path is looked at
    # before it is read, read only as a regular file and written through
    # `_write_inside_project`, as every `aak fix` recipe does. A missing file reads
    # as empty.
    raw = b""
    refused = _write_refusal(cfg_path, project)
    if refused is None:
        try:
            raw = _read_config(cfg_path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            refused = f"{cfg_path.name} could not be read ({exc.strerror})" if exc.strerror else str(exc)
    if refused is not None:
        _refuse(refused)
    try:
        if len(raw) > _MAX_BYTES:
            raise _CannotAdd(f"{cfg_path.name} is over 1 MB, which AAK does not edit")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _CannotAdd(f"{cfg_path.name} is not UTF-8") from exc
        new = _with_hook(text, cfg_path.name)
    except _CannotAdd as exc:
        _refuse(str(exc), by_hand=True)
    if new is None:
        click.echo("agent-audit-kit hook already configured in .pre-commit-config.yaml")
        return
    # Moved into place whole, so a write that fails part way leaves the config as it was.
    refused = _replace_inside_project(cfg_path, new.encode("utf-8"), project)
    if refused is not None:
        _refuse(refused)
    click.echo(f"added agent-audit-kit pre-commit hook to {cfg_path.relative_to(project)}")
    click.echo("next: run `pre-commit install`")
