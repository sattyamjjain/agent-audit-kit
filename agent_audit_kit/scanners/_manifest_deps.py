"""The dependency declarations a manifest or an MCP config actually makes.

The CVE pin table used to search a manifest's text for each package name and
judge the first match. Three failure modes came of it, all found while proving
the table's limitations:

- The first match won, and a match was anything. A comment or a description
  that named the package with a number (`# gateway needs litellm 1.90 or
  newer`, a pyproject `description`) was read as the declaration and hid the
  real `litellm==1.0.0` below it. An MCP server *named* `n8n` read as the `n8n`
  package, and a path or an image name read as a version.
- A name was matched without a left boundary, so `repomix-plugin-extras`,
  `ruflo-extras` and `litellm-proxy-extras==0.4.3` read as `repomix`, `ruflo`
  and `litellm`, and `@agenticmail/openclaw` as `openclaw`.
- A version was the first number after the name. Extras (`litellm[proxy]==1.90.0`),
  a Poetry caret (`litellm = "^1.90.0"`) and a Pipfile string (`"==1.90.0"`) put
  something else there, so a patched pin read as unpinned and upgrading could
  not clear the finding.

This module parses each file in its own format and returns its declarations:
the package as the registry knows it, the version text as written, and how to
read that text. Comments, descriptions, keys, paths and URLs are never
declarations. What it reads:

- requirements*.txt: requirement lines, with comments, markers, extras,
  `--hash` options and continuations handled, and `-e <vcs>#egg=<name>`.
- pyproject.toml: PEP 621 `dependencies` and `optional-dependencies`, PEP 735
  `dependency-groups`, `build-system.requires`, Poetry's `dependencies`,
  `dev-dependencies` and groups, uv's `dev-dependencies`,
  `constraint-dependencies` and `override-dependencies`, PDM's dev groups and
  resolution overrides, Hatch environment dependencies and Rye's dev group.
- Pipfile: every package category (`[packages]`, `[dev-packages]`, custom ones).
- package.json: `dependencies`, `devDependencies`, `peerDependencies` and
  `optionalDependencies` (an `npm:` alias reads as the package it names), npm
  `overrides`, Yarn `resolutions` and `pnpm.overrides`, and every launcher in
  `scripts` (`npx -y pkg@1.0.0`).
- MCP configs (JSON, JSONC or YAML): every object with a `command`, wherever
  it sits, read through the launcher grammar in `_launchers`. A command that is
  not a launcher (`"command": "ruflo"`) is a reference to the installed program
  of that name, with no version.

Each manifest declaration records its section (the requirements file, a PEP 621
list, an extra, a dependency group, a Pipfile category, a package.json section)
and its environment marker, because a pin constrains only the install it is
part of: a dev group's patched pin says nothing about what production resolves.
uv `constraint-dependencies` are the one global constraint, and the overrides
replace the regular entries; the pin table reads both that way.

A file that does not parse yields no declarations. A manifest no installer can
read installs nothing, so there is no version in it to report.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef,import-not-found]

import yaml

from agent_audit_kit.scanners._helpers import (
    compose_yaml_all,
    load_yaml,
    loads_json,
    loads_jsonc,
    loads_toml,
    refuse,
    strip_jsonc,
)
from agent_audit_kit.scanners._launchers import (
    Launched,
    basename,
    launched_packages,
    npm_spec,
    py_spec,
    shell_tokens,
    starts_with_launcher,
)


# How large a file the dependency readers take in, checked with stat() before
# the file is read. A manifest is written by hand and stays small. A lockfile
# is generated and grows with the whole resolved graph: a lockfileVersion 3
# package-lock.json spends about 450 bytes a package, so it passes 1 MB at
# about 2,200 packages. The readers used to skip a lockfile over 1 MB
# (AAK-SUPPLY-002/005) or 2 MB (the CVE pin table) without a finding, a silent
# all-clear on exactly the projects with the most dependencies. A lockfile now
# has to pass 32 MiB, some 70,000 packages at that density, before it is
# skipped, and every rule that reads lockfiles states the limit in its
# limitations. A file over the limit is still skipped without a finding; the
# limit exists only to bound what a crafted file can cost the scan.
MAX_MANIFEST_BYTES = 2_000_000
MAX_LOCKFILE_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class Declaration:
    """One declared dependency on one package."""

    name: str               # the package name as written
    version: str            # the version text as written; empty when none
    dialect: str            # how to read `version`: "npm", "poetry" or "pep440"
    ecosystem: str | None   # "js", "py", or None when the registry is unknown
    kind: str               # "dependency", "constraint", "override" or "launch"
    text: str               # the declaration as it reads, for the evidence
    # Which install the declaration belongs to: a requirements file, a PEP 621
    # list, an extra, a dependency group, a Pipfile category, a package.json
    # section. A pin in one section does not constrain an install of another.
    section: str = ""
    # The environment marker it applies under (`python_version < "3.9"`), or "".
    marker: str = ""
    # For a launch, the whole command line it came from, so a pin whose flaw sits
    # behind an option (mcp-remote's `--device-code`) can ask whether it was passed.
    argv: tuple[str, ...] = ()
    # The 1-based line the declaration starts on, where the parser knows it (a
    # requirements file is read line by line), else 0.
    line: int = 0
    # Where the declaration sits in the parsed document, as keys and indices
    # (`("devDependencies", "pkg")`, `("mcpServers", "x", "args", 1)`), so that
    # `declaration_lines` can find its line without searching the text; () for a
    # requirements line, which carries `line` instead.
    path: tuple[str | int, ...] = ()


_PIPFILE_NON_PACKAGES = frozenset({"source", "requires", "scripts", "pipenv"})
_NPM_DEPENDENCY_SECTIONS = (
    "dependencies", "devDependencies", "peerDependencies", "optionalDependencies",
)


# --- requirements files -----------------------------------------------------


def _strip_comment(line: str) -> str:
    """pip's rule: `#` starts a comment at the line start or after whitespace."""
    for i, c in enumerate(line):
        if c == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
    return line


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """(first physical line, text) of each logical line, continuations joined.

    The line is counted in `\\n`s, as an editor and SARIF count it, though
    `splitlines` also breaks on rarer separators.
    """
    out: list[tuple[int, str]] = []
    pending = ""
    newlines = 0
    start = 1
    for raw in text.splitlines(keepends=True):
        number = newlines + 1
        newlines += raw.count("\n")
        line = _strip_comment(raw.rstrip("\r\n")).rstrip()
        if not pending:
            start = number
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        joined = (pending + line).strip()
        pending = ""
        if joined:
            out.append((start, joined))
    if pending.strip():
        out.append((start, pending.strip()))
    return out


def _egg_name(reference: str) -> str:
    """The `#egg=<name>` of a VCS or URL requirement, or ""."""
    fragment = reference.partition("#")[2]
    for part in fragment.split("&"):
        if part.startswith("egg="):
            return part[4:].split("[", 1)[0]
    return ""


def _marker(requirement: str) -> str:
    """The environment marker of a PEP 508 string, whitespace-normalised, or ""."""
    marker = requirement.partition(";")[2]
    return " ".join(marker.split())


def _pep508(requirement: str, kind: str = "dependency", section: str = "") -> Declaration | None:
    """A PEP 508 requirement string, or None when it names no registry package."""
    parts = py_spec(requirement)
    if parts.kind == "local" or not parts.name:
        return None
    version = "" if parts.kind == "vcs" else parts.version
    return Declaration(parts.name, version, "pep440", "py", kind, requirement.strip(),
                       section, _marker(requirement))


def requirements_declarations(text: str) -> list[Declaration]:
    """Every line of one requirements file is one install, so one section."""
    found: list[Declaration] = []
    for number, line in _logical_lines(text):
        if line.startswith("-"):
            head, _, rest = line.partition(" ")
            option, equals, inline = head.partition("=")
            if option in ("-e", "--editable"):
                name = _egg_name((inline if equals else rest).strip())
                if name:
                    found.append(Declaration(name, "", "pep440", "py", "dependency", line,
                                             "requirements", line=number))
            continue
        # Per-requirement options (`--hash=...`) follow the requirement.
        requirement = line.split(" --", 1)[0].split("\t--", 1)[0].strip()
        if requirement.startswith(("git+", "http://", "https://", "file:")):
            name = _egg_name(requirement)
            if name:
                found.append(Declaration(name, "", "pep440", "py", "dependency", requirement,
                                         "requirements", _marker(requirement), line=number))
            continue
        declaration = _pep508(requirement, section="requirements")
        if declaration is not None:
            found.append(replace(declaration, line=number))
    return found


# --- pyproject.toml and Pipfile ---------------------------------------------


def _table(data: object, *keys: str) -> object:
    node = data
    for key in keys:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _requirement_list(
    value: object, section: str, path: tuple[str | int, ...], kind: str = "dependency"
) -> list[Declaration]:
    found: list[Declaration] = []
    if isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, str):
                declaration = _pep508(item, kind, section)
                if declaration is not None:
                    found.append(replace(declaration, path=path + (index,)))
    return found


def _requirement_groups(
    value: object, prefix: str, path: tuple[str | int, ...]
) -> list[Declaration]:
    """Each group or extra is its own install, so its own section."""
    found: list[Declaration] = []
    if isinstance(value, dict):
        for group, items in value.items():
            found.extend(_requirement_list(items, f"{prefix}.{group}", path + (group,)))
    return found


def _poetry_marker(value: dict) -> str:
    parts = [f"python {value['python']}" if isinstance(value.get("python"), str) else "",
             value["markers"] if isinstance(value.get("markers"), str) else ""]
    return " and ".join(p for p in parts if p)


def _poetry_value(
    name: str, value: object, section: str, path: tuple[str | int, ...]
) -> list[Declaration]:
    """`name = "^1.2"`, `name = {version = "^1.2", extras = [...]}`, or a list.

    A list holds alternatives for different environments (one per `python` or
    `markers` value), not constraints on one another, so each item is read as
    its own section.
    """
    if isinstance(value, str):
        return [Declaration(name, value, "poetry", "py", "dependency", f"{name} = {value!r}",
                            section, path=path)]
    if isinstance(value, dict):
        version = value.get("version")
        if isinstance(version, str):
            return [Declaration(name, version, "poetry", "py", "dependency",
                                f"{name} = {{version = {version!r}}}", section,
                                _poetry_marker(value), path=path)]
        # A git, path or url source states no registry version.
        return [Declaration(name, "", "poetry", "py", "dependency", f"{name} = {{...}}",
                            section, _poetry_marker(value), path=path)]
    if isinstance(value, list):
        found: list[Declaration] = []
        for index, item in enumerate(value):
            found.extend(_poetry_value(name, item, f"{section}#{index}", path + (index,)))
        return found
    return []


def _poetry_table(value: object, section: str, path: tuple[str | int, ...]) -> list[Declaration]:
    found: list[Declaration] = []
    if isinstance(value, dict):
        for name, spec in value.items():
            if str(name).lower() != "python":
                found.extend(_poetry_value(str(name), spec, section, path + (name,)))
    return found


def pyproject_declarations(data: dict) -> list[Declaration]:
    """Each table is its own section. uv's `constraint-dependencies` constrain
    every install and its `override-dependencies` (and PDM's resolution
    overrides) replace the regular entries, so those two carry their own kinds."""
    found: list[Declaration] = []
    found.extend(_requirement_list(_table(data, "project", "dependencies"), "project.dependencies",
                                   ("project", "dependencies")))
    found.extend(_requirement_groups(_table(data, "project", "optional-dependencies"),
                                     "project.optional-dependencies",
                                     ("project", "optional-dependencies")))
    found.extend(_requirement_groups(_table(data, "dependency-groups"), "dependency-groups",
                                     ("dependency-groups",)))
    found.extend(_requirement_list(_table(data, "build-system", "requires"), "build-system.requires",
                                   ("build-system", "requires")))
    poetry = _table(data, "tool", "poetry")
    found.extend(_poetry_table(_table(poetry, "dependencies"), "tool.poetry.dependencies",
                               ("tool", "poetry", "dependencies")))
    found.extend(_poetry_table(_table(poetry, "dev-dependencies"), "tool.poetry.dev-dependencies",
                               ("tool", "poetry", "dev-dependencies")))
    groups = _table(poetry, "group")
    if isinstance(groups, dict):
        for group, table in groups.items():
            found.extend(_poetry_table(_table(table, "dependencies"), f"tool.poetry.group.{group}",
                                       ("tool", "poetry", "group", group, "dependencies")))
    uv = _table(data, "tool", "uv")
    found.extend(_requirement_list(_table(uv, "dev-dependencies"), "tool.uv.dev-dependencies",
                                   ("tool", "uv", "dev-dependencies")))
    found.extend(_requirement_list(_table(uv, "constraint-dependencies"),
                                   "tool.uv.constraint-dependencies",
                                   ("tool", "uv", "constraint-dependencies"), kind="constraint"))
    found.extend(_requirement_list(_table(uv, "override-dependencies"),
                                   "tool.uv.override-dependencies",
                                   ("tool", "uv", "override-dependencies"), kind="override"))
    found.extend(_requirement_groups(_table(data, "tool", "pdm", "dev-dependencies"),
                                     "tool.pdm.dev-dependencies", ("tool", "pdm", "dev-dependencies")))
    overrides = _table(data, "tool", "pdm", "resolution", "overrides")
    if isinstance(overrides, dict):
        for name, spec in overrides.items():
            if isinstance(spec, str):
                found.append(Declaration(str(name), spec, "pep440", "py", "override",
                                         f"{name} = {spec!r}", "tool.pdm.resolution.overrides",
                                         path=("tool", "pdm", "resolution", "overrides", name)))
    envs = _table(data, "tool", "hatch", "envs")
    if isinstance(envs, dict):
        for env_name, env in envs.items():
            for key in ("dependencies", "extra-dependencies"):
                found.extend(_requirement_list(_table(env, key), f"tool.hatch.envs.{env_name}",
                                               ("tool", "hatch", "envs", env_name, key)))
    found.extend(_requirement_list(_table(data, "tool", "rye", "dev-dependencies"),
                                   "tool.rye.dev-dependencies", ("tool", "rye", "dev-dependencies")))
    return found


def pipfile_declarations(data: dict) -> list[Declaration]:
    """Each package category (`[packages]`, `[dev-packages]`, ...) is a section."""
    found: list[Declaration] = []
    for section, packages in data.items():
        if section in _PIPFILE_NON_PACKAGES or not isinstance(packages, dict):
            continue
        for name, value in packages.items():
            version = value if isinstance(value, str) else _table(value, "version")
            spec = version if isinstance(version, str) else ""
            shown = repr(spec) if spec else "{...}"
            markers = _table(value, "markers")
            found.append(Declaration(str(name), spec, "pep440", "py", "dependency",
                                     f"{name} = {shown}", str(section),
                                     " ".join(markers.split()) if isinstance(markers, str) else "",
                                     path=(section, name)))
    return found


# --- package.json -----------------------------------------------------------


def _npm_dependency(
    name: str, spec: str, kind: str, section: str, path: tuple[str | int, ...]
) -> Declaration:
    """A `"name": "spec"` entry. A git, file or URL spec reads as no version."""
    text = f'"{name}": "{spec}"'
    if spec.startswith("npm:"):
        alias = npm_spec(spec)
        if alias.kind == "registry" and alias.name:
            return Declaration(alias.name, alias.version, "npm", "js", kind, text, section,
                               path=path)
    return Declaration(name, spec, "npm", "js", kind, text, section, path=path)


def _override_name(key: str) -> str:
    """The package an override key targets: `**/x`, `a/x`, `a>x`, `x@<2`."""
    target = key.strip().rsplit(">", 1)[-1]
    segments = target.split("/")
    if len(segments) >= 2 and segments[-2].startswith("@"):
        name = segments[-2] + "/" + segments[-1]
    else:
        name = segments[-1]
    at = name.find("@", 1)
    return name[:at] if at != -1 else name


def _npm_overrides(
    value: object, parent: str = "", path: tuple[str | int, ...] = ("overrides",)
) -> list[Declaration]:
    """npm `overrides` nest (`{"a": {".": "1.0.0", "b": "2.0.0"}}`)."""
    found: list[Declaration] = []
    if not isinstance(value, dict):
        return found
    for key, spec in value.items():
        name = parent if key == "." else _override_name(str(key))
        if isinstance(spec, str):
            if name and not spec.startswith("$"):
                found.append(_npm_dependency(name, spec, "override", "overrides", path + (key,)))
        elif isinstance(spec, dict):
            found.extend(_npm_overrides(spec, name, path + (key,)))
    return found


def _token_path(
    argv: list[str], paths: list[tuple[str | int, ...]], spec: str
) -> tuple[str | int, ...]:
    """Where in the document the argument a launched package came from sits:
    the token itself, else the token whose shell line holds it."""
    for token, where in zip(argv, paths):
        if token == spec:
            return where
    for token, where in zip(argv, paths):
        if spec in token:
            return where
    return ()


def _launch_declarations(
    packages: list[Launched], argv: list[str], paths: list[tuple[str | int, ...]]
) -> list[Declaration]:
    found: list[Declaration] = []
    line = tuple(argv)
    for launched in packages:
        text = f"{launched.launcher} {launched.spec}"
        where = _token_path(argv, paths, launched.spec)
        if launched.ecosystem == "js":
            parts = npm_spec(launched.spec)
            if parts.kind == "registry" and parts.name:
                found.append(Declaration(parts.name, parts.version, "npm", "js", "launch", text,
                                         argv=line, path=where))
        else:
            parts = py_spec(launched.spec)
            if parts.kind != "local" and parts.name:
                version = "" if parts.kind == "vcs" else parts.version
                found.append(Declaration(parts.name, version, "pep440", "py", "launch", text,
                                         argv=line, path=where))
    return found


def package_json_declarations(data: dict) -> list[Declaration]:
    found: list[Declaration] = []
    for section in _NPM_DEPENDENCY_SECTIONS:
        deps = data.get(section)
        if isinstance(deps, dict):
            for name, spec in deps.items():
                if isinstance(spec, str):
                    found.append(_npm_dependency(str(name), spec, "dependency", section,
                                                 (section, name)))
    found.extend(_npm_overrides(data.get("overrides")))
    for key, path, overrides in (
        ("resolutions", ("resolutions",), data.get("resolutions")),
        ("pnpm.overrides", ("pnpm", "overrides"), _table(data, "pnpm", "overrides")),
    ):
        if isinstance(overrides, dict):
            for target, spec in overrides.items():
                if isinstance(spec, str) and not spec.startswith("$"):
                    found.append(_npm_dependency(_override_name(str(target)), spec, "override", key,
                                                 path + (target,)))
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for script, line in scripts.items():
            if isinstance(line, str):
                tokens = shell_tokens(line)
                found.extend(_launch_declarations(launched_packages(tokens), tokens,
                                                  [("scripts", script)] * len(tokens)))
    return found


# --- MCP configs ------------------------------------------------------------


def _is_argument(value: object) -> bool:
    return isinstance(value, (str, int, float)) and not isinstance(value, bool)


def _argv(
    entry: dict, path: tuple[str | int, ...] | None = ()
) -> tuple[list[str], list[tuple[str | int, ...]]]:
    """The command line an entry runs, and where each word of it sits: () for
    every word of an entry whose own path is None (see `_command_entries`)."""

    def at(*keys: str | int) -> tuple[str | int, ...]:
        return path + keys if path is not None else ()

    command = entry.get("command")
    tokens: list[str] = []
    paths: list[tuple[str | int, ...]] = []
    if isinstance(command, str):
        words = command.split()
        tokens.extend(words)
        paths.extend([at("command")] * len(words))
    elif isinstance(command, list):
        for index, word in enumerate(command):
            if _is_argument(word):
                tokens.append(str(word))
                paths.append(at("command", index))
    else:
        return [], []
    args = entry.get("args")
    if isinstance(args, list):
        for index, arg in enumerate(args):
            if _is_argument(arg):
                tokens.append(str(arg))
                paths.append(at("args", index))
    return tokens, paths


# The longest path in a parsed JSON, YAML or TOML document that is built or
# recorded: `_command_entries` builds none longer for a server, counting the
# two keys a word of its command line adds (`"args", 3`), and the position
# passes ("where a declaration is written", below) record none longer. A
# declaration nested deeper is still reported, without a line; a client reads
# an MCP server two to six levels down, and a package.json override a few more.
_MAX_PATH_DEPTH = 64


def _command_entries(data: object) -> list[tuple[dict, tuple[str | int, ...] | None]]:
    """Every object holding a `command`, at any depth, in document order, with
    its path, or None for one deeper than `_MAX_PATH_DEPTH` allows (its words
    have no position then). A container met twice, which only a YAML alias can
    make, is read once, by identity, and keeps the path it was first reached by.
    The walk followed every path to a shared node: seven levels of anchors, ten
    aliases each, is a 449-byte file that reaches the same ten servers by 10^7
    paths, and the pin table took 26 s of CPU time on it. A server an alias
    repeats is the same server, read once, and a document that contains itself
    (`&a [*a]`) ends.

    Each queued container carries the record of its parent rather than its own
    path: copying the path at every level cost the square of the depth, so a
    1.9 MB root .mcp.json of 105 chains of 9,000 lists took 10.8 s in the pin
    table on Python 3.12, and 9 chains of 100,000 took 110 s on 3.14, where
    JSON's parser reads that deep. A path is built from the records only for
    an entry, and not past the bound: one server inside another, 9,000 levels
    down, made 9,000 entries whose paths together held the square of that, and
    1.4 MB of such chains held 1.75 GB.
    """
    if not isinstance(data, (dict, list)):
        return []
    entries: list[tuple[dict, int]] = []
    # Per record (one per container, in the order the walk reads them): the
    # parent's record (-1 for the top level), the key or index the container
    # sits under, and its depth.
    parents: list[int] = []
    keys: list[str | int] = []
    depths: list[int] = []
    queue: deque[tuple[object, int, str | int]] = deque([(data, -1, "")])
    seen: set[int] = set()
    while queue:
        node, parent, key = queue.popleft()
        if id(node) in seen:
            continue
        seen.add(id(node))
        record = len(parents)
        parents.append(parent)
        keys.append(key)
        depths.append(depths[parent] + 1 if parent >= 0 else 0)
        if isinstance(node, dict):
            if isinstance(node.get("command"), (str, list)):
                entries.append((node, record))
            queue.extend((value, record, k) for k, value in node.items()
                         if isinstance(value, (dict, list)))
        elif isinstance(node, list):
            queue.extend((value, record, index) for index, value in enumerate(node)
                         if isinstance(value, (dict, list)))
    return [(node, _record_path(record, parents, keys, depths)) for node, record in entries]


def _record_path(
    record: int, parents: list[int], keys: list[str | int], depths: list[int]
) -> tuple[str | int, ...] | None:
    """The path of a `_command_entries` record, or None past `_MAX_PATH_DEPTH`,
    less the two keys a word of its command line adds (`"args", 3`)."""
    if depths[record] > _MAX_PATH_DEPTH - 2:
        return None
    path: list[str | int] = []
    while parents[record] >= 0:
        path.append(keys[record])
        record = parents[record]
    return tuple(reversed(path))


def mcp_config_declarations(data: object) -> list[Declaration]:
    found: list[Declaration] = []
    for entry, where in _command_entries(data):
        argv, paths = _argv(entry, where)
        if not argv:
            continue
        found.extend(_launch_declarations(launched_packages(argv), argv, paths))
        head = basename(argv[0])
        if head and not starts_with_launcher(argv):
            # A program run by name: the installed package of that name, at an
            # unknown version (`"command": "ruflo"`). Its registry is unknown.
            found.append(Declaration(head, "", "npm", None, "launch", f"command {head}",
                                     argv=tuple(argv), path=paths[0]))
    return found


# --- dispatch ----------------------------------------------------------------


def declarations(path: Path, text: str) -> list[Declaration]:
    """The declarations `path` makes, or [] when it does not parse.

    Args:
        path: The candidate file; its name selects the format.
        text: The file's contents.

    Returns:
        Every dependency declaration the file makes, in file order.
    """
    name = path.name.lower()
    try:
        if name.startswith("requirements") and name.endswith(".txt"):
            return requirements_declarations(text)
        if name == "pyproject.toml":
            return pyproject_declarations(loads_toml(text, path))
        if name == "pipfile":
            return pipfile_declarations(loads_toml(text, path))
        if name == "package.json":
            data = loads_json(text, path)
            return package_json_declarations(data) if isinstance(data, dict) else []
        if name.endswith((".yaml", ".yml")):
            # `_command_entries` reads each container once, so a document that
            # contains itself ends there and is read, not refused.
            return mcp_config_declarations(load_yaml(text, path, cycles_ok=True))
        if name.endswith(".json"):
            return mcp_config_declarations(loads_jsonc(text, path))
    except (ValueError, tomllib.TOMLDecodeError, yaml.YAMLError):
        return []
    except RecursionError:
        # A dependency table nested past the recursion limit (npm `overrides`,
        # a Poetry list of alternatives) is refused, not read as no
        # dependencies: the parse helpers already refuse a file the parser
        # cannot take, and this is the same file seen one step later.
        refuse(path, "dependency table nested too deep to read (RecursionError)")
        return []
    return []


# --- where a declaration is written ------------------------------------------
#
# A finding that names no line has no SARIF region, so code scanning and the
# VS Code extension put it on the first line of the file. A requirements file
# is read line by line and its declarations carry their line. The other formats
# are parsed whole (JSON, TOML, YAML), which loses positions, so each
# declaration records its path in the parsed document instead, and the line of
# every path is read off the text in one pass, the first time a file has a
# finding. The positions come from the document's own structure, not from a
# search for the declaration's words: a search took the first place that spelt
# them, which was a comment, another package whose key ended in the same name
# (`"@acme/n8n-mcp"` for an override of `n8n-mcp`), or the same package in an
# earlier table at a fixed version, and it re-read the whole file for each
# finding (96 findings in a 31 MiB lockfile took 76 s against 3 s). A path the
# pass did not reach gives no line rather than a guessed one.
#
# A pass records no path longer than `_MAX_PATH_DEPTH`. Each recorded path is a
# tuple, so recording every one cost the sum of all their lengths: four JSON
# chains of 6,000 lists (48 KB) held 579 MB, and 400 TOML arrays nested 300
# deep (243 KB) 155 MB. A pinned server beside 1,000 JSON chains of 480 lists
# (961 KB, inside the 500-level limit) held 969 MB of traced memory in the pin
# table for its line. The structure deeper down is still read, so the paths
# above it keep their lines.

# A JSON string, or one structural character. Scalars are skipped: no
# declaration is a number or a literal, and the commas around them keep count.
# The closing quote is optional, so text that is not JSON still costs one pass.
_JSON_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"?|[{}\[\]:,]')


def _json_key(token: str) -> str:
    try:
        key = loads_json(token, None)
    except ValueError:
        return token[1:-1]
    return key if isinstance(key, str) else token[1:-1]


def _json_positions(text: str) -> dict[tuple[str | int, ...], int]:
    """The line of every string, object and array in a JSON or JSONC document,
    by path. A duplicated key keeps its last position, as `json.loads` keeps
    the last value."""
    try:
        text = strip_jsonc(text)
    except ValueError:
        return {}
    positions: dict[tuple[str | int, ...], int] = {}
    # One frame per open container: [is_object, path, key or index, state],
    # where an object's state is "key", "colon" or "value" and an array's
    # "value" until its element is read.
    stack: list[list] = []
    line, last = 1, 0
    for m in _JSON_TOKEN_RE.finditer(text):
        token, start = m.group(), m.start()
        line += text.count("\n", last, start)
        last = start
        frame = stack[-1] if stack else None
        if token[0] == '"':
            if frame is None:
                positions[()] = line
            elif frame[0] and frame[3] == "key":
                # A key below the bound names no recorded path, so it is not decoded.
                frame[2], frame[3] = (_json_key(token) if frame[1] is not None else ""), "colon"
            elif frame[3] == "value":
                if frame[1] is not None and len(frame[1]) < _MAX_PATH_DEPTH:
                    positions[frame[1] + (frame[2],)] = line
                frame[3] = "done"
        elif token in "{[":
            child: tuple[str | int, ...] | None
            if frame is None:
                child = ()
            elif frame[3] == "value":
                child = (frame[1] + (frame[2],)
                         if frame[1] is not None and len(frame[1]) < _MAX_PATH_DEPTH else None)
                frame[3] = "done"
            else:
                break  # not a document `json.loads` accepted; keep what was read
            if child is not None:
                positions[child] = line
            if token == "{":
                stack.append([True, child, "", "key"])
            else:
                stack.append([False, child, 0, "value"])
        elif token in "}]":
            if stack:
                stack.pop()
        elif token == ":":
            if frame is not None and frame[0] and frame[3] == "colon":
                frame[3] = "value"
        elif frame is not None:  # ","
            if frame[0]:
                frame[3] = "key"
            else:
                frame[2] += 1
                frame[3] = "value"
    return positions


_TOML_SPACE_RE = re.compile(r"[ \t]*")
_TOML_BARE_KEY_RE = re.compile(r"[A-Za-z0-9_-]+")
_TOML_BASIC_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"')
_TOML_LITERAL_RE = re.compile(r"'[^'\n]*'")
# A number, boolean or date: everything up to what may follow a value. A date
# may hold a space (`1979-05-27 07:32:00Z`).
_TOML_BARE_VALUE_RE = re.compile(r"[^,\]\}\n#]*")


class _TomlPositions:
    """The line of every key, table and array item of a TOML document, by path.

    tomllib keeps no positions, so this walks a document tomllib has already
    accepted: table headers, with each array of tables (`[[package]]`) counted so
    that `[package.source]` resolves to the last one, dotted and quoted keys,
    inline tables, arrays across lines, every string form and comments. It
    reads, it does not validate: on anything it does not expect it stops and
    returns what it has.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.i = 0
        self.line = 1
        self.positions: dict[tuple[str | int, ...], int] = {}
        self.arrays: dict[tuple[str | int, ...], int] = {}

    def run(self) -> dict[tuple[str | int, ...], int]:
        try:
            self._document()
        except (IndexError, ValueError, RecursionError):
            pass
        return self.positions

    def _space(self) -> None:
        self._match(_TOML_SPACE_RE)

    def _blank(self) -> None:
        """Spaces, line breaks and comments."""
        text, n = self.text, len(self.text)
        while True:
            self._space()
            if self.i >= n:
                return
            c = text[self.i]
            if c == "\n":
                self.line += 1
                self.i += 1
            elif c == "\r":
                self.i += 1
            elif c == "#":
                end = text.find("\n", self.i)
                self.i = n if end < 0 else end
            else:
                return

    def _expect(self, token: str) -> None:
        if not self.text.startswith(token, self.i):
            raise ValueError(token)
        self.i += len(token)

    def _match(self, pattern: re.Pattern[str]) -> str:
        m = pattern.match(self.text, self.i)
        if m is None:
            raise ValueError(pattern.pattern)
        self.i = m.end()
        return m.group()

    def _key(self) -> tuple[str, ...]:
        parts: list[str] = []
        while True:
            self._space()
            c = self.text[self.i]
            if c == '"':
                parts.append(_json_key(self._match(_TOML_BASIC_RE)))
            elif c == "'":
                parts.append(self._match(_TOML_LITERAL_RE)[1:-1])
            else:
                parts.append(self._match(_TOML_BARE_KEY_RE))
            self._space()
            if self.text.startswith(".", self.i):
                self.i += 1
                continue
            return tuple(parts)

    def _resolve(self, parts: tuple[str, ...]) -> tuple[str | int, ...]:
        """A header's path, with the current index of each array of tables in it."""
        out: tuple[str | int, ...] = ()
        for part in parts:
            out = out + (part,)
            if out in self.arrays:
                out = out + (self.arrays[out],)
        return out

    def _document(self) -> None:
        text, n = self.text, len(self.text)
        table: tuple[str | int, ...] = ()
        while True:
            self._blank()
            if self.i >= n:
                return
            if text.startswith("[[", self.i):
                self.i += 2
                parts = self._key()
                self._expect("]]")
                full = self._resolve(parts[:-1]) + (parts[-1],)
                self.arrays[full] = self.arrays.get(full, -1) + 1
                table = full + (self.arrays[full],)
                if len(table) <= _MAX_PATH_DEPTH:
                    self.positions[table] = self.line
            elif text[self.i] == "[":
                self.i += 1
                parts = self._key()
                self._expect("]")
                table = self._resolve(parts)
                if len(table) <= _MAX_PATH_DEPTH:
                    self.positions[table] = self.line
            else:
                key_path = self._below(table, self._key())
                if key_path is not None:
                    self.positions[key_path] = self.line
                self._expect("=")
                self._space()
                self._value(key_path)

    @staticmethod
    def _below(
        path: tuple[str | int, ...] | None, keys: tuple[str | int, ...]
    ) -> tuple[str | int, ...] | None:
        """`path` extended by `keys`, or None past `_MAX_PATH_DEPTH` (see above)."""
        if path is None or len(path) + len(keys) > _MAX_PATH_DEPTH:
            return None
        return path + keys

    def _value(self, path: tuple[str | int, ...] | None) -> None:
        text = self.text
        c = text[self.i]
        if c == "[":
            self.i += 1
            index = 0
            while True:
                self._blank()
                if text[self.i] == "]":
                    self.i += 1
                    return
                item = self._below(path, (index,))
                if item is not None:
                    self.positions[item] = self.line
                self._value(item)
                self._blank()
                if text[self.i] == ",":
                    self.i += 1
                    index += 1
                    continue
                self._expect("]")
                return
        elif c == "{":
            self.i += 1
            while True:
                self._blank()
                if text[self.i] == "}":
                    self.i += 1
                    return
                full = self._below(path, self._key())
                if full is not None:
                    self.positions[full] = self.line
                self._expect("=")
                self._space()
                self._value(full)
                self._blank()
                if text[self.i] == ",":
                    self.i += 1
                    continue
                self._expect("}")
                return
        elif text.startswith('"""', self.i) or text.startswith("'''", self.i):
            self._multiline(text[self.i:self.i + 3])
        elif c == '"':
            self._match(_TOML_BASIC_RE)
        elif c == "'":
            self._match(_TOML_LITERAL_RE)
        else:
            self._match(_TOML_BARE_VALUE_RE)

    def _multiline(self, quote: str) -> None:
        text, start = self.text, self.i
        at = start + 3
        while True:
            close = text.find(quote, at)
            if close < 0:
                raise ValueError(quote)
            backslashes = 0
            while quote == '"""' and text[close - 1 - backslashes] == "\\":
                backslashes += 1
            if backslashes % 2 == 0:
                break
            at = close + 1
        end = close + 3
        while end < len(text) and text[end] == quote[0] and end - close < 5:
            end += 1  # up to two quotes may end the content
        self.line += text.count("\n", start, end)
        self.i = end


def _toml_positions(text: str) -> dict[tuple[str | int, ...], int]:
    return _TomlPositions(text).run()


def _yaml_positions(text: str) -> dict[tuple[str | int, ...], int]:
    """The line of every node of a YAML document, by path (scalar keys only)."""
    try:
        roots = compose_yaml_all(text, None)
    except (yaml.YAMLError, RecursionError):
        return {}
    root = roots[0] if len(roots) == 1 else None  # `yaml.compose` takes one document
    positions: dict[tuple[str | int, ...], int] = {}
    # Breadth first in document order, as `_command_entries` walks the loaded
    # document, so a node an alias shares gets the path that walk records for it.
    queue: deque[tuple[yaml.Node, tuple[str | int, ...]]] = deque(
        [(root, ())] if root is not None else [])
    seen: set[int] = set()
    while queue:
        node, where = queue.popleft()
        if id(node) in seen:  # an alias can point back at its own ancestor
            continue
        seen.add(id(node))
        positions[where] = node.start_mark.line + 1
        if len(where) >= _MAX_PATH_DEPTH:
            continue
        if isinstance(node, yaml.MappingNode):
            queue.extend((value, where + (key.value,)) for key, value in node.value
                         if isinstance(key, yaml.ScalarNode))
        elif isinstance(node, yaml.SequenceNode):
            queue.extend((item, where + (index,)) for index, item in enumerate(node.value))
    return positions


def declaration_lines(path: Path, text: str) -> Callable[[Declaration], int | None]:
    """A lookup of the line each declaration `declarations(path, text)` returned
    is written on.

    The file's positions are read once, when this is called, so a caller with
    several findings in one file calls it once and asks it for each.

    Args:
        path: The file the declarations were read from; its name selects the format.
        text: The file's contents.

    Returns:
        A function from a declaration to its 1-based line, or None when its
        position is unknown.
    """
    name = path.name.lower()
    positions: dict[tuple[str | int, ...], int] = {}
    if name in ("pyproject.toml", "pipfile"):
        positions = _toml_positions(text)
    elif name.endswith(".json"):
        positions = _json_positions(text)
    elif name.endswith((".yaml", ".yml")):
        positions = _yaml_positions(text)

    def line(declaration: Declaration) -> int | None:
        if declaration.line:
            return declaration.line
        if not declaration.path:
            return None
        return positions.get(declaration.path)

    return line


def declaration_line(text: str, declaration: Declaration, file_name: str) -> int | None:
    """The 1-based line one declaration is written on, or None.

    Reads the whole file's positions; for more than one declaration of a file,
    call `declaration_lines` once instead.

    Args:
        text: The contents of the file the declaration was read from.
        declaration: One of the declarations `declarations()` returned for it.
        file_name: That file's name; it selects the format.

    Returns:
        The line, or None when its position is unknown.
    """
    return declaration_lines(Path(file_name), text)(declaration)
