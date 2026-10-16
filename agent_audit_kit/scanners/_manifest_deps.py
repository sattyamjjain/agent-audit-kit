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

import json
import re
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef,import-not-found]

import yaml

from agent_audit_kit.scanners._helpers import loads_jsonc, strip_jsonc
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
    # requirements file is read line by line), else 0 and `declaration_line`
    # finds it in the text.
    line: int = 0


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
    value: object, section: str, kind: str = "dependency"
) -> list[Declaration]:
    found: list[Declaration] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                declaration = _pep508(item, kind, section)
                if declaration is not None:
                    found.append(declaration)
    return found


def _requirement_groups(value: object, prefix: str) -> list[Declaration]:
    """Each group or extra is its own install, so its own section."""
    found: list[Declaration] = []
    if isinstance(value, dict):
        for group, items in value.items():
            found.extend(_requirement_list(items, f"{prefix}.{group}"))
    return found


def _poetry_marker(value: dict) -> str:
    parts = [f"python {value['python']}" if isinstance(value.get("python"), str) else "",
             value["markers"] if isinstance(value.get("markers"), str) else ""]
    return " and ".join(p for p in parts if p)


def _poetry_value(name: str, value: object, section: str) -> list[Declaration]:
    """`name = "^1.2"`, `name = {version = "^1.2", extras = [...]}`, or a list.

    A list holds alternatives for different environments (one per `python` or
    `markers` value), not constraints on one another, so each item is read as
    its own section.
    """
    if isinstance(value, str):
        return [Declaration(name, value, "poetry", "py", "dependency", f"{name} = {value!r}",
                            section)]
    if isinstance(value, dict):
        version = value.get("version")
        if isinstance(version, str):
            return [Declaration(name, version, "poetry", "py", "dependency",
                                f"{name} = {{version = {version!r}}}", section,
                                _poetry_marker(value))]
        # A git, path or url source states no registry version.
        return [Declaration(name, "", "poetry", "py", "dependency", f"{name} = {{...}}",
                            section, _poetry_marker(value))]
    if isinstance(value, list):
        found: list[Declaration] = []
        for index, item in enumerate(value):
            found.extend(_poetry_value(name, item, f"{section}#{index}"))
        return found
    return []


def _poetry_table(value: object, section: str) -> list[Declaration]:
    found: list[Declaration] = []
    if isinstance(value, dict):
        for name, spec in value.items():
            if str(name).lower() != "python":
                found.extend(_poetry_value(str(name), spec, section))
    return found


def pyproject_declarations(data: dict) -> list[Declaration]:
    """Each table is its own section. uv's `constraint-dependencies` constrain
    every install and its `override-dependencies` (and PDM's resolution
    overrides) replace the regular entries, so those two carry their own kinds."""
    found: list[Declaration] = []
    found.extend(_requirement_list(_table(data, "project", "dependencies"), "project.dependencies"))
    found.extend(_requirement_groups(_table(data, "project", "optional-dependencies"),
                                     "project.optional-dependencies"))
    found.extend(_requirement_groups(_table(data, "dependency-groups"), "dependency-groups"))
    found.extend(_requirement_list(_table(data, "build-system", "requires"), "build-system.requires"))
    poetry = _table(data, "tool", "poetry")
    found.extend(_poetry_table(_table(poetry, "dependencies"), "tool.poetry.dependencies"))
    found.extend(_poetry_table(_table(poetry, "dev-dependencies"), "tool.poetry.dev-dependencies"))
    groups = _table(poetry, "group")
    if isinstance(groups, dict):
        for group, table in groups.items():
            found.extend(_poetry_table(_table(table, "dependencies"), f"tool.poetry.group.{group}"))
    uv = _table(data, "tool", "uv")
    found.extend(_requirement_list(_table(uv, "dev-dependencies"), "tool.uv.dev-dependencies"))
    found.extend(_requirement_list(_table(uv, "constraint-dependencies"),
                                   "tool.uv.constraint-dependencies", kind="constraint"))
    found.extend(_requirement_list(_table(uv, "override-dependencies"),
                                   "tool.uv.override-dependencies", kind="override"))
    found.extend(_requirement_groups(_table(data, "tool", "pdm", "dev-dependencies"),
                                     "tool.pdm.dev-dependencies"))
    overrides = _table(data, "tool", "pdm", "resolution", "overrides")
    if isinstance(overrides, dict):
        for name, spec in overrides.items():
            if isinstance(spec, str):
                found.append(Declaration(str(name), spec, "pep440", "py", "override",
                                         f"{name} = {spec!r}", "tool.pdm.resolution.overrides"))
    envs = _table(data, "tool", "hatch", "envs")
    if isinstance(envs, dict):
        for env_name, env in envs.items():
            found.extend(_requirement_list(_table(env, "dependencies"), f"tool.hatch.envs.{env_name}"))
            found.extend(_requirement_list(_table(env, "extra-dependencies"),
                                           f"tool.hatch.envs.{env_name}"))
    found.extend(_requirement_list(_table(data, "tool", "rye", "dev-dependencies"),
                                   "tool.rye.dev-dependencies"))
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
                                     " ".join(markers.split()) if isinstance(markers, str) else ""))
    return found


# --- package.json -----------------------------------------------------------


def _npm_dependency(name: str, spec: str, kind: str, section: str) -> Declaration:
    """A `"name": "spec"` entry. A git, file or URL spec reads as no version."""
    text = f'"{name}": "{spec}"'
    if spec.startswith("npm:"):
        alias = npm_spec(spec)
        if alias.kind == "registry" and alias.name:
            return Declaration(alias.name, alias.version, "npm", "js", kind, text, section)
    return Declaration(name, spec, "npm", "js", kind, text, section)


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


def _npm_overrides(value: object, parent: str = "") -> list[Declaration]:
    """npm `overrides` nest (`{"a": {".": "1.0.0", "b": "2.0.0"}}`)."""
    found: list[Declaration] = []
    if not isinstance(value, dict):
        return found
    for key, spec in value.items():
        name = parent if key == "." else _override_name(str(key))
        if isinstance(spec, str):
            if name and not spec.startswith("$"):
                found.append(_npm_dependency(name, spec, "override", "overrides"))
        elif isinstance(spec, dict):
            found.extend(_npm_overrides(spec, name))
    return found


def _launch_declarations(packages: list[Launched], argv: list[str]) -> list[Declaration]:
    found: list[Declaration] = []
    line = tuple(argv)
    for launched in packages:
        text = f"{launched.launcher} {launched.spec}"
        if launched.ecosystem == "js":
            parts = npm_spec(launched.spec)
            if parts.kind == "registry" and parts.name:
                found.append(Declaration(parts.name, parts.version, "npm", "js", "launch", text,
                                         argv=line))
        else:
            parts = py_spec(launched.spec)
            if parts.kind != "local" and parts.name:
                version = "" if parts.kind == "vcs" else parts.version
                found.append(Declaration(parts.name, version, "pep440", "py", "launch", text,
                                         argv=line))
    return found


def package_json_declarations(data: dict) -> list[Declaration]:
    found: list[Declaration] = []
    for section in _NPM_DEPENDENCY_SECTIONS:
        deps = data.get(section)
        if isinstance(deps, dict):
            for name, spec in deps.items():
                if isinstance(spec, str):
                    found.append(_npm_dependency(str(name), spec, "dependency", section))
    found.extend(_npm_overrides(data.get("overrides")))
    for key, overrides in (("resolutions", data.get("resolutions")),
                           ("pnpm.overrides", _table(data, "pnpm", "overrides"))):
        if isinstance(overrides, dict):
            for target, spec in overrides.items():
                if isinstance(spec, str) and not spec.startswith("$"):
                    found.append(_npm_dependency(_override_name(str(target)), spec, "override", key))
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for line in scripts.values():
            if isinstance(line, str):
                tokens = shell_tokens(line)
                found.extend(_launch_declarations(launched_packages(tokens), tokens))
    return found


# --- MCP configs ------------------------------------------------------------


def _argv(entry: dict) -> list[str]:
    command = entry.get("command")
    if isinstance(command, str):
        tokens = command.split()
    elif isinstance(command, list):
        tokens = [str(t) for t in command if isinstance(t, (str, int, float)) and not isinstance(t, bool)]
    else:
        return []
    args = entry.get("args")
    if isinstance(args, list):
        tokens.extend(str(a) for a in args if isinstance(a, (str, int, float)) and not isinstance(a, bool))
    return tokens


def _command_entries(data: object) -> list[dict]:
    """Every object holding a `command`, at any depth, in document order."""
    entries: list[dict] = []
    queue: deque[object] = deque([data])
    while queue:
        node = queue.popleft()
        if isinstance(node, dict):
            if isinstance(node.get("command"), (str, list)):
                entries.append(node)
            queue.extend(node.values())
        elif isinstance(node, list):
            queue.extend(node)
    return entries


def mcp_config_declarations(data: object) -> list[Declaration]:
    found: list[Declaration] = []
    for entry in _command_entries(data):
        argv = _argv(entry)
        if not argv:
            continue
        found.extend(_launch_declarations(launched_packages(argv), argv))
        head = basename(argv[0])
        if head and not starts_with_launcher(argv):
            # A program run by name: the installed package of that name, at an
            # unknown version (`"command": "ruflo"`). Its registry is unknown.
            found.append(Declaration(head, "", "npm", None, "launch", f"command {head}",
                                     argv=tuple(argv)))
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
            return pyproject_declarations(tomllib.loads(text))
        if name == "pipfile":
            return pipfile_declarations(tomllib.loads(text))
        if name == "package.json":
            data = json.loads(text)
            return package_json_declarations(data) if isinstance(data, dict) else []
        if name.endswith((".yaml", ".yml")):
            return mcp_config_declarations(yaml.safe_load(text))
        if name.endswith(".json"):
            return mcp_config_declarations(loads_jsonc(text))
    except (ValueError, tomllib.TOMLDecodeError, yaml.YAMLError, RecursionError):
        return []
    return []


# --- where a declaration is written ------------------------------------------
#
# A finding that names no line has no SARIF region, so code scanning and the
# VS Code extension put it on the first line of the file. A requirements file
# is read line by line and its declarations carry their line. The other formats
# are parsed whole (JSON, TOML, YAML), which loses positions, so the line is
# found again in the text, from the offset of the first place that spells the
# declaration: the text as written where the format keeps it verbatim (a PEP
# 508 string, a package.json entry), a `name =` key or table header in TOML,
# and for a launch its package argument, never the server key that often
# repeats the name. A match inside a comment does not count, which is the
# reason a plain text search (`find_line_number`) would not do: a comment that
# names the package above its declaration took the line, as it took the
# version before #987. JSON comments are blanked first (`strip_jsonc` keeps
# offsets); `#` before the match on its line marks a comment in the other
# formats. Every pattern is a literal with fixed-width context, and each look
# back and ahead is bounded, so a file that repeats the name on one long line
# costs one pass.

_LOOK_BACK = 1024
# What may not touch a launch's package argument on either side, so that
# `pkg@1.0.0` is not read inside `other-pkg@1.0.0` or `pkg@1.0.0-beta`.
_TOKEN_CHARS = r"\w@./:+-"
_NOT_A_KEY = r"""(?!["']?[ \t]{0,16}:)"""


def _launch_spec(declaration: Declaration) -> str:
    """The package argument a launch declaration was read from, as written."""
    return declaration.text.rsplit(" ", 1)[-1]


def _patterns(declaration: Declaration, file_name: str) -> list[re.Pattern[str]]:
    """The spellings of `declaration` to look for, most exact first."""
    name = re.escape(declaration.name)
    word = rf"(?<![\w.-]){name}(?![\w.-])"
    if declaration.kind == "launch":
        spec = re.escape(_launch_spec(declaration))
        token = rf"(?<![{_TOKEN_CHARS}]){spec}(?![{_TOKEN_CHARS}])"
        # The server is often keyed by its package name, and a key is not the launch.
        return [re.compile(token + _NOT_A_KEY, re.IGNORECASE),
                re.compile(word + _NOT_A_KEY, re.IGNORECASE)]
    key, sep, value = declaration.text.partition('": "')
    if file_name == "package.json" and sep:
        exact = re.compile(re.escape(key + '"') + r"[ \t]{0,16}:[ \t]{0,16}"
                           + re.escape('"' + value))
    else:
        exact = re.compile(re.escape(declaration.text))
    return [
        exact,
        # A TOML key (`name = ...`) or table header (`[tool.poetry.dependencies.name]`).
        re.compile(rf"""(?m)^[ \t]*["']?{name}["']?[ \t]*=""", re.IGNORECASE),
        re.compile(rf"""(?m)^[ \t]*\[[^\]\n]{{0,256}}\.["']?{name}["']?[ \t]*\]""",
                   re.IGNORECASE),
        # A JSON key that ends in the name (`"**/name": ...`, an npm override).
        re.compile(word + r"""["'][ \t]{0,16}:""", re.IGNORECASE),
        re.compile(word, re.IGNORECASE),
    ]


def _in_comment(text: str, at: int) -> bool:
    """Does a `#` outside a string come before `at` on its line?

    Looks back a bounded distance, and reads a `#` as inside a string when an
    odd number of quotes precedes it, which is enough for one-line TOML and
    YAML values (`"pkg @ git+https://host/repo#egg=pkg"`).
    """
    line_start = text.rfind("\n", max(0, at - _LOOK_BACK), at) + 1
    prefix = text[max(line_start, at - _LOOK_BACK):at]
    hash_at = prefix.find("#")
    if hash_at == -1:
        return False
    return prefix.count('"', 0, hash_at) % 2 == 0 and prefix.count("'", 0, hash_at) % 2 == 0


def declaration_line(text: str, declaration: Declaration, file_name: str) -> int | None:
    """The 1-based line `declaration` is written on in `text`, or None.

    Args:
        text: The contents of the file the declaration was read from.
        declaration: One of the declarations `declarations()` returned for it.
        file_name: That file's name; it selects the comment syntax.

    Returns:
        The line the parser recorded, else the line of the first match outside
        a comment of the patterns that spell the declaration, else None.
    """
    if declaration.line:
        return declaration.line
    name = file_name.lower()
    hash_comments = not name.endswith(".json")
    if not hash_comments:
        try:
            text = strip_jsonc(text)
        except ValueError:
            pass
    for pattern in _patterns(declaration, name):
        for m in pattern.finditer(text):
            if hash_comments and _in_comment(text, m.start()):
                continue
            return text.count("\n", 0, m.start()) + 1
    return None
