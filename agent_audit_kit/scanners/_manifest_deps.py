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

A file that does not parse yields no declarations. A manifest no installer can
read installs nothing, so there is no version in it to report.
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef,import-not-found]

import yaml

from agent_audit_kit.scanners._launchers import (
    Launched,
    basename,
    launched_packages,
    npm_spec,
    py_spec,
    shell_tokens,
    starts_with_launcher,
)


@dataclass(frozen=True)
class Declaration:
    """One declared dependency on one package."""

    name: str               # the package name as written
    version: str            # the version text as written; empty when none
    dialect: str            # how to read `version`: "npm", "poetry" or "pep440"
    ecosystem: str | None   # "js", "py", or None when the registry is unknown
    kind: str               # "dependency", "override" or "launch"
    text: str               # the declaration as it reads, for the evidence


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


def _logical_lines(text: str) -> list[str]:
    out: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = _strip_comment(raw).rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        joined = (pending + line).strip()
        pending = ""
        if joined:
            out.append(joined)
    if pending.strip():
        out.append(pending.strip())
    return out


def _egg_name(reference: str) -> str:
    """The `#egg=<name>` of a VCS or URL requirement, or ""."""
    fragment = reference.partition("#")[2]
    for part in fragment.split("&"):
        if part.startswith("egg="):
            return part[4:].split("[", 1)[0]
    return ""


def _pep508(requirement: str, kind: str = "dependency") -> Declaration | None:
    """A PEP 508 requirement string, or None when it names no registry package."""
    parts = py_spec(requirement)
    if parts.kind == "local" or not parts.name:
        return None
    version = "" if parts.kind == "vcs" else parts.version
    return Declaration(parts.name, version, "pep440", "py", kind, requirement.strip())


def requirements_declarations(text: str) -> list[Declaration]:
    found: list[Declaration] = []
    for line in _logical_lines(text):
        if line.startswith("-"):
            head, _, rest = line.partition(" ")
            option, equals, inline = head.partition("=")
            if option in ("-e", "--editable"):
                name = _egg_name((inline if equals else rest).strip())
                if name:
                    found.append(Declaration(name, "", "pep440", "py", "dependency", line))
            continue
        # Per-requirement options (`--hash=...`) follow the requirement.
        requirement = line.split(" --", 1)[0].split("\t--", 1)[0].strip()
        if requirement.startswith(("git+", "http://", "https://", "file:")):
            name = _egg_name(requirement)
            if name:
                found.append(Declaration(name, "", "pep440", "py", "dependency", requirement))
            continue
        declaration = _pep508(requirement)
        if declaration is not None:
            found.append(declaration)
    return found


# --- pyproject.toml and Pipfile ---------------------------------------------


def _table(data: object, *keys: str) -> object:
    node = data
    for key in keys:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _requirement_list(value: object, kind: str = "dependency") -> list[Declaration]:
    found: list[Declaration] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                declaration = _pep508(item, kind)
                if declaration is not None:
                    found.append(declaration)
    return found


def _requirement_groups(value: object) -> list[Declaration]:
    found: list[Declaration] = []
    if isinstance(value, dict):
        for group in value.values():
            found.extend(_requirement_list(group))
    return found


def _poetry_value(name: str, value: object) -> list[Declaration]:
    """`name = "^1.2"`, `name = {version = "^1.2", extras = [...]}`, or a list."""
    if isinstance(value, str):
        return [Declaration(name, value, "poetry", "py", "dependency", f"{name} = {value!r}")]
    if isinstance(value, dict):
        version = value.get("version")
        if isinstance(version, str):
            return [Declaration(name, version, "poetry", "py", "dependency",
                                f"{name} = {{version = {version!r}}}")]
        # A git, path or url source states no registry version.
        return [Declaration(name, "", "poetry", "py", "dependency", f"{name} = {{...}}")]
    if isinstance(value, list):
        found: list[Declaration] = []
        for item in value:
            found.extend(_poetry_value(name, item))
        return found
    return []


def _poetry_table(value: object) -> list[Declaration]:
    found: list[Declaration] = []
    if isinstance(value, dict):
        for name, spec in value.items():
            if str(name).lower() != "python":
                found.extend(_poetry_value(str(name), spec))
    return found


def pyproject_declarations(data: dict) -> list[Declaration]:
    found: list[Declaration] = []
    found.extend(_requirement_list(_table(data, "project", "dependencies")))
    found.extend(_requirement_groups(_table(data, "project", "optional-dependencies")))
    found.extend(_requirement_groups(_table(data, "dependency-groups")))
    found.extend(_requirement_list(_table(data, "build-system", "requires")))
    poetry = _table(data, "tool", "poetry")
    found.extend(_poetry_table(_table(poetry, "dependencies")))
    found.extend(_poetry_table(_table(poetry, "dev-dependencies")))
    groups = _table(poetry, "group")
    if isinstance(groups, dict):
        for group in groups.values():
            found.extend(_poetry_table(_table(group, "dependencies")))
    uv = _table(data, "tool", "uv")
    found.extend(_requirement_list(_table(uv, "dev-dependencies")))
    found.extend(_requirement_list(_table(uv, "constraint-dependencies")))
    found.extend(_requirement_list(_table(uv, "override-dependencies"), kind="override"))
    found.extend(_requirement_groups(_table(data, "tool", "pdm", "dev-dependencies")))
    overrides = _table(data, "tool", "pdm", "resolution", "overrides")
    if isinstance(overrides, dict):
        for name, spec in overrides.items():
            if isinstance(spec, str):
                found.append(Declaration(str(name), spec, "pep440", "py", "override",
                                         f"{name} = {spec!r}"))
    envs = _table(data, "tool", "hatch", "envs")
    if isinstance(envs, dict):
        for env in envs.values():
            found.extend(_requirement_list(_table(env, "dependencies")))
            found.extend(_requirement_list(_table(env, "extra-dependencies")))
    found.extend(_requirement_list(_table(data, "tool", "rye", "dev-dependencies")))
    return found


def pipfile_declarations(data: dict) -> list[Declaration]:
    found: list[Declaration] = []
    for section, packages in data.items():
        if section in _PIPFILE_NON_PACKAGES or not isinstance(packages, dict):
            continue
        for name, value in packages.items():
            version = value if isinstance(value, str) else _table(value, "version")
            spec = version if isinstance(version, str) else ""
            shown = repr(spec) if spec else "{...}"
            found.append(Declaration(str(name), spec, "pep440", "py", "dependency",
                                     f"{name} = {shown}"))
    return found


# --- package.json -----------------------------------------------------------


def _npm_dependency(name: str, spec: str, kind: str) -> Declaration:
    """A `"name": "spec"` entry. A git, file or URL spec reads as no version."""
    text = f'"{name}": "{spec}"'
    if spec.startswith("npm:"):
        alias = npm_spec(spec)
        if alias.kind == "registry" and alias.name:
            return Declaration(alias.name, alias.version, "npm", "js", kind, text)
    return Declaration(name, spec, "npm", "js", kind, text)


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
                found.append(_npm_dependency(name, spec, "override"))
        elif isinstance(spec, dict):
            found.extend(_npm_overrides(spec, name))
    return found


def _launch_declarations(packages: list[Launched]) -> list[Declaration]:
    found: list[Declaration] = []
    for launched in packages:
        text = f"{launched.launcher} {launched.spec}"
        if launched.ecosystem == "js":
            parts = npm_spec(launched.spec)
            if parts.kind == "registry" and parts.name:
                found.append(Declaration(parts.name, parts.version, "npm", "js", "launch", text))
        else:
            parts = py_spec(launched.spec)
            if parts.kind != "local" and parts.name:
                version = "" if parts.kind == "vcs" else parts.version
                found.append(Declaration(parts.name, version, "pep440", "py", "launch", text))
    return found


def package_json_declarations(data: dict) -> list[Declaration]:
    found: list[Declaration] = []
    for section in _NPM_DEPENDENCY_SECTIONS:
        deps = data.get(section)
        if isinstance(deps, dict):
            for name, spec in deps.items():
                if isinstance(spec, str):
                    found.append(_npm_dependency(str(name), spec, "dependency"))
    found.extend(_npm_overrides(data.get("overrides")))
    for overrides in (data.get("resolutions"), _table(data, "pnpm", "overrides")):
        if isinstance(overrides, dict):
            for target, spec in overrides.items():
                if isinstance(spec, str) and not spec.startswith("$"):
                    found.append(_npm_dependency(_override_name(str(target)), spec, "override"))
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for line in scripts.values():
            if isinstance(line, str):
                found.extend(_launch_declarations(launched_packages(shell_tokens(line))))
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
        found.extend(_launch_declarations(launched_packages(argv)))
        head = basename(argv[0])
        if head and not starts_with_launcher(argv):
            # A program run by name: the installed package of that name, at an
            # unknown version (`"command": "ruflo"`). Its registry is unknown.
            found.append(Declaration(head, "", "npm", None, "launch", f"command {head}"))
    return found


# --- dispatch ----------------------------------------------------------------


def _load_json(text: str) -> object:
    try:
        return json.loads(text)
    except ValueError:
        from agent_audit_kit.scanners.ide_task_rce import _strip_jsonc

        return json.loads(_strip_jsonc(text))


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
            return mcp_config_declarations(_load_json(text))
    except (ValueError, tomllib.TOMLDecodeError, yaml.YAMLError, RecursionError):
        return []
    return []
