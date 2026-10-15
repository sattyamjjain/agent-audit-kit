"""Which packages a launch command fetches: npx, uvx and their relatives.

An MCP server entry, or a package.json script, names the package it runs as an
argument to a launcher. Reading that argument well takes the launcher's grammar,
and two scanners used to approximate it:

- The CVE pin table matched package names anywhere in a config's text, so a
  server *named* `n8n` read as the `n8n` package, a path such as
  `/opt/whatsapp-mcp/main.py` as `whatsapp-mcp`, and an image name as a version.
- AAK-SUPPLY-001 treated every argument that did not start with `-` as a
  package, so `--port 3000` reported the `3000`, the server URL in
  `npx -y mcp-remote@0.1.30 https://example.test/mcp` reported the URL,
  `uvx some-mcp-server==1.2.3` reported an exact pin (only `@` counted as a
  version), and `uvx --from x==1.0 x` reported both `x==1.0` and the command
  name. It also counted any text after `@` as a version, so `pkg@latest` and
  `pkg@^1` passed as pinned.

This module reads one invocation the way the launcher does: options first, with
the values of options that take one skipped, then the package. `npx -p a cmd` and
`uvx --from a cmd` name the package with an option, and the positional argument is
then a command, not a package. `uvx --with b` and repeated `-p` add packages. The
launcher also says which registry the package comes from (`npx` is npm, `uvx` is
PyPI), which a same-named package on the other registry needs.

`invocation_packages` reads the launcher at the head of an argv and nothing else,
which is what AAK-SUPPLY-001 judges with `pin_problem`. `launched_packages` scans
a whole token list for every launcher in it, so a launcher behind a shell
(`cmd /c npx -y pkg`, `bash -c "npx -y pkg"`) or nested in another server's
arguments (`supergateway --stdio "npx -y pkg"`) is read too:
a token no launcher consumed that holds whitespace is split as a shell line and
scanned, and a control operator (`&&`, `;`, `|`) ends the invocation it follows.
That is what the CVE pin table reads, where a missed launch is a missed
vulnerable version.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from agent_audit_kit.redaction import is_secret_option
from agent_audit_kit.scanners._versions import is_exact_version


@dataclass(frozen=True)
class Launched:
    """One package spec a launcher fetches."""

    ecosystem: str      # "js" (npm registry) or "py" (PyPI)
    spec: str           # as written: `pkg@1.2.3`, `pkg==1.2.3`, `github:o/r#sha`
    launcher: str       # `npx`, `uvx`, `uv tool run`, `pnpm dlx`, ...
    extra: bool = False  # an added package (`uvx --with`), not the launched one


@dataclass(frozen=True)
class PackageSpec:
    """A package spec split into its name and its version text."""

    kind: str       # "registry", "vcs" (git or a URL) or "local" (a path)
    name: str       # registry name; empty for vcs and local
    version: str    # version text as written; empty when none is stated
    dialect: str    # how to read `version`: "npm" or "pep440"


# How deep `launched_packages` follows a command line inside an argument.
_MAX_NESTING = 4
_CONTROL = frozenset({"&&", "||", ";", "|", "&", "(", ")", ";;", "|&", ">", ">>", "<", "<<"})

# Options that take a value, per launcher family. An option missing from these
# tables is read as a flag; `--opt=value` carries its value either way. A
# credential option (`--api-key`, `--token`) takes the next argument under any
# launcher, so a key is never read as the package and quoted into a finding.
_JS_VALUE_OPTIONS = frozenset({
    "-p", "--package", "-c", "--call", "--registry", "--cache", "--prefix",
    "--userconfig", "--node-options", "-w", "--workspace", "--loglevel",
    "--script-shell", "--shell", "--reporter", "--allow-build",
})
_JS_PACKAGE_OPTIONS = frozenset({"-p", "--package"})
_NO_OPTIONS: frozenset[str] = frozenset()
_PY_VALUE_OPTIONS = frozenset({
    "--from", "--with", "-w", "--with-editable", "--with-requirements",
    "--with-executables-from", "--python", "-p", "--index", "--default-index",
    "--index-url", "-i", "--extra-index-url", "--find-links", "-f", "--env-file",
    "--directory", "--project", "--config-file", "--cache-dir", "--refresh-package",
    "--upgrade-package", "-P", "--reinstall-package", "--no-binary-package",
    "--no-build-package", "--index-strategy", "--keyring-provider", "--resolution",
    "--prerelease", "--exclude-newer", "--exclude-newer-package", "--link-mode",
    "--color", "--build-constraints", "-b", "--constraints", "-c", "--overrides",
    "--python-preference", "--python-platform", "--torch-backend",
    "--allow-insecure-host", "--config-setting", "-C", "--spec", "--pip-args",
    "--suffix", "--group", "--extra", "--only-group", "--no-group", "--package",
})
# Options naming the package to launch (the positional is then a command), and
# options adding one more package to the environment.
_PY_PACKAGE_OPTIONS = frozenset({"--from", "--spec"})
_PY_EXTRA_OPTIONS = frozenset({"--with", "-w"})
# `uv` global options that may come before its subcommand (`uv --directory x run`).
_UV_GLOBAL_VALUE_OPTIONS = frozenset({
    "--directory", "--project", "--config-file", "--cache-dir", "--color",
    "--python", "-p", "--allow-insecure-host",
})

_COMMIT_SHA_RE = re.compile(r"[0-9a-fA-F]{7,40}")
_WINDOWS_DRIVE_RE = re.compile(r"[A-Za-z]:[\\/]")
_VCS_PREFIXES = (
    "git+", "git://", "git@", "ssh://", "http://", "https://", "github:", "gitlab:",
    "bitbucket:", "gist:",
)
_LOCAL_PREFIXES = ("/", "./", "../", "~", ".\\", "..\\", "file:", "link:", "workspace:", "portal:")
# A PEP 508 name, then an optional `[extras]`, then whatever follows.
_PY_NAME_RE = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?")


def basename(command: str) -> str:
    """`/usr/local/bin/npx` and `C:\\tools\\npx.cmd` are both `npx`."""
    name = re.split(r"[\\/]", command.strip())[-1]
    lowered = name.lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if lowered.endswith(suffix):
            return name[: -len(suffix)]
    return name


def shell_tokens(line: str) -> list[str]:
    """Split a shell command line into words and control operators.

    `#` is not a comment here: it opens the commit fragment of
    `github:org/repo#sha`. An unbalanced quote falls back to whitespace.
    """
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:
        return line.split()


def _option(token: str) -> tuple[str, str | None]:
    """(`--opt`, inline value or None) for `--opt=value`, `--opt` and `-o`."""
    if token.startswith("--") and "=" in token:
        name, _, value = token.partition("=")
        return name, value
    return token, None


def _parse(
    tokens: list[str],
    start: int,
    launcher: str,
    ecosystem: str,
    value_options: frozenset[str],
    package_options: frozenset[str],
    extra_options: frozenset[str],
    command_only: bool = False,
) -> tuple[list[Launched], int]:
    """Read one invocation from `tokens[start:]`.

    Returns the packages it fetches and the index just past the positional
    argument (the package, or the command when an option named the package), so
    the caller resumes scanning in that command's own arguments.
    """
    found: list[Launched] = []
    named_by_option = False
    i, n = start, len(tokens)
    end_of_options = False
    while i < n:
        token = tokens[i]
        if token in _CONTROL:
            return found, i
        if not end_of_options and token == "--":
            end_of_options = True
            i += 1
            continue
        if not end_of_options and token.startswith("-") and token != "-":
            name, inline = _option(token)
            value: str | None = inline
            if inline is None and (name in value_options or is_secret_option(name)):
                value = tokens[i + 1] if i + 1 < n else None
                i += 1
            i += 1
            if value is None:
                continue
            if name in package_options:
                found.append(Launched(ecosystem, value, launcher))
                named_by_option = True
            elif name in extra_options:
                found.append(Launched(ecosystem, value, launcher, extra=True))
            continue
        if not (command_only or named_by_option):
            found.append(Launched(ecosystem, token, launcher))
        return found, i + 1
    return found, i


def _uv_subcommand(tokens: list[str], start: int) -> tuple[str, int] | None:
    """(`run` or `tool run`, index after it) for `uv [globals] run|tool run`."""
    i, n = start, len(tokens)
    while i < n and tokens[i].startswith("-"):
        name, inline = _option(tokens[i])
        i += 2 if inline is None and name in _UV_GLOBAL_VALUE_OPTIONS else 1
    if i < n and tokens[i] == "run":
        return "uv run", i + 1
    if i + 1 < n and tokens[i] == "tool" and tokens[i + 1] == "run":
        return "uv tool run", i + 2
    return None


def _launch_at(tokens: list[str], i: int) -> tuple[list[Launched], int] | None:
    """Parse a launcher that starts at `tokens[i]`, or None when none does."""
    word = basename(tokens[i]).lower()
    nxt = tokens[i + 1].lower() if i + 1 < len(tokens) else ""
    js = (_JS_VALUE_OPTIONS, _JS_PACKAGE_OPTIONS, _NO_OPTIONS)
    py = (_PY_VALUE_OPTIONS, _PY_PACKAGE_OPTIONS, _PY_EXTRA_OPTIONS)
    if word in ("npx", "bunx", "pnpx"):
        return _parse(tokens, i + 1, word, "js", *js)
    if (word, nxt) in (("npm", "exec"), ("npm", "x"), ("pnpm", "dlx"), ("yarn", "dlx"), ("bun", "x")):
        return _parse(tokens, i + 2, f"{word} {nxt}", "js", *js)
    if word == "uvx":
        return _parse(tokens, i + 1, "uvx", "py", *py)
    if (word, nxt) == ("pipx", "run"):
        return _parse(tokens, i + 2, "pipx run", "py", *py)
    if word == "uv":
        sub = _uv_subcommand(tokens, i + 1)
        if sub is None:
            return None
        launcher, start = sub
        if launcher == "uv run":
            # `uv run` runs a command or script from the project; only the
            # packages `--with` adds are fetched by this invocation.
            return _parse(tokens, start, launcher, "py", _PY_VALUE_OPTIONS,
                          _NO_OPTIONS, _PY_EXTRA_OPTIONS, command_only=True)
        return _parse(tokens, start, launcher, "py", *py)
    return None


def starts_with_launcher(tokens: list[str]) -> bool:
    """True when `tokens[0]` begins a launcher invocation this module reads."""
    return bool(tokens) and _launch_at(tokens, 0) is not None


def invocation_packages(tokens: list[str]) -> list[Launched]:
    """The packages the launcher at `tokens[0]` fetches, read as argv.

    No token is split as a shell line and no nested launcher is followed: this
    is exactly what the launcher itself receives when the MCP client spawns it.
    """
    if not tokens:
        return []
    hit = _launch_at(tokens, 0)
    return hit[0] if hit else []


def launched_packages(tokens: list[str], _depth: int = 0) -> list[Launched]:
    """Every package any launcher in `tokens` fetches, in order.

    A token a launcher consumes (an option value, the package) is read as one
    argv element, spaces and all: `uvx --from "name @ git+https://..." cmd`
    names one package. Any other token that holds whitespace is a command line
    (`bash -c "..."`, `supergateway --stdio "..."`) and is split and scanned in
    turn, to a fixed depth.
    """
    found: list[Launched] = []
    i = 0
    while i < len(tokens):
        hit = _launch_at(tokens, i)
        if hit is not None:
            packages, resume = hit
            found.extend(packages)
            i = max(resume, i + 1)
            continue
        token = tokens[i]
        if _depth < _MAX_NESTING and any(c.isspace() for c in token):
            found.extend(launched_packages(shell_tokens(token), _depth + 1))
        i += 1
    return found


def _is_local(spec: str) -> bool:
    return spec.startswith(_LOCAL_PREFIXES) or bool(_WINDOWS_DRIVE_RE.match(spec))


def npm_spec(spec: str) -> PackageSpec:
    """Split an npm package spec: `@scope/name@range`, `name@tag`, `npm:x@1`."""
    text = spec.strip()
    if text.startswith("npm:"):
        text = text[4:]
    if _is_local(text):
        return PackageSpec("local", "", "", "npm")
    if text.startswith(_VCS_PREFIXES):
        return PackageSpec("vcs", "", text, "npm")
    if text.startswith("@"):
        slash = text.find("/")
        if slash == -1:
            return PackageSpec("registry", text, "", "npm")
        at = text.find("@", slash)
    else:
        at = text.find("@")
        head = text if at == -1 else text[:at]
        if "/" in head:
            # `owner/repo` and `owner/repo#ref` are GitHub shorthands.
            return PackageSpec("vcs", "", text, "npm")
    if at == -1:
        return PackageSpec("registry", text, "", "npm")
    return PackageSpec("registry", text[:at], text[at + 1:], "npm")


def py_spec(spec: str) -> PackageSpec:
    """Split a PyPI spec: `name[extra]==1.2`, `name@1.2` (uv), `name @ git+...`."""
    text = spec.strip()
    if _is_local(text):
        return PackageSpec("local", "", "", "pep440")
    if text.startswith(_VCS_PREFIXES):
        return PackageSpec("vcs", "", text, "pep440")
    m = _PY_NAME_RE.match(text)
    if not m:
        return PackageSpec("registry", "", "", "pep440")
    name, rest = m.group(1), text[m.end():].strip()
    if rest.startswith("["):
        # Extras written after a space: `litellm [proxy]==1.0`.
        close = rest.find("]")
        rest = rest[close + 1:].strip() if close != -1 else rest
    if rest.startswith("@"):
        target = rest[1:].strip()
        if target.startswith(_VCS_PREFIXES) or _is_local(target):
            return PackageSpec("vcs", name, target, "pep440")
        # uv's `name@1.2.3` and `name@latest`.
        if target and target[0].isdigit():
            return PackageSpec("registry", name, "==" + target, "pep440")
        return PackageSpec("registry", name, target, "pep440")
    rest = rest.split(";", 1)[0].strip()
    if rest.startswith("(") and rest.endswith(")"):
        rest = rest[1:-1].strip()
    return PackageSpec("registry", name, rest, "pep440")


def _vcs_pinned(target: str, dialect: str) -> bool:
    """A git reference is pinned when its ref is a full or short commit SHA.

    npm puts the ref in the fragment (`github:org/repo#<sha>`, `#commit=<sha>`);
    pip puts it after the last `@` of the URL path and keeps the fragment for
    `#egg=` (`git+https://host/repo.git@<sha>#egg=name`).
    """
    ref = ""
    if dialect == "npm":
        if "#" in target:
            ref = target.rsplit("#", 1)[1].split("&", 1)[0]
            if ref.startswith("commit="):
                ref = ref[len("commit="):]
    else:
        path = target.split("#", 1)[0].split("://", 1)[-1]
        if "@" in path:
            ref = path.rsplit("@", 1)[1]
    return bool(_COMMIT_SHA_RE.fullmatch(ref))


def _unpinned_label(version: str) -> str:
    if version in ("*", "x", "X") or version[:1] in "^~<>=!" or version[:1].isdigit():
        return f"version range `{version}`"
    return f"floating tag `{version}`"


def pin_problem(launched: Launched) -> str | None:
    """Why `launched` is not pinned to one release, or None when it is.

    Pinned means an exact version (`pkg@1.2.3`, `pkg==1.2.3`, uv's `pkg@1.2.3`)
    or a commit (`github:org/repo#<sha>`, `git+https://...@<sha>`). A dist-tag
    (`@latest`), a range (`@^1`, `@~1.2`, `>=1`, `@1.x`), a wildcard and no
    version at all are not. A local path is not a fetch and is not judged.
    """
    parts = npm_spec(launched.spec) if launched.ecosystem == "js" else py_spec(launched.spec)
    if parts.kind == "local":
        return None
    if parts.kind == "vcs":
        if _vcs_pinned(parts.version, parts.dialect):
            return None
        return "a git or URL reference without a commit"
    version = parts.version.strip()
    if not version:
        return "no version pin"
    if parts.dialect == "npm":
        exact = version[1:] if version.startswith("=") else version
        return None if is_exact_version(exact) else _unpinned_label(version)
    clauses = [c.strip() for c in version.split(",") if c.strip()]
    if len(clauses) == 1:
        for op in ("===", "=="):
            target = clauses[0][len(op):].strip()
            if clauses[0].startswith(op) and "*" not in target and target[:1].isdigit():
                return None
    return _unpinned_label(version)


# The ` (<problem>)` that closes `launch_evidence`. `pin_problem`'s wording holds
# no parenthesis, and `[^()]` ends each attempt at the next one, so the search is
# linear. A version echoed into a problem can hold one; that evidence gets no
# subject, and its finding is kept.
_LAUNCH_PROBLEM_RE = re.compile(r" \([^()]*\)\Z")


def launch_evidence(server: str, spec: str, problem: str) -> str:
    """The evidence of a finding on one package spec a server launches.

    AAK-SUPPLY-001 and AAK-MCP-007 both report an unpinned launch, and
    `engine.run_scan` drops AAK-MCP-007 where AAK-SUPPLY-001 reports the same
    one. It recognises the launch by the `Server '<name>' arg: <spec>` head
    (`launch_subject`), so both rules build their evidence here, where the
    format and its reader cannot drift apart.
    """
    return f"Server '{server}' arg: {spec} ({problem})"


def launch_subject(evidence: str) -> str | None:
    """The `Server '<name>' arg: <spec>` head of `launch_evidence` output.

    None for evidence without the closing `(<problem>)`; the engine then keeps
    the finding, so an unexpected format costs a duplicate, never a finding.
    """
    m = _LAUNCH_PROBLEM_RE.search(evidence)
    return evidence[: m.start()] if m else None
