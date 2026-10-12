from __future__ import annotations

import json
import re
from pathlib import Path
from typing import AbstractSet, Any, Iterator
from urllib.parse import urlsplit

try:
    import tomllib
except ImportError:  # Python 3.9 and 3.10
    import tomli as tomllib  # type: ignore[no-redef,import-not-found]

from agent_audit_kit.models import Finding
from agent_audit_kit.rules.builtin import get_rule

# Interpolation of a caller-controlled variable into a command / shell string.
# Shared by hook_rce and ide_task_rce so there is exactly ONE definition of the
# "user input reaches a command string" signature (promoted here from
# hook_rce.py, which now imports it).
INTERPOLATION_RE = re.compile(
    r"""(?:["']\s*\+\s*|\$\{|%\{|{{\s*|\$\(|`)\s*(?:input|args|event|payload|user|argv|request)""",
    re.IGNORECASE,
)

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
    directory (`hook_rce`'s `.claude/hooks`, `mcp_config`'s `.windsurf`) may
    look above the root on purpose: `aak scan ~/.claude` depends on the root's
    own name. `tests/test_skip_dirs.py` fails on a scanner that tests a skip set
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


def find_line_number(raw: str, key: object) -> int | None:
    """Locate `key` in `raw`, tolerating a non-string key.

    Callers pass a value straight out of parsed JSON, and a malformed config can
    put an int or a list where the MCP schema says string. Substring search then
    raised TypeError and took the whole scanner down (issue #743). The value is
    only ever used to point a finding at a line, so coercing is the right
    trade: a wrong-typed key simply fails to match and the finding carries no
    line number, which is what a missing match already did.
    """
    if not isinstance(key, str):
        key = str(key)
    if not key:
        return None
    for i, line in enumerate(raw.splitlines(), 1):
        if key in line:
            return i
    return None


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


def url_host(value: str) -> str | None:
    """The host a client would connect to for `value`, or None when there is none.

    Read the way a WHATWG URL parser reads it (Node's ``new URL``, so Claude
    Code), not the way ``urlsplit`` does, because the two disagree on exactly the
    input an attacker writes. For an http(s) URL WHATWG treats ``\\`` as ``/``:
    ``https://evil.example\\@api.anthropic.com`` connects to ``evil.example``,
    while ``urlsplit`` reads its host as ``api.anthropic.com``, and it reads
    ``https://evil.example\\.anthropic.com`` as a subdomain of anthropic.com. An
    allowlist built on raw ``urlsplit`` waves both through. So, before parsing:
    leading and trailing C0 controls and spaces are stripped and tab, CR and LF
    removed, as WHATWG does (``urlsplit`` does so only on newer Python
    releases); ``\\`` becomes ``/``; and a value with no ``://`` is read as a
    bare authority (``api.anthropic.com/v1``, ``localhost:8080``).

    The host comes back lower-cased without a trailing dot, and only when it is a
    plain DNS name or IPv4 address: anything else (a space, ``%``, non-ASCII, an
    IPv6 literal, a malformed authority) returns None, so a caller comparing the
    host against an allowlist fails closed on it.
    """
    url = value.strip(_C0_CONTROL_OR_SPACE)
    for ch in "\t\r\n":
        url = url.replace(ch, "")
    url = url.replace("\\", "/")
    if "://" not in url:
        url = "//" + url
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".")
    if not host or not set(host) <= _HOSTNAME_CHARS:
        return None
    return host


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


#: The keys an MCP client config keeps its server map under. `mcpServers` is the
#: key of Claude Code, Cursor, Windsurf, Gemini CLI and most other clients; VS
#: Code's `.vscode/mcp.json` keeps the same map under `servers`.
MCP_SERVER_KEYS: tuple[str, ...] = ("mcpServers", "servers")


def mcp_server_maps(data: object) -> list[tuple[str, dict[str, Any]]]:
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
    """
    if not isinstance(data, dict):
        return []
    return [(key, data[key]) for key in MCP_SERVER_KEYS if isinstance(data.get(key), dict)]


def iter_mcp_servers(data: object) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(name, server)`` for every server object in a config's server maps.

    An entry that is not a JSON object is skipped, as every reader here did.
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


def _js_skip_regex(text: str, start: int) -> int:
    """Index just past the regex literal (and its flags) opened at `start`.

    `[...]` is a class, inside which `/` does not close. A newline before the
    closing `/` means the slash was a division after all: stop there, having
    blanked nothing, and let the caller carry on.
    """
    n = len(text)
    i = start + 1
    in_class = False
    while True:
        m = _JS_REGEX_SPECIAL_RE.search(text, i)
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


def _pyproject_declares_mcp(text: str) -> bool:
    try:
        data = tomllib.loads(text)
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
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def declares_mcp_sdk(project_root: Path) -> tuple[bool, list[str]]:
    """Whether a manifest at the project root declares an MCP SDK, and which.

    The gate in front of AAK-MCP-STATELESS-001..004 and the source half of
    AAK-MCP-SAMPLING-001. Its copies took pyproject.toml only as the exact
    quoted string `"mcp"`, so `"mcp[cli]>=1.2.0"`, the way most servers declare
    it, and Poetry's `mcp = "^1.2.0"` never opened it, and the requirements
    reader cut a line at its first `=`, so `mcp~=1.2.0` came out as `mcp~`.
    Those rules never ran for a typical Python server.

    pyproject.toml is parsed and read through its dependency tables (see
    `_pyproject_dependency_names`), and each requirement's name is taken the
    PEP 508 way and compared PEP 503-normalised, so case, extras, any version
    operator, environment markers and `name @ url` all work. The old quoted
    string test still runs too, so nothing it accepted is lost. package.json,
    Maven and Gradle builds and Cargo.toml are read as before.

    `mcp_sdk_hardening` keeps a copy of the old gate for AAK-ANTHROPIC-SDK-001.

    Returns:
        ``(declared, manifests)``: manifests are paths relative to the root.
    """
    manifests: list[str] = []

    pyproject = project_root / "pyproject.toml"
    if pyproject.is_file():
        text = _read_text(pyproject)
        if text is not None and _pyproject_declares_mcp(text):
            manifests.append("pyproject.toml")

    for req in sorted(project_root.glob("requirements*.txt")):
        text = _read_text(req)
        if text is not None and _requirements_declare_mcp(text):
            manifests.append(str(req.relative_to(project_root)))

    pkg = project_root / "package.json"
    if pkg.is_file():
        text = _read_text(pkg)
        try:
            data = json.loads(text) if text is not None else {}
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
