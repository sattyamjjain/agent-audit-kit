from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from agent_audit_kit.models import Finding
from agent_audit_kit.redaction import redact_evidence
from agent_audit_kit.scanners._helpers import (
    _is_loopback_host,
    find_line_number,
    hook_command,
    host_ip,
    in_skip_dir,
    is_loopback_url,
    iter_hook_handlers,
    loads_json,
    make_finding,
    read_text_capped,
    url_readings,
)
from agent_audit_kit.scanners._launchers import shell_words
from agent_audit_kit.scanners.skill_composition import _parse_frontmatter

# Network-capable commands
# The inline-code arms used to read `\s+.*` after the flag, which split each
# whitespace run between `\s+` and `.*` every possible way and let every
# `python -c` / `node -e` on a line rescan to its end: a `python -c` and 64,000
# blanks took 9.9 seconds, and the time grew with the square. Now `\s+`
# takes the whole run and the code is read from its first non-space character,
# and the read stops at the next `python -c` / `node -e`, which reaches the same
# `import requests` / `fetch(` itself. A command matches exactly when it did.
NETWORK_COMMANDS = re.compile(
    r"\b(curl|wget|nc|ncat|ssh|scp|rsync|ftp)\b|"
    r"python\s+-c\s+(?:\S(?:(?!python\s+-c\s).)*?)?import\s+requests|"
    r"node\s+-e\s+(?:\S(?:(?!node\s+-e\s).)*?)?fetch\(",
    re.IGNORECASE,
)

# Credential environment variables. HOME and PATH were in this list, so
# `cd $HOME/...` or extending `$PATH` read as credential theft: all 9 such
# AAK-HOOK-002 hits on 159 real settings files were false, two of them a local
# `$path` that the case-insensitive match took for PATH (hook-precision,
# 2026-10-12). The same four names are what an `http` hook may not send.
_CREDENTIAL_VAR_NAMES = (
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID",
)
CREDENTIAL_VARS = re.compile(
    r"\$(" + "|".join(_CREDENTIAL_VAR_NAMES) + r")|"
    r"(env\s*\|\s*curl|printenv\s*\|\s*nc|echo\s+\$\w+\s*\|\s*base64)",
    re.IGNORECASE,
)

# A write target outside the project (AAK-HOOK-003), read at the start of a word.
_OUTSIDE_TARGET = re.compile(r"(?:/tmp|~|/etc|/var|/usr|/home)(?:/|$)")

# Allowed formatting/linting binaries
FORMATTING_ALLOWLIST = frozenset({
    "prettier", "eslint", "black", "ruff", "mypy", "tsc",
    "cargo fmt", "cargo-fmt", "clippy", "rustfmt", "gofmt",
    "isort", "autopep8", "yapf", "biome", "dprint",
})

# Sensitive lifecycle events
SENSITIVE_EVENTS = frozenset({
    "PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit",
})

# Base64 operations
BASE64_PATTERNS = re.compile(
    r"\b(base64|btoa|atob|b64encode|b64decode)\b", re.IGNORECASE
)

# Privilege escalation
PRIVILEGE_PATTERNS = re.compile(
    r"\b(sudo|doas|pkexec)\b|chmod\s+\+x",
)

# Obfuscation indicators
# A nested `sh -c` is read from the first non-space character after the outer
# one's whitespace. `\s+.*` split that run between `\s+` and `.*` every possible
# way, so a long run with no second `sh -c` grew with the square.
OBFUSCATION_PATTERNS = re.compile(
    r"(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|sh\s+-c\s+(?:\S.*?)?sh\s+-c)",
)

# An embedded encoded payload (AAK-HOOK-008): 64 or more base64 characters in
# one unbroken run. A readable command never holds one, because paths and words
# break on `/`, `.`, `-`, `_` and spaces. `_is_encoded_blob` also requires upper
# case, lower case and digits, so a hex digest (an image's `@sha256:` pin) does
# not count.
_ENCODED_RUN = re.compile(r"[A-Za-z0-9+=]{64,}")

# A project source file (AAK-HOOK-009): lower-case extensions only.
_SOURCE_FILE = re.compile(r"\.(py|js|ts|go|rs|java|rb|c|cpp|h)\b")

SETTINGS_FILES = [
    ".claude/settings.json",
    ".claude/settings.local.json",
]
# A settings file over this many characters is not read.
_MAX_HOOK_FILE_CHARS = 1_000_000
# A plugin `hooks/hooks.json` or a `SKILL.md` over this many bytes is not read.
# It is sized before it is read, as agentic_skills and skill_composition size a
# SKILL.md, so a huge file is never loaded only to be thrown away.
_MAX_PLUGIN_OR_SKILL_BYTES = 512_000


def _find_settings(project_root: Path, include_user_config: bool = False) -> list[Path]:
    found: list[Path] = []
    for name in SETTINGS_FILES:
        p = project_root / name
        if p.is_file():
            found.append(p)
    if include_user_config:
        user_settings = Path.home() / ".claude" / "settings.json"
        if user_settings.is_file():
            found.append(user_settings)
    return found


def _is_plugin_root(root: Path, project_root: Path) -> bool:
    """Whether ``root`` is a Claude Code plugin's root directory.

    Claude Code loads a plugin's hooks from ``hooks/hooks.json`` under the
    plugin root (plugins reference, "Standard layout"). The manifest,
    ``.claude-plugin/plugin.json``, is optional: without one a marketplace entry
    serves as the manifest, and that marketplace keeps its
    ``.claude-plugin/marketplace.json`` in a directory above. So a root counts
    when it holds a ``.claude-plugin`` directory itself, or when a directory
    between it and the scanned root holds a marketplace manifest. Of 80 public
    repositories with a root ``hooks/hooks.json`` that mentions PreToolUse, 76
    had ``.claude-plugin/`` beside it, and two of the other four were Codex
    plugins (``.codex-plugin/``), which use the same file name; of 77 nested
    ``plugins/<name>/hooks/hooks.json``, 67 had their own manifest and 9 sat
    under a marketplace (code search, 2026-10-17). GitHub Copilot keeps hook
    files in ``.github/hooks/``, which has neither.

    When the scanned directory is itself a plugin's ``hooks/``, the root is
    the one directory above it; its manifest is looked for, as other checks
    classify a file by an enclosing directory, but a marketplace is searched
    for only inside the scanned tree, so the walk never leaves it.
    """
    if (root / ".claude-plugin").is_dir():
        return True
    if not root.is_relative_to(project_root):
        return False
    for directory in (root, *root.parents):
        if (directory / ".claude-plugin" / "marketplace.json").is_file():
            return True
        if directory == project_root:
            break
    return False


def _plugin_and_skill_files(project_root: Path) -> tuple[list[Path], list[Path]]:
    """Every ``hooks/hooks.json`` at a Claude Code plugin's root, and every
    ``SKILL.md``, outside vendored trees.

    Both come from one walk of the tree. A name-specific ``rglob`` still lists
    every directory, and on a large tree that listing is most of a scanner's
    time: over 51 checkouts of this repository, two took 6.8 s and one 3.6 s.

    The directory names are read on the resolved directory: `aak scan .` passes
    the root unresolved, and inside a plugin's `hooks/` the walk yields
    `hooks.json`, whose parent's name is "". The file itself is not resolved, so
    a `hooks.json` that is a symlink is still the plugin's.
    """
    plugins: list[Path] = []
    skills: list[Path] = []
    resolved_root = project_root.resolve()
    for path in project_root.rglob("*"):
        if path.name == "SKILL.md":
            found = skills
        elif path.name == "hooks.json":
            directory = path.parent.resolve()
            if directory.name != "hooks" or not _is_plugin_root(directory.parent, resolved_root):
                continue
            found = plugins
        else:
            continue
        if path.is_file() and not in_skip_dir(path, project_root):
            found.append(path)
    return sorted(plugins), sorted(skills)


def _relative(path: Path, project_root: Path) -> str:
    return str(path.relative_to(project_root)) if path.is_relative_to(project_root) else str(path)


def _hook_sources(
    project_root: Path, include_user_config: bool, scanned_files: set[str]
) -> Iterator[tuple[str, str, Any]]:
    """``(relative path, text, hooks block)`` for every file whose hooks AAK reads.

    The two settings files (and the user's, when asked for), a plugin's
    ``hooks/hooks.json`` and a skill's frontmatter. Claude Code documents one
    shape for all of them: an event maps to matcher groups whose ``hooks``
    hold the handlers (hooks reference, "Hook locations" and "Hooks in skills
    and agents"), so every source goes through ``iter_hook_handlers``. The
    settings files were the only source until 2026-10-17, so a plugin, the
    way hooks are shared, could ship `curl ... | sh` on every tool call unread.
    """
    for path in _find_settings(project_root, include_user_config):
        try:
            raw_text = read_text_capped(path, _MAX_HOOK_FILE_CHARS, errors="replace")
            if len(raw_text) > _MAX_HOOK_FILE_CHARS:
                continue
            data = loads_json(raw_text, path)
        except (json.JSONDecodeError, OSError):
            continue
        rel_path = _relative(path, project_root)
        scanned_files.add(rel_path)
        if not isinstance(data, dict):
            continue
        yield rel_path, raw_text, data.get("hooks", {})
    plugin_files, skill_files = _plugin_and_skill_files(project_root)
    for path in plugin_files:
        # `loads_json` refuses a file nested past `JSON_MAX_NESTING`, and the
        # refusal is reported against it: 20,000 nested `[` in 40 KB used to
        # take the whole scanner down, and the settings findings with it.
        try:
            if path.stat().st_size > _MAX_PLUGIN_OR_SKILL_BYTES:
                continue
            raw_text = read_text_capped(path, _MAX_PLUGIN_OR_SKILL_BYTES, errors="replace")
            data = loads_json(raw_text, path)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            continue
        rel_path = _relative(path, project_root)
        scanned_files.add(rel_path)
        if isinstance(data, dict):
            yield rel_path, raw_text, data.get("hooks", {})
    for path in skill_files:
        try:
            if path.stat().st_size > _MAX_PLUGIN_OR_SKILL_BYTES:
                continue
            raw_text = read_text_capped(path, _MAX_PLUGIN_OR_SKILL_BYTES, errors="replace")
        except OSError:
            continue
        rel_path = _relative(path, project_root)
        scanned_files.add(rel_path)
        yield rel_path, raw_text, _parse_frontmatter(raw_text, path).get("hooks", {})


_find_line_number = find_line_number
_make_finding = make_finding


# ---------------------------------------------------------------------------
# `http` hooks (AAK-HOOK-001 and -002). An `http` handler runs no command: it
# POSTs the event's JSON input to its `url`, with any `headers`, whose values
# may interpolate `$VAR_NAME` or `${VAR_NAME}`, and Claude Code resolves only
# the variables `allowedEnvVars` lists; a reference to any other becomes an
# empty string (hooks reference, "HTTP hook fields"). Every `http` hook sends
# its event off the process, so that alone is not reported. AAK-HOOK-001 reports
# where the event goes in a way no https endpoint on a DNS name would: in
# cleartext to another machine, to a bare IP address, or with a credential in
# the URL. AAK-HOOK-002 reports a header that sends one of the provider keys
# the command arm reads. On the 109 `http` handlers in 1,347 public settings
# and plugin hook files (code search, 2026-10-17), every token sent was the
# endpoint's own (`$VIBEMAN_HOOK_SECRET`, `$SHIELD_TOKEN`, a bearer token for the
# service the hook reports to), and every cleartext URL was 127.0.0.1 or
# localhost, as in the reference's own example.
# ---------------------------------------------------------------------------

_HEADER_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
def _http_url_risks(url: str) -> list[str]:
    """Why AAK-HOOK-001 reports an `http` hook's URL; empty when it does not.

    The URL is judged on each of `url_readings`, the way Node (Claude Code) and
    the urlsplit, httpx and curl family read it, so a backslash cannot hide
    either host: `http://localhost\\@evil.example/` is cleartext to
    evil.example for curl, and `https://hooks.example.com\\@203.0.113.7/` is a
    bare IP for httpx. The loopback exemption holds only when every reading is
    local (`is_loopback_url`), and an address is read as clients read it, so
    `https://0xcb.0.113.7/` is 203.0.113.7 and `http://127.1/` is loopback. A
    credential is anything evidence redaction masks in the URL: a password or
    token in the userinfo, a credential-named query parameter, or a known token
    format.
    """
    readings = url_readings(url)
    risks: list[str] = []
    if any(reading.scheme in ("http", "ws") for reading in readings) and not is_loopback_url(url):
        risks.append("plain http to another machine")
    if any(host_ip(reading.host) is not None and not _is_loopback_host(reading.host)
           for reading in readings):
        risks.append("an IP address, not a name")
    if redact_evidence(url) != url:
        risks.append("a credential in the URL")
    return risks


def _http_sent_credentials(handler: dict[str, Any]) -> list[tuple[str, str]]:
    """``(header, variable)`` for each provider key a header sends (AAK-HOOK-002)."""
    allowed = handler.get("allowedEnvVars")
    headers = handler.get("headers")
    if not isinstance(allowed, list) or not isinstance(headers, dict):
        return []
    listed = {name for name in allowed if isinstance(name, str)}
    sent: list[tuple[str, str]] = []
    for header, value in headers.items():
        if not isinstance(value, str):
            continue
        for match in _HEADER_VAR.finditer(value):
            name = match.group(1) or match.group(2)
            if name in listed and name.upper() in _CREDENTIAL_VAR_NAMES:
                sent.append((str(header), name))
    return sent


def _value_line(raw_text: str, value: str, key: str) -> int | None:
    """The line of a string value from a parsed file, found as the file writes it.

    `find_line_number` looks for the decoded value, which JSON (and a quoted YAML
    scalar) escapes: `\\` is written `\\\\`, and json.dumps writes a non-ASCII
    character as `\\uXXXX`, so `http://localhost\\@evil.example/` had no line.
    The escaped spellings are tried next, then the first line naming the key.
    """
    for spelling in (value, json.dumps(value, ensure_ascii=False)[1:-1], json.dumps(value)[1:-1]):
        line = find_line_number(raw_text, spelling)
        if line is not None:
            return line
    return find_line_number(raw_text, f'"{key}"') or find_line_number(raw_text, f"{key}:")


def _http_findings(rel_path: str, raw_text: str, event_name: str, handler: dict[str, Any]) -> list[Finding]:
    url = handler.get("url")
    if not isinstance(url, str) or not url:
        return []
    findings: list[Finding] = []
    risks = _http_url_risks(url)
    if risks:
        findings.append(_make_finding(
            "AAK-HOOK-001", rel_path,
            f"Event '{event_name}': http hook posts the event to {url} ({'; '.join(risks)})",
            _value_line(raw_text, url, "url"),
        ))
    sent = _http_sent_credentials(handler)
    if sent:
        named = ", ".join(f"${name} in {header!r}" for header, name in sent)
        findings.append(_make_finding(
            "AAK-HOOK-002", rel_path,
            f"Event '{event_name}': http hook sends {named} to {url}",
            _find_line_number(raw_text, sent[0][0]) or _value_line(raw_text, url, "url"),
        ))
    return findings


def _is_formatting_tool(command: str) -> bool:
    cmd_lower = command.strip().lower()
    return any(tool in cmd_lower for tool in FORMATTING_ALLOWLIST)


def _count_hooks(hooks_data: Any) -> int:
    """Number of hook handlers in a ``hooks`` block, whatever their type.

    Counts handlers, not entries: a matcher group holding twelve hooks is twelve
    definitions to audit, which is what AAK-HOOK-007 is about. The old count
    took the length of each event's list, so that group counted once.
    """
    return sum(1 for _ in iter_hook_handlers(hooks_data))


# ---------------------------------------------------------------------------
# Reading a hook's command line as shell commands (AAK-HOOK-003 and -009).
#
# Both rules searched the whole line for text: 003 for `/tmp/` or `~/`
# anywhere, 009 for a reader verb followed anywhere later by `.py`. On 159 real
# settings files (hook-precision, 2026-10-12) 4 of the 6 HOOK-003 hits and all
# 4 HOOK-009 hits were false: `cd /tmp/x`, a path in an echo, `grep '\.py$'`
# filtering a file list. The line is now read the way a shell reads it, one
# simple command at a time, and each command is judged by what it writes or
# reads.
# ---------------------------------------------------------------------------

_PUNCTUATION = frozenset("();<>|&\n")
# Words that run the command after them, with the options of each that take a
# value, so `sudo -u root cp x /etc/` reads as `cp`.
_PREFIX_COMMANDS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U"}),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "-C", "-S"}),
    "xargs": frozenset({"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a"}),
    "nice": frozenset({"-n"}),
    "command": frozenset(),
    "exec": frozenset(),
    "nohup": frozenset(),
    "time": frozenset(),
}
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
_MAX_SHELL_NESTING = 3
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")

# AAK-HOOK-003: programs that write each path operand, and programs whose last
# operand (or -t DIR) is the one written.
_WRITES_EVERY_OPERAND = frozenset({"mkdir", "touch", "tee", "chmod", "chown", "truncate"})
_WRITES_LAST_OPERAND = frozenset({"cp", "mv", "install", "ln"})
_IN_PLACE_CLUSTER = re.compile(r"-[npsuzrlaw0E]+i\S*")
# Download output options, and the short-option letters that take the path.
_DOWNLOAD_OUTPUT: dict[str, tuple[frozenset[str], str]] = {
    "curl": (frozenset({"-o", "--output"}), "o"),
    "wget": (frozenset({"-O", "--output-document", "-P", "--directory-prefix"}), "OP"),
}

# AAK-HOOK-009: readers whose every operand is a file, and readers whose first
# operand is a pattern or program unless an option supplied one. The values are
# (options that supply the pattern, other options that take a value).
_READS_EVERY_OPERAND = frozenset({"cat", "head", "tail", "less", "more"})
_READS_AFTER_PATTERN: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "grep": (
        frozenset({"-e", "-f", "--regexp", "--file"}),
        frozenset({"-m", "-A", "-B", "-C", "--max-count", "--context"}),
    ),
    "sed": (frozenset({"-e", "-f", "--expression", "--file"}), frozenset({"-l", "--line-length"})),
    "awk": (frozenset({"-f"}), frozenset({"-F", "-v"})),
}
_IN_PLACE_OPTIONS = {  # sed and perl -i: (options that supply the script, other value options)
    "sed": _READS_AFTER_PATTERN["sed"],
    "perl": (frozenset({"-e", "-E"}), frozenset({"-I", "-M", "-x"})),
}


def _shell_words(command: str) -> list[str]:
    """Words and operators of a command line, with quotes removed.

    An unbalanced quote makes shlex give up; whitespace words are the
    fallback, so a malformed hook is still read.
    """
    # A newline ends a command, so it is punctuation here; `#` starts a comment.
    return shell_words(command, punctuation="".join(sorted(_PUNCTUATION)), whitespace=" \t\r", commenters="#")


def _split_commands(words: list[str]) -> list[list[str]]:
    """Group words into simple commands at ; && || | & ( ) and newlines.

    A redirection operator (anything holding `<` or `>`) stays in its command,
    where the readers below look at it and at its target.
    """
    commands: list[list[str]] = []
    current: list[str] = []
    for word in words:
        if word and set(word) <= _PUNCTUATION and not {"<", ">"} & set(word):
            if current:
                commands.append(current)
            current = []
        else:
            current.append(word)
    if current:
        commands.append(current)
    return commands


def _verb_index(words: list[str]) -> int | None:
    """Index of the word naming the program a simple command runs, if any."""
    i = 0
    while i < len(words):
        word = words[i]
        name = word.rsplit("/", 1)[-1]
        if _ASSIGNMENT.match(word):
            i += 1
        elif name in _PREFIX_COMMANDS:
            takes_value = _PREFIX_COMMANDS[name]
            i += 1
            while i < len(words) and words[i].startswith("-"):
                i += 2 if words[i] in takes_value else 1
        else:
            return i
    return None


def _program(words: list[str]) -> tuple[str, list[str]] | None:
    """The program a simple command runs, and its arguments without redirections."""
    index = _verb_index(words)
    if index is None:
        return None
    args: list[str] = []
    skip = False
    for word in words[index + 1:]:
        if skip:
            skip = False
        elif word and set(word) <= _PUNCTUATION:
            skip = True  # a redirection; its target is not an argument
        else:
            args.append(word)
    return words[index].rsplit("/", 1)[-1], args


def _inline_script(words: list[str]) -> str | None:
    """The command string a shell runs with `-c`, or what `eval` runs."""
    program = _program(words)
    if program is None:
        return None
    name, args = program
    if name == "eval":
        return " ".join(args)
    if name not in _SHELLS:
        return None
    for i, arg in enumerate(args[:-1]):
        if arg.startswith("-") and not arg.startswith("--") and "c" in arg:
            return args[i + 1]
    return None


def _simple_commands(command: str, depth: int = 0) -> list[list[str]]:
    """Each simple command in a hook command line, as its words.

    The script after `sh -c` or `bash -c`, and what `eval` runs, are read as
    commands of their own, three levels deep, so a write hidden in
    `bash -c "echo x >> ~/.zshrc"` is still seen.
    """
    commands = _split_commands(_shell_words(command))
    if depth < _MAX_SHELL_NESTING:
        for words in list(commands):
            script = _inline_script(words)
            if script:
                commands.extend(_simple_commands(script, depth + 1))
    return commands


def _file_operands(args: list[str], pattern_options: frozenset[str],
                   value_options: frozenset[str]) -> list[str]:
    """Operands of grep, sed, awk or perl that name files.

    The first operand is the pattern or program unless an option such as `-e`
    or `-f` supplied it, and an option's value is never a file.
    """
    operands: list[str] = []
    pattern_given = False
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg.startswith("-") and arg != "-":
            if arg.split("=", 1)[0] in pattern_options:
                pattern_given = True
            skip = arg in pattern_options or arg in value_options
        else:
            operands.append(arg)
    return operands if pattern_given else operands[1:]


def _destination_outside(name: str, args: list[str]) -> bool:
    """cp, mv, install, ln: the -t directory, else the last operand, is written."""
    for i, arg in enumerate(args):
        if arg in ("-t", "--target-directory") and i + 1 < len(args):
            return bool(_OUTSIDE_TARGET.match(args[i + 1]))
        if arg.startswith("--target-directory="):
            return bool(_OUTSIDE_TARGET.match(arg.split("=", 1)[1]))
    operands = [a for a in args if not a.startswith("-")]
    if name == "install" and "-d" in args:  # install -d creates every operand
        return any(_OUTSIDE_TARGET.match(a) for a in operands)
    return len(operands) >= 2 and bool(_OUTSIDE_TARGET.match(operands[-1]))


def _edits_in_place_outside(name: str, args: list[str]) -> bool:
    """sed -i or perl -i on a file outside the project; the script is not a file."""
    in_place = any(
        a.startswith("-i") or a.startswith("--in-place") or _IN_PLACE_CLUSTER.fullmatch(a)
        for a in args
    )
    if not in_place:
        return False
    files = _file_operands(args, *_IN_PLACE_OPTIONS[name])
    return any(_OUTSIDE_TARGET.match(f) for f in files)


def _downloads_outside(name: str, args: list[str]) -> bool:
    """curl -o or wget -O / -P naming a path outside the project."""
    options, letters = _DOWNLOAD_OUTPUT[name]
    for i, arg in enumerate(args):
        following = args[i + 1] if i + 1 < len(args) else ""
        if arg in options:
            value = following
        elif arg.startswith("--") and arg.split("=", 1)[0] in options:
            value = arg.split("=", 1)[-1]
        elif arg.startswith("-") and not arg.startswith("--"):
            at = next((k for k, ch in enumerate(arg) if k and ch in letters), None)
            if at is None:
                continue
            value = arg[at + 1:] or following  # -fsSLo PATH, or attached: -o/tmp/x
        else:
            continue
        if _OUTSIDE_TARGET.match(value):
            return True
    return False


def _tar_writes_outside(args: list[str]) -> bool:
    """tar extracting into, or creating an archive in, a path outside the project."""
    for i, arg in enumerate(args):
        if arg in ("-C", "--directory") and i + 1 < len(args) and _OUTSIDE_TARGET.match(args[i + 1]):
            return True
        if arg.startswith("--directory=") and _OUTSIDE_TARGET.match(arg.split("=", 1)[1]):
            return True
    clusters = [a.lstrip("-") for a in args if a.startswith("-") and not a.startswith("--")]
    if args and not args[0].startswith("-"):
        clusters.append(args[0])  # old-style bundled mode: tar czf out.tgz src
    creates = "--create" in args or "--append" in args or any("c" in c or "r" in c for c in clusters)
    return creates and any(_OUTSIDE_TARGET.match(a) for a in args if not a.startswith("-"))


def _has_encoded_blob(command: str) -> bool:
    """Whether a command embeds a run of base64 text (AAK-HOOK-008)."""
    for match in _ENCODED_RUN.finditer(command):
        run = match.group(0)
        if any(c.isupper() for c in run) and any(c.islower() for c in run) and any(c.isdigit() for c in run):
            return True
    return False


def _writes_outside(words: list[str]) -> bool:
    """Whether one simple command writes a path outside the project (AAK-HOOK-003)."""
    for word, target in zip(words, words[1:]):
        if ">" in word and set(word) <= _PUNCTUATION and _OUTSIDE_TARGET.match(target):
            return True  # > /tmp/x, >> ~/.zshrc, &> /var/log/x
    program = _program(words)
    if program is None:
        return False
    name, args = program
    if name in _WRITES_EVERY_OPERAND:
        return any(_OUTSIDE_TARGET.match(a) for a in args if not a.startswith("-"))
    if name in _WRITES_LAST_OPERAND:
        return _destination_outside(name, args)
    if name in _IN_PLACE_OPTIONS:
        return _edits_in_place_outside(name, args)
    if name in _DOWNLOAD_OUTPUT:
        return _downloads_outside(name, args)
    if name == "dd":
        return any(a.startswith("of=") and bool(_OUTSIDE_TARGET.match(a[3:])) for a in args)
    if name == "tar":
        return _tar_writes_outside(args)
    return False


def _reads_source(words: list[str]) -> bool:
    """Whether one simple command reads a project source file (AAK-HOOK-009)."""
    for word, target in zip(words, words[1:]):
        if word == "<" and _SOURCE_FILE.search(target):
            return True
    program = _program(words)
    if program is None:
        return False
    name, args = program
    if name in _READS_EVERY_OPERAND:
        files = [a for a in args if not a.startswith("-")]
    elif name in _READS_AFTER_PATTERN:
        files = _file_operands(args, *_READS_AFTER_PATTERN[name])
    else:
        return False
    return any(_SOURCE_FILE.search(f) for f in files)


def scan(project_root: Path, include_user_config: bool = False) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned_files: set[str] = set()
    for rel_path, raw_text, hooks in _hook_sources(project_root, include_user_config, scanned_files):
        if hooks:
            findings.extend(_scan_hooks(rel_path, raw_text, hooks))
    return findings, scanned_files


def _scan_hooks(rel_path: str, raw_text: str, hooks: Any) -> list[Finding]:
    """Every AAK-HOOK finding for one file's ``hooks`` block."""
    findings: list[Finding] = []

    # AAK-HOOK-007: Excessive hook count
    hook_count = _count_hooks(hooks)
    if hook_count > 15:
        findings.append(_make_finding(
            "AAK-HOOK-007", rel_path,
            f"{hook_count} hooks defined (threshold: 15)",
            _find_line_number(raw_text, "hooks"),
        ))

    for event_name, handler in iter_hook_handlers(hooks):
        command = hook_command(handler)
        if command:
            findings.extend(_command_findings(rel_path, raw_text, event_name, command))
        # Not an `elif`: Claude Code runs an `http` handler as http whatever else
        # it carries, so a decoy `"command": "true"` beside the `url` hid it.
        if handler.get("type") == "http":
            findings.extend(_http_findings(rel_path, raw_text, event_name, handler))
    return findings


def _command_findings(rel_path: str, raw_text: str, event_name: str, command: str) -> list[Finding]:
    """AAK-HOOK-001 to -006, -008 and -009 for one hook's command line."""
    findings: list[Finding] = []
    commands = _simple_commands(command)

    # AAK-HOOK-001: Network-capable command
    if NETWORK_COMMANDS.search(command):
        findings.append(_make_finding(
            "AAK-HOOK-001", rel_path,
            f"Event '{event_name}': {command}",
            _find_line_number(raw_text, command.split()[0] if command.split() else command),
        ))

    # AAK-HOOK-002: Credential exfiltration
    if CREDENTIAL_VARS.search(command):
        findings.append(_make_finding(
            "AAK-HOOK-002", rel_path,
            f"Event '{event_name}': {command}",
            _find_line_number(raw_text, command.split()[0] if command.split() else command),
        ))

    # AAK-HOOK-003: Write outside project
    if any(_writes_outside(words) for words in commands):
        findings.append(_make_finding(
            "AAK-HOOK-003", rel_path,
            f"Event '{event_name}': {command}",
            _find_line_number(raw_text, command.split()[0] if command.split() else command),
        ))

    # AAK-HOOK-004: an inventory of hooks on the events that fire around
    # tool calls, on each prompt and at session start, rated LOW. At HIGH
    # it failed `--fail-on high` on 150 of 159 real hook-bearing settings
    # files at about 4% precision, and 12 of its 14 true positives did
    # their work in a script the settings file only names, which nothing
    # on the command line shows (hook-precision, 2026-10-12).
    if event_name in SENSITIVE_EVENTS and not _is_formatting_tool(command):
        findings.append(_make_finding(
            "AAK-HOOK-004", rel_path,
            f"Event '{event_name}': {command}",
            _find_line_number(raw_text, event_name),
        ))

    # AAK-HOOK-005: Base64 operations
    if BASE64_PATTERNS.search(command):
        findings.append(_make_finding(
            "AAK-HOOK-005", rel_path,
            f"Event '{event_name}': {command}",
            _find_line_number(raw_text, "base64"),
        ))

    # AAK-HOOK-006: Privilege escalation
    if PRIVILEGE_PATTERNS.search(command):
        findings.append(_make_finding(
            "AAK-HOOK-006", rel_path,
            f"Event '{event_name}': {command}",
            _find_line_number(raw_text, command.split()[0] if command.split() else command),
        ))

    # AAK-HOOK-008: Obfuscated payload. A command over 500 characters
    # was reported too, and all 21 such hits on 159 real settings files
    # were ordinary long one-liners (hook-precision, 2026-10-12): length
    # is not obfuscation, an embedded encoded blob is.
    if OBFUSCATION_PATTERNS.search(command) or _has_encoded_blob(command):
        findings.append(_make_finding(
            "AAK-HOOK-008", rel_path,
            f"Event '{event_name}': {command[:200]}{'...' if len(command) > 200 else ''}",
            _find_line_number(raw_text, event_name),
        ))

    # AAK-HOOK-009: Hook reads source files
    if any(_reads_source(words) for words in commands):
        findings.append(_make_finding(
            "AAK-HOOK-009", rel_path,
            f"Event '{event_name}': {command}",
            _find_line_number(raw_text, command.split()[0] if command.split() else command),
        ))

    return findings
