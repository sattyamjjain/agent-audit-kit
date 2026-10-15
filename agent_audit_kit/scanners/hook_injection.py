from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    find_line_number,
    hook_command,
    iter_hook_handlers,
    make_finding,
)

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
# 2026-10-12).
CREDENTIAL_VARS = re.compile(
    r"\$(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|"
    r"AWS_ACCESS_KEY_ID)|"
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


_find_line_number = find_line_number
_make_finding = make_finding


def _extract_hook_commands(hooks_data: Any) -> list[tuple[str, str]]:
    """Extract (event_name, command_string) pairs from a ``hooks`` block.

    Every handler ``iter_hook_handlers`` finds, in Claude Code's documented
    matcher-group shape or the flat ``{"command": ...}`` shape, that runs a
    command line. Exec form (``args`` set) is joined into one string; see
    ``hook_command``.
    """
    results: list[tuple[str, str]] = []
    for event_name, handler in iter_hook_handlers(hooks_data):
        command = hook_command(handler)
        if command:
            results.append((event_name, command))
    return results


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
    lexer = shlex.shlex(command, posix=True, punctuation_chars="".join(sorted(_PUNCTUATION)))
    lexer.whitespace = " \t\r"  # a newline ends a command, so it is punctuation here
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:
        return command.split()


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
    settings_files = _find_settings(project_root, include_user_config)

    for settings_path in settings_files:
        try:
            raw_text = settings_path.read_text(encoding="utf-8")
            if len(raw_text) > 1_000_000:
                continue
            data = json.loads(raw_text)
        except (json.JSONDecodeError, OSError):
            continue

        rel_path = str(settings_path.relative_to(project_root)) if settings_path.is_relative_to(project_root) else str(settings_path)
        scanned_files.add(rel_path)
        hooks = data.get("hooks", {})
        if not hooks:
            continue

        hook_commands = _extract_hook_commands(hooks)

        # AAK-HOOK-007: Excessive hook count
        hook_count = _count_hooks(hooks)
        if hook_count > 15:
            findings.append(_make_finding(
                "AAK-HOOK-007", rel_path,
                f"{hook_count} hooks defined (threshold: 15)",
                _find_line_number(raw_text, "hooks"),
            ))

        for event_name, command in hook_commands:
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

    return findings, scanned_files
