"""Credentials written into Claude Code's permission rules (AAK-SECRET-010).

When a user answers "Yes, and don't ask again" to a shell command, Claude Code
saves the exact command, any secret on it included, as a `Bash(<command>)` rule
in `.claude/settings.local.json`. Apiiro, reported by The Hacker News on 7 Nov
2026, found 104,185 public copies of that file, 1,122 of them holding at least
one secret: database passwords (`PGPASSWORD=`, `mysql -p`), SSH logins
(`sshpass -p`), tokens and cloud keys. A typed password is short and low in
entropy, so AAK-SECRET-004's length and entropy gate drops it, and `-pSECRET`
or `sshpass -p SECRET` is no `NAME=value` shape at all. Here the place is the
evidence: a value in one of the shapes below, inside a permission rule, is
read with no length or entropy gate.

This module reads the rules and the credentials in them; `secret_exposure`
decides which to report (placeholders, values another rule already reports)
and builds the findings. It is a helper, not a scanner: the engine never calls
it, and the count scripts do not count it.

Everything here is linear in the file: the commands are cut into words by one
regex pass each, never by `shlex`, which grows a word one character at a time.
"""

from __future__ import annotations

import re
from collections import deque
from pathlib import Path
from typing import Any, NamedTuple

from ._helpers import strip_jsonc

#: The Claude Code settings files whose permission rules are read, in a `.claude` folder.
PERMISSION_FILES = frozenset({"settings.json", "settings.local.json"})
#: The permission lists, each a list of rule strings.
PERMISSION_LISTS = ("allow", "ask", "deny")


class Credential(NamedTuple):
    """One literal credential inside one permission rule."""

    rule_list: str   # `allow`, `ask` or `deny`
    shape: str       # what the message names: "assignment to `PGPASSWORD`"
    value: str       # the credential, never shown whole
    entry: str       # the rule string it was read from, to place it in the file


def is_permission_file(path: Path) -> bool:
    """Is `path` a Claude Code settings file whose permission rules are read?"""
    return path.name in PERMISSION_FILES and path.parent.name == ".claude"


# `Bash(<command>)`; anything else is read as written.
_BASH_RULE_RE = re.compile(r"\ABash\((.*)\)\Z", re.DOTALL)
# Claude Code's prefix wildcard at the end of a rule (`Bash(npm run:*)`), which is not
# part of the command.
_PREFIX_WILDCARD = ":*"
# One shell word, quotes and backslash escapes kept, or a run of the operators that end
# a simple command. Each alternative of the word takes one quoted span or one plain
# character, so the repetition never re-reads what it matched.
_WORD_RE = re.compile(r"""(?:[^\s'"\\;&|]|'[^']*'|"(?:[^"\\]|\\.)*"|\\.)+|[;&|]+""", re.DOTALL)
_QUOTED_RE = re.compile(r"""'([^']*)'|"((?:[^"\\]|\\.)*)"|\\(.)""", re.DOTALL)
_DOUBLE_QUOTE_ESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)

# `NAME=VALUE` with a credential's name. PWD alone is the shell's working directory, and a
# name ending in _FILE, _PATH, _DIR or _URL names where a secret is, not the secret.
_ASSIGNMENT_RE = re.compile(r"\A([A-Za-z_][A-Za-z0-9_]*)=(.*)\Z", re.DOTALL)
_LOGIN_NAME_RE = re.compile(r"PASSWORD|PASSWD|PWD|SECRET|TOKEN", re.IGNORECASE)
_LOCATION_NAME_RE = re.compile(r"\A(?:OLD)?PWD\Z|_(?:FILE|PATH|DIR|URL)\Z", re.IGNORECASE)
_MYSQL_CLIENTS = frozenset({"mysql", "mariadb", "mysqldump", "mysqladmin"})
# sshpass options that take a value as the next word.
_SSHPASS_VALUE_OPTIONS = frozenset({"-f", "-d", "-P"})
_URL_USERINFO_RE = re.compile(
    r"(?<![\w+.-])(postgres|postgresql|mysql|redis|rediss|mongodb|mongodb\+srv|amqp|amqps|http|https)"
    r"://[^\s:/@]*:([^\s/@]+)@",
    re.IGNORECASE,
)
_AUTHORIZATION_RE = re.compile(r"\bAuthorization:\s*(Bearer|Basic|token)\s+(\S+)", re.IGNORECASE)


def _unquote(word: str) -> str:
    """A shell word as the command receives it: quotes removed, escapes resolved."""
    def one(m: re.Match[str]) -> str:
        if m.group(1) is not None:
            return m.group(1)
        if m.group(2) is not None:
            return _DOUBLE_QUOTE_ESCAPE_RE.sub(r"\1", m.group(2))
        return m.group(3)
    return _QUOTED_RE.sub(one, word)


def _simple_commands(command: str) -> list[list[str]]:
    """The command's simple commands, each as its words with quotes removed."""
    commands: list[list[str]] = [[]]
    for m in _WORD_RE.finditer(command):
        word = m.group()
        if word[0] in ";&|":
            commands.append([])
        else:
            commands[-1].append(_unquote(word))
    return [words for words in commands if words]


def _program(word: str) -> str:
    return word.rsplit("/", 1)[-1].lower()


def _assignments(words: list[str]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for word in words:
        m = _ASSIGNMENT_RE.match(word)
        if m and _LOGIN_NAME_RE.search(m.group(1)) and not _LOCATION_NAME_RE.search(m.group(1)):
            found.append((f"assignment to `{m.group(1)}`", m.group(2)))
    return found


def _mysql_passwords(words: list[str]) -> list[tuple[str, str]]:
    """`-pVALUE` attached after a MySQL or MariaDB client. A bare `-p` prompts, and `-P` is
    the port. The client reads no value after `--password` and a space (the long form
    takes one only after `=`), so that is left to `_password_options`' `=` form."""
    found: list[tuple[str, str]] = []
    client = None
    for word in words:
        if client is None:
            if _program(word) in _MYSQL_CLIENTS:
                client = _program(word)
            continue
        if word.startswith("-p") and len(word) > 2:
            found.append((f"password attached to `{client} -p`", word[2:]))
    return found


def _password_options(words: list[str]) -> list[tuple[str, str]]:
    """`--password=VALUE` on any command, and `--password VALUE` except after a MySQL or
    MariaDB client, where the next word is not the password."""
    found: list[tuple[str, str]] = []
    mysql = any(_program(word) in _MYSQL_CLIENTS for word in words)
    for i, word in enumerate(words):
        if word.startswith("--password="):
            found.append(("value of `--password`", word[len("--password="):]))
        elif word == "--password" and not mysql and i + 1 < len(words) and not words[i + 1].startswith("-"):
            found.append(("value of `--password`", words[i + 1]))
    return found


def _sshpass_passwords(words: list[str]) -> list[tuple[str, str]]:
    """`sshpass -p VALUE` or `-pVALUE`, read among sshpass's own options only: the command
    it runs (`ssh -p 2222 host`) has a `-p` of its own."""
    found: list[tuple[str, str]] = []
    for start, word in enumerate(words):
        if _program(word) != "sshpass":
            continue
        i = start + 1
        while i < len(words) and words[i].startswith("-"):
            option = words[i]
            if option == "-p":
                if i + 1 < len(words):
                    found.append(("password after `sshpass -p`", words[i + 1]))
                i += 2
            elif option.startswith("-p"):
                found.append(("password after `sshpass -p`", option[2:]))
                i += 1
            else:
                i += 2 if option in _SSHPASS_VALUE_OPTIONS else 1
        break
    return found


def _curl_passwords(words: list[str]) -> list[tuple[str, str]]:
    """`curl -u user:VALUE` and `--user user:VALUE`, attached or not. A `-u user` with no
    colon makes curl prompt, so it holds none."""
    found: list[tuple[str, str]] = []
    if not any(_program(word) == "curl" for word in words):
        return found
    for i, word in enumerate(words):
        flag, given = None, None
        if word in ("-u", "--user") and i + 1 < len(words):
            flag, given = word, words[i + 1]
        elif word.startswith("--user="):
            flag, given = "--user", word[len("--user="):]
        elif word.startswith("-u") and len(word) > 2 and not word.startswith("--"):
            flag, given = "-u", word[2:]
        if flag is not None and given is not None and ":" in given:
            found.append((f"password in the credentials after `curl {flag}`", given.split(":", 1)[1]))
    return found


def _text_passwords(words: list[str]) -> list[tuple[str, str]]:
    """A URL's userinfo password and an Authorization header's credentials, read in the
    simple command's words joined back, so an unquoted `-H Authorization: Bearer x`
    reads as a quoted one does."""
    text = " ".join(words)
    found = [(f"password in a `{m.group(1).lower()}://` URL", m.group(2)) for m in _URL_USERINFO_RE.finditer(text)]
    found.extend(
        (f"{m.group(1).capitalize()} credentials in an `Authorization` header", m.group(2))
        for m in _AUTHORIZATION_RE.finditer(text)
    )
    return found


def _is_reference(value: str) -> bool:
    """A value the shell fills in (`$DB_PASS`, `$(cat f)`, `${X}`) or a rule's wildcard."""
    return not value or value.startswith("$") or value == "*" or value.endswith("*")


def command_credentials(rule: str) -> list[tuple[str, str]]:
    """(shape, value) for every literal credential in one permission rule string, each
    value once, in the order the shapes are read. Shell references and wildcards are
    left out; placeholders are the caller's to judge."""
    m = _BASH_RULE_RE.match(rule)
    command = m.group(1) if m else rule
    if command.endswith(_PREFIX_WILDCARD):
        command = command[: -len(_PREFIX_WILDCARD)]
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for words in _simple_commands(command):
        for reader in (_assignments, _mysql_passwords, _password_options, _sshpass_passwords,
                       _curl_passwords, _text_passwords):
            for shape, value in reader(words):
                if _is_reference(value) or value in seen:
                    continue
                seen.add(value)
                found.append((shape, value))
    return found


def permission_rules(data: Any) -> list[tuple[str, str]]:
    """(list name, rule string) for every string in `permissions.allow`, `.ask` and
    `.deny` of a parsed settings file, in that order."""
    permissions = data.get("permissions") if isinstance(data, dict) else None
    if not isinstance(permissions, dict):
        return []
    rules: list[tuple[str, str]] = []
    for name in PERMISSION_LISTS:
        entries = permissions.get(name)
        if isinstance(entries, list):
            rules.extend((name, entry) for entry in entries if isinstance(entry, str))
    return rules


def credentials(data: Any) -> list[Credential]:
    """Every literal credential in a parsed settings file's permission rules."""
    return [
        Credential(rule_list, shape, value, rule)
        for rule_list, rule in permission_rules(data)
        for shape, value in command_credentials(rule)
    ]


# A JSON string literal in the file's text, escapes kept.
_JSON_STRING_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"')

_JSON_ESCAPE_RE = re.compile(r'\\(?:u([0-9a-fA-F]{4})|(["\\/bfnrt]))')
_JSON_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _json_string(literal: str) -> str:
    """One JSON string literal's text, escapes resolved and surrogate pairs joined, so a
    rule written with `\\u0041` is found as the parsed rule reads it. A literal has no
    nesting, so this needs no recursive parser (`json.loads`), which scanners call only
    through the refusing helpers. Raises ValueError for a lone surrogate."""
    def one(m: re.Match[str]) -> str:
        return chr(int(m.group(1), 16)) if m.group(1) else _JSON_ESCAPES[m.group(2)]
    text = _JSON_ESCAPE_RE.sub(one, literal[1:-1])
    return text.encode("utf-16", "surrogatepass").decode("utf-16")


class RulePlaces:
    """Where each rule string sits in the file's text, built on first use in one pass.

    A rule written twice is placed at its first copy, then its second: each lookup takes
    the next unclaimed offset of that string.
    """

    def __init__(self, text: str) -> None:
        self._text = text
        self._offsets: dict[str, deque[int]] | None = None

    def offset(self, rule: str) -> int | None:
        if self._offsets is None:
            self._offsets = {}
            try:
                bare = strip_jsonc(self._text)
            except ValueError:
                bare = self._text
            for m in _JSON_STRING_RE.finditer(bare):
                try:
                    decoded = _json_string(m.group())
                except ValueError:  # a lone surrogate
                    continue
                self._offsets.setdefault(decoded, deque()).append(m.start())
        found = self._offsets.get(rule)
        if not found:
            return None
        return found.popleft() if len(found) > 1 else found[0]


__all__ = [
    "Credential",
    "PERMISSION_FILES",
    "PERMISSION_LISTS",
    "RulePlaces",
    "command_credentials",
    "credentials",
    "is_permission_file",
    "permission_rules",
]
