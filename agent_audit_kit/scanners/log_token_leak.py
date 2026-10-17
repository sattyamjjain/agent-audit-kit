"""AAK-SPLUNK-TOKLOG-001 — token-shaped values in log sinks.

CVE-2026-20205 (the Splunk MCP Server app below 1.0.3) logged session
tokens into the Splunk `_internal` index in cleartext. The pattern generalises:
any `logger.info|warn|error` or `print` whose interpolated argument
matches a Bearer / JWT / `splunkd_session` / `st-*` shape is a token
leak into whatever the log sink is wired to.

One detection, and no version pin:

1. Pattern: log-sink call (Python / TS / JS) whose argument contains a
   token-shaped literal or writes the value of a credential-named variable,
   attribute or key (`access_token`, `client_secret`, `headers["Authorization"]`).

The module used to pin `splunk-mcp-server` below 1.0.3 in Python and npm
manifests, which could only match the wrong package. CVE-2026-20205 names the
Splunk MCP Server app (Splunkbase app 7931, `Splunk_MCP_Server`; Splunk's
SVD-2026-0407), which installs into Splunk, not from a package registry. On
2026-10-17 PyPI had no `splunk-mcp-server`, and npm's, 0.1.1 since 2026-03-09
with no repository, is an unrelated MCP server for Splunk's REST API, every
release of which read as affected. The pin is gone; the app's version, in its
`default/app.conf`, is not read.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SOURCE_MAX_BYTES, in_skip_dir, make_finding, read_text_capped

# A log-level call on any receiver; `_is_logger_receiver` decides whether the receiver
# is a logger. The receiver used to be part of this pattern, as `\b(?:logger|logging|
# LOGGER|log)`, so `_logger`, `self._logger`, `LOG`, `app_logger` and
# `logging.getLogger(__name__)` were not sinks, and `log` was not a method, so
# `logger.log(level, ...)` was not a call to one.
_LOG_METHOD_RE = re.compile(
    r"\.\s*(?:info|warning|warn|error|critical|exception|debug|trace|fatal|severe|fine|finer|finest|log)\s*\("
)
_OTHER_SINK_RE = re.compile(
    r"""
    (?:
        \bprint\s*\(
      | \bconsole\s*\.\s*(?:log|info|warn|error|debug)\s*\(
      | \bSystem\s*\.\s*out\s*\.\s*print(?:ln)?\s*\(
    )
    """,
    re.VERBOSE,
)
# A logger's name: `logger`, `log`, `logging`, in any case and after underscores
# (`_logger`, `LOG`), as the last word of a snake_case name (`app_logger`,
# `audit_log`) or a camelCase hump (`requestLogger`, `appLog`). A word that merely
# ends in "log" (`catalog`, `dialog`, `backlog`) is not one.
_LOGGER_NAME_RE = re.compile(r"(?i:_*(?:[a-z0-9]+_+)*(?:log|logger|logging))|_*[a-z][A-Za-z0-9]*(?:Log|Logger)")
# Calls that hand back a logger: `logging.getLogger(__name__).info(...)`,
# `structlog.get_logger().debug(...)`, `LoggerFactory.getLogger(X.class).info(...)`.
_LOGGER_FACTORIES = frozenset({"getLogger", "get_logger", "getChild"})
# How far back a receiver is read, and how many characters of arguments a call may
# have to be read: bounded, so a crafted file of unclosed calls costs one pass, not
# one walk to its end per call. A call of exactly 4,000 is read, as the rule says.
_RECEIVER_WINDOW = 160
_ARGS_WINDOW = 4_000

_TOKEN_SHAPE_RE = re.compile(
    r"""
    (?:
        Bearer\s+[A-Za-z0-9._\-]{20,}                    # "Bearer eyJ..."
      | eyJ[A-Za-z0-9._\-]{20,}                          # raw JWT
      | splunkd_session=[A-Za-z0-9._\-]{10,}             # Splunk cookie
      | \bst-[A-Za-z0-9]{40,}\b                          # Splunk session token
      | sk-ant-[A-Za-z0-9_\-]{20,}                       # Anthropic API key
      | \bghp_[A-Za-z0-9]{20,}\b                         # GitHub PAT
    )
    """,
    re.VERBOSE,
)

# A credential name counts only where the call writes its value as is:
# a whole argument (`logger.info("x %s", token)`), a keyword argument's value, an
# operand of `+` or `%`, an argument of `.format(...)`, or a whole `{...}` hole of an
# f-string or `${...}` hole of a template literal. A reference may run through
# attributes, keys and `.get("...")` (`self.token`, `headers["Authorization"]`,
# `os.environ.get("OPENAI_API_KEY")`). So the message text never counts ("token" and
# "password" are ordinary words there), and neither does something computed from the
# value: `len(token)`, `token[:8]`, `'set' if API_KEY else 'unset'`, `fingerprint(token)`.
#
# A name is a credential when its last word is one (`github_token`, `bearerToken`,
# `client_secret`, `jwt`, `authorization`) or it runs one in (`authtoken`, `apikey`),
# unless an earlier word says it holds something else: a flag (`has_credentials`), a
# transformed value (`masked_token`), a description of something that has one
# (`configs_with_inline_credential`) or a count or cursor (`cost_per_token`,
# `totalToken`, `next_page_token`). So `max_tokens`, `token_count`, `token_type`,
# `secret_name` and `tokenizer` are not. A name that is only `token` counts when the
# message also calls it a credential (`"token=%s"`, `"auth %s"`), since LLM streaming
# (`print(token, end="")`), lexers and trading code use the word for other things.
#
# This replaced a `\b...\b` group of seven names (`access_token`, `session_token`,
# `id_token`, `auth_token`, `refresh_token`, `splunkd_session`, `api_key`, `bearer`)
# that ran over the whole call, message text included. So it missed bare `token`,
# `jwt`, `secret`, `password` and `authorization`, and `github_token` or
# `client_secret`, and it fired on "Bearer token authentication ENABLED" and on
# `len(api_key)`. On 16,446 source files from public MCP repositories (2026-10-17),
# 148 calls fired on a name only through the message text or a computed value.
_CREDENTIAL_WORDS = frozenset({
    "token", "jwt", "secret", "password", "passwd", "passphrase", "authorization",
    "bearer", "apikey", "credential", "credentials",
})
_CREDENTIAL_SUFFIXES = (
    "token", "secret", "password", "passwd", "apikey", "accesskey", "privatekey", "secretkey",
    "splunkdsession",
)
_NOT_A_CREDENTIAL = frozenset({
    "has", "is", "allow", "allowed", "use", "no", "with", "without", "require", "required", "redact",
    "masked", "redacted", "hashed",
    "truncated", "cost", "per", "total", "count", "num", "max", "min", "next", "page",
    "start", "end", "progress", "cancel", "cancellation", "continuation", "cursor",
    "sync", "symbol", "input", "output", "prompt", "completion", "handoff", "stop",
    "eos", "bos", "pad", "unk", "special",
})
_CREDENTIAL_LABEL_RE = re.compile(r"token|auth|bearer|jwt|credential|secret|password|api[ _-]?key", re.IGNORECASE)
_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")
_WORD_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
# A reference whose value is written as is: a name, then attributes, keys or
# `.get("key")`, the key (or the last name) being what is judged. Each step opens with
# its own character (`.`, `[`), so a read cannot backtrack.
_KEY = r"""(?:"[^"\n]{1,64}"|'[^'\n]{1,64}')"""
_REFERENCE_RE = re.compile(
    r"(?:(?:os\s*\.\s*)?getenv\s*\(\s*(?P<env>" + _KEY + r")\s*(?:,[^()]{0,80})?\)"
    r"|[A-Za-z_$][\w$]*"
    r"(?:\s*\.\s*[A-Za-z_$][\w$]*|\s*\[\s*(?:" + _KEY + r"|\d{1,4})\s*\]"
    r"|\s*\.\s*get\s*\(\s*" + _KEY + r"\s*(?:,[^()]{0,80})?\))*)"
)
_LAST_PART_RE = re.compile(r"""[A-Za-z_$][\w$]*|"[^"\n]{1,64}"|'[^'\n]{1,64}'""")
_KEYWORD_ARG_RE = re.compile(r"\s*[A-Za-z_]\w*\s*=(?!=)")
_TEMPLATE_HOLE_RE = re.compile(r"\$\{([^{}]*)\}")
_FSTRING_HOLE_RE = re.compile(r"(?<!\{)\{([^{}]*)\}")
_STRING_PREFIX_RE = re.compile(r"(?<![\w$])[A-Za-z]{1,2}\Z")
# A call is read only if its arguments end within a file's first this-many characters
# of call arguments, so nested calls cannot make one file cost more than a pass over it
# and this budget.
_FILE_ARGS_BUDGET = 2_000_000

# `.replace(<a token word>, "***")` reads as a redaction. Both runs around the token
# word are bounded: unbounded `[^)]*`, read from every `.replace(` of a closed call that
# opens `.replace(token,` over and over, cost about 110 ms a call, so 80 such calls
# (0.31 MB) took 8.9 s. A real call's first argument is a name, far shorter than 80.
_REDACT_HINTS_RE = re.compile(
    r"""
    (?:
        redact\b | mask\b | anonymi[sz]e\b | \*{3,} | <redacted> | \[redacted\]
      | \.replace\s*\([^)]{0,80}(?:token|auth|bearer|key)[^)]{0,80},\s*['"](\*{3,}|[\[\]<>]*redacted[\[\]<>]*)
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_PY_EXTS = (".py",)
_JS_EXTS = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_JAVA_EXTS = (".java", ".kt")


def _identifier_start(text: str, end: int, lo: int) -> int:
    """Where the identifier that ends at ``end`` starts, looking no further back than ``lo``."""
    i = end
    while i > lo and (text[i - 1].isalnum() or text[i - 1] in "_$"):
        i -= 1
    return i


def _logger_receiver(text: str, dot: int) -> int | None:
    """Where the receiver of the ``.method(`` at ``dot`` starts, if it is a logger.

    The receiver is the identifier before the dot (`_logger`, `self._logger`, `LOG`,
    `requestLogger`), whitespace between them allowed for a chained call, or a call
    that hands back a logger (`logging.getLogger(__name__)`). Both are read within
    ``_RECEIVER_WINDOW`` characters.
    """
    lo = max(0, dot - _RECEIVER_WINDOW)
    j = dot
    while j > lo and text[j - 1].isspace():
        j -= 1
    if j > lo and text[j - 1] == ")":
        depth = 0
        for k in range(j - 1, lo - 1, -1):
            if text[k] == ")":
                depth += 1
            elif text[k] == "(":
                depth -= 1
                if depth == 0:
                    start = _identifier_start(text, k, lo)
                    return start if text[start:k] in _LOGGER_FACTORIES else None
        return None
    start = _identifier_start(text, j, lo)
    return start if start < j and _LOGGER_NAME_RE.fullmatch(text, start, j) else None


def _paren_partners(text: str) -> dict[int, int]:
    """Each `(` in ``text`` mapped to the `)` that closes it, in one pass.

    The `)` a forward walk from a `(` stops at, counting depth, is the one a stack
    pairs it with, so this gives what the per-call walk gave without walking from
    every call to the end of a file that never closes it.
    """
    partners: dict[int, int] = {}
    stack: list[int] = []
    for paren in re.finditer(r"[()]", text):
        if paren.group() == "(":
            stack.append(paren.start())
        elif stack:
            partners[stack.pop()] = paren.start()
    return partners


def _collect_log_call_args(text: str) -> list[tuple[str, int]]:
    """Return a list of (arg_substring, line) pairs for each log-sink call.

    Not a real parser: a call's arguments run to the `)` that closes its `(`, and a
    call whose arguments run past ``_ARGS_WINDOW`` characters, or never close, is
    skipped. Good enough for scanner heuristics; AST would be nice but per-language.
    """
    calls: list[tuple[int, int]] = []  # (where the sink starts, its `(`)
    for match in _LOG_METHOD_RE.finditer(text):
        start = _logger_receiver(text, match.start())
        if start is not None:
            calls.append((start, match.end() - 1))
    for match in _OTHER_SINK_RE.finditer(text):
        calls.append((match.start(), match.end() - 1))
    if not calls:
        return []
    partners = _paren_partners(text)
    breaks = [m.start() for m in re.finditer(r"\n", text)]
    out: list[tuple[str, int]] = []
    for start, open_idx in sorted(calls):
        close = partners.get(open_idx)
        if close is None or close - open_idx - 1 > _ARGS_WINDOW:
            continue
        out.append((text[open_idx + 1 : close], bisect_left(breaks, start) + 1))
    return out


# A string literal: triple-quoted, on one line, or a template literal, the shapes whose
# content is message text. Each alternative is its quotes around a run of characters
# that cannot close it or an escape, so a read never backtracks.
_STRING_LITERAL_RE = re.compile(
    r'"""(?:[^"\\]|\\.|"(?!""))*"""' r"|'''(?:[^'\\]|\\.|'(?!''))*'''"
    r'|"(?:[^"\\\n]|\\.)*"' r"|'(?:[^'\\\n]|\\.)*'" r"|`(?:[^`\\]|\\.)*`"
)
_FORMAT_CALL_RE = re.compile(r"\.\s*format\s*\(")


_QUOTE_RE = re.compile(r"[\"'`]")
_STRUCTURE_RE = re.compile(r"[()\[\]{},+%]")


def _literal_spans(text: str) -> list[tuple[int, int, bool]]:
    """Each string literal in ``text``, read once left to right: ``(start, end, closed)``.

    A quote that opens no complete literal opens one that runs to the end of the text,
    and the read stops there. Retrying `_STRING_LITERAL_RE` at every later quote, as a
    `finditer` does, re-scanned the rest of the argument once per quote: on arguments of
    `"\\` pairs, 200 closed calls of 4 KB took 14 s (0.16 s on main).
    """
    spans: list[tuple[int, int, bool]] = []
    pos = 0
    while True:
        quote = _QUOTE_RE.search(text, pos)
        if quote is None:
            return spans
        literal = _STRING_LITERAL_RE.match(text, quote.start())
        if literal is None:
            spans.append((quote.start(), len(text), False))
            return spans
        spans.append((quote.start(), literal.end(), True))
        pos = literal.end()


def _operands(code: str, depth_left: int = 4) -> list[str]:
    """``code`` cut at each `,`, `+` and `%` outside brackets and string literals.

    A keyword argument's name, a wrapping pair of parentheses (`% (a, b)`) and a
    `"...".format(...)` call are opened, so each piece is one value the call writes;
    ``depth_left`` bounds how many are opened inside one another.
    """
    pieces: list[str] = []
    spans = _literal_spans(code)
    depth = start = 0
    span_at = 0
    for mark in _STRUCTURE_RE.finditer(code):
        at = mark.start()
        while span_at < len(spans) and spans[span_at][1] <= at:
            span_at += 1
        if span_at < len(spans) and spans[span_at][0] <= at:
            continue  # inside a string literal
        ch = mark.group()
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif depth == 0:
            pieces.append(code[start:at])
            start = at + 1
    pieces.append(code[start:])
    out: list[str] = []
    for piece in pieces:
        keyword = _KEYWORD_ARG_RE.match(piece)
        piece = piece[keyword.end():] if keyword else piece
        stripped = piece.strip()
        call = _FORMAT_CALL_RE.search(stripped)
        if depth_left and stripped.startswith("(") and stripped.endswith(")"):
            out.extend(_operands(stripped[1:-1], depth_left - 1))
        elif depth_left and call is not None and stripped.endswith(")") and _STRING_LITERAL_RE.match(stripped):
            out.extend(_operands(stripped[call.end():-1], depth_left - 1))
        else:
            out.append(stripped)
    return out


# Calls and methods that write the value they are given: `str(token)`, `repr(token)`,
# `format(token)`, `token.strip()`, `token.decode()`. Anything else computes a value
# from it (`len(token)`, `token[:8]`, `hash(token)`), which is not the credential.
_VALUE_FUNCTIONS = frozenset({"str", "repr", "format"})
_VALUE_METHODS = frozenset({"strip", "lstrip", "rstrip", "decode", "encode"})


def _first_argument(arguments: str) -> str:
    """The text before the first comma outside brackets in a call's arguments."""
    depth = 0
    for mark in _STRUCTURE_RE.finditer(arguments):
        ch = mark.group()
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return arguments[: mark.start()]
    return arguments


def _value_of(expression: str) -> str:
    """``expression`` with its value-keeping wrappers taken off, at most four."""
    value = expression.strip()
    for _ in range(4):
        if not value.endswith(")"):
            return value
        head, dot, call = value.rpartition(".")
        method, paren, rest = call.partition("(")
        if dot and paren and method.strip() in _VALUE_METHODS and "(" not in rest and rest.count(")") == 1:
            value = head.strip()
            continue
        name, paren, _rest = value.partition("(")
        if paren and name.strip() in _VALUE_FUNCTIONS:
            value = _first_argument(value[len(name) + 1 : -1]).strip()
            continue
        return value
    return value


def _referenced_name(expression: str) -> str | None:
    """The name a reference ends in (`self.token` -> `token`, `headers["Authorization"]`
    -> `Authorization`), or None when ``expression`` computes a value from one."""
    if len(expression) > 200:
        return None
    reference = _REFERENCE_RE.fullmatch(_value_of(expression))
    if reference is None:
        return None
    last = reference.group("env") or _LAST_PART_RE.findall(reference.group())[-1]
    return last.strip("\"'")


def _written_names(arg_str: str) -> tuple[list[str], str]:
    """The names whose values a log call writes as is, and the call's message text.

    See `_CREDENTIAL_WORDS` for what counts as written as is. The message text is every
    string literal's text, the holes of an f-string or template literal left out.
    """
    names: list[str] = []
    message: list[str] = []
    for start, end, closed in _literal_spans(arg_str):
        text = arg_str[start:end]
        quotes = 3 if text.startswith(('"""', "'''")) else 1
        body = text[quotes : len(text) - quotes] if closed else text[quotes:]
        prefix = _STRING_PREFIX_RE.search(arg_str, max(0, start - 2), start)
        if text[0] == "`":
            holes, hole_re = _TEMPLATE_HOLE_RE.findall(body), _TEMPLATE_HOLE_RE
        elif prefix is not None and "f" in prefix.group().lower():
            holes, hole_re = _FSTRING_HOLE_RE.findall(body), _FSTRING_HOLE_RE
        else:
            holes, hole_re = [], None
        message.append(hole_re.sub(" ", body) if hole_re is not None else body)
        for hole in holes:
            # `{token!r}`, `{token:>8}` and `{token=}` write the value too.
            expression = hole.split("!", 1)[0].split(":", 1)[0].rstrip("= ")
            name = _referenced_name(expression)
            if name is not None:
                names.append(name)
    for operand in _operands(arg_str):
        name = _referenced_name(operand)
        if name is not None:
            names.append(name)
    return names, " ".join(message)


def _credential_words(name: str) -> list[str] | None:
    """A name's words when it names a credential (see `_CREDENTIAL_WORDS`), else None."""
    if len(name) > 64:
        return None
    words = [w.lower() for w in _WORD_SPLIT_RE.split(_CAMEL_RE.sub(r"\1_\2", name)) if w]
    if not words or any(w in _NOT_A_CREDENTIAL for w in words[:-1]):
        return None
    if words[-1] in _CREDENTIAL_WORDS or "".join(words).endswith(_CREDENTIAL_SUFFIXES):
        return words
    return None


def _contains_token_leak(arg_str: str) -> bool:
    if _REDACT_HINTS_RE.search(arg_str):
        return False
    if _TOKEN_SHAPE_RE.search(arg_str):
        return True
    # A credential-named value the call writes: `f"session={session_token}"`,
    # `logger.info("bearer %s", bearer_token)`, `print(headers["Authorization"])`.
    names, message = _written_names(arg_str)
    for name in names:
        words = _credential_words(name)
        if words is None:
            continue
        if words == ["token"] and not _CREDENTIAL_LABEL_RE.search(message):
            continue
        return True
    return False


def _check_pattern(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _PY_EXTS + _JS_EXTS + _JAVA_EXTS:
            continue
        if in_skip_dir(path, project_root):
            continue
        try:
            text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
        except OSError:
            continue
        budget = _FILE_ARGS_BUDGET
        for arg_str, line in _collect_log_call_args(text):
            budget -= len(arg_str)
            if budget < 0:
                break
            if _contains_token_leak(arg_str):
                rel = str(path.relative_to(project_root))
                scanned.add(rel)
                findings.append(make_finding(
                    "AAK-SPLUNK-TOKLOG-001",
                    rel,
                    "Log sink call contains a token-shaped value or "
                    "unredacted token variable — CVE-2026-20205 shape.",
                    line_number=line,
                ))
                break  # One finding per file is plenty.
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    findings.extend(_check_pattern(project_root, scanned))
    return findings, scanned
