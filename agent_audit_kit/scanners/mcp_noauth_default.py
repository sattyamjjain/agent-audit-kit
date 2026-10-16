"""MCP server unauthenticated-by-default / fail-open auth scanner — CWE-306/862.

Distinct from `AAK-MCP-HTTP-NOAUTH-SERVER-001` (which flags a transport with *no
auth configured at all*): this flags an MCP server that **ships an auth check
that does not actually enforce** — it fails open on an empty/unset secret, or
ships a placeholder/default credential. CVE-2026-48814 (Network-AI, CVSS 9.1) is
the anchor — an *incomplete fix* of CVE-2026-46701 where the added auth gate
still admitted requests when the secret was unset.

Three detection arms (all emit ``AAK-MCP-NOAUTH-DEFAULT``):
  (a) an auth / ``is_authorized`` / ``verify_token``-style function that returns
      a truthy value when the secret/token is empty or unset
      (``if not SECRET: return True``);
  (b) a default / placeholder secret literal — a secret-named variable set to
      ``""`` / ``"changeme"`` / ``"secret"`` / ``"admin"`` / ..., or
      ``os.environ.get("X_SECRET", "")`` with an empty default (ships unauthed);
  (c) a secret-emptiness gate that only *warns* (logs and proceeds, no
      raise/return) while the server binds a non-loopback interface
      (``0.0.0.0`` / ``::``).

FP guards: a required secret (``os.environ["X"]`` with no empty default), a
non-empty literal, an auth function that returns ``token == SECRET``, and a
loopback bind all PASS. Python is analysed with stdlib ``ast``; JSON / YAML /
env / TOML configs use a guarded text pass (placeholder secret + non-loopback
bind).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, in_skip_dir

_RULE_ID = "AAK-MCP-NOAUTH-DEFAULT"

_MCP_HINT_RE = re.compile(
    r"\bmcp\b|modelcontextprotocol|FastMCP|McpServer|mcpServers|\bServer\s*\(",
    re.IGNORECASE,
)
_SECRET_NAME_RE = re.compile(
    r"secret|token|api[_-]?key|apikey|password|passwd|auth[_-]?key|auth_token",
    re.IGNORECASE,
)
_AUTH_FN_RE = re.compile(
    r"^_?(?:is_?authori[sz]ed|authori[sz]e|check_?auth|verify_?token|verify_?auth"
    r"|require_?auth|validate_?token|validate_?auth|authenticate)$",
    re.IGNORECASE,
)
_WEAK_SECRET_VALUES = frozenset({
    "", "changeme", "change-me", "change_me", "secret", "password", "passwd",
    "admin", "default", "token", "test", "placeholder", "xxx", "none",
    "your-secret-here", "your_secret_here", "your-token-here", "example",
})
_WARN_CALL_RE = re.compile(r"warn|warning|getLogger|logger|print|console\.warn", re.IGNORECASE)
# Non-loopback bind: 0.0.0.0, [::], or a quoted "::" — NOT a bare `::` (which
# also appears in GitHub Actions `::group::` syntax, slices, C++ scope, etc.).
_BIND_NONLOOPBACK_RE = re.compile(r"0\.0\.0\.0|\[::\]|[\"']::[\"']")

_PY_SUFFIXES = (".py",)
_CONFIG_SUFFIXES = (".json", ".yaml", ".yml", ".env", ".toml")


# ---------------------------------------------------------------------------
# Python (AST)
# ---------------------------------------------------------------------------


def _is_emptiness_test(test: ast.AST) -> bool:
    """True if `test` checks a secret-ish name for empty / None / falsy."""
    # `if not SECRET:` / `if not token:`
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _refs_secret(test.operand)
    # `if SECRET == "" / is None / in (None, "")`
    if isinstance(test, ast.Compare) and _refs_secret(test.left):
        for op, comp in zip(test.ops, test.comparators):
            if isinstance(op, (ast.Eq, ast.Is, ast.In)):
                if isinstance(comp, ast.Constant) and (comp.value in ("", None)):
                    return True
                if isinstance(comp, (ast.Tuple, ast.List, ast.Set)):
                    return True
    # bare `if SECRET:` is NOT an emptiness test (that's the safe direction)
    return False


def _refs_secret(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and _SECRET_NAME_RE.search(sub.id):
            return True
        if isinstance(sub, ast.Attribute) and _SECRET_NAME_RE.search(sub.attr):
            return True
    return False


def _returns_truthy(body: list[ast.stmt]) -> bool:
    for stmt in body:
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant):
            if stmt.value.value not in (False, None, "", 0):
                return True
    return False


_STOP_CALLS = frozenset({"exit", "_exit", "abort", "quit"})


def _call_stops(name: str) -> bool:
    """True if a call spelled `name` ends the process or the command.

    A call named exit, _exit, abort or quit, as the whole name or its last
    part (`sys.exit`, `os._exit`, `os.abort`, click's `ctx.exit` and
    `ctx.abort`, the `exit()` and `quit()` builtins, which raise SystemExit),
    argparse's `<parser>.error(...)`, which prints usage and exits with status
    2, and click's `ctx.fail(...)`, which raises UsageError and ends the
    command. Until the last two and `quit` were read, a gate that warned and
    then called `quit(1)` or `parser.error(...)` was reported as one that
    carries on.

    The names are matched whole, not as substrings. A substring test read
    `atexit.register(...)`, which registers an exit handler and carries on, as
    a stop, so a gate that warned and then registered one went unreported;
    `app.on_exit(...)` and `log_equity(...)` are not stops either. The
    receiver decides the other two: `.error` stops only on a name containing
    parser (`parser`, `self.arg_parser`), so `logger.error(...)` and
    `logging.error(...)` still carry on, and `.fail` only on a name containing
    ctx or context (`ctx`, `click.get_current_context()`).
    """
    receiver, _, method = name.rpartition(".")
    if method in _STOP_CALLS:
        return True
    receiver = receiver.lower()
    if method == "error" and "parser" in receiver:
        return True
    return method == "fail" and ("ctx" in receiver or "context" in receiver)


def _body_is_warn_only(body: list[ast.stmt]) -> bool:
    """True if the branch warns/logs and then *continues* — no raise / return /
    call that would stop unauthenticated execution (see `_call_stops`)."""
    saw_warn = False
    for stmt in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(stmt, (ast.Raise, ast.Return)):
            return False
        if isinstance(stmt, ast.Call):
            name = ast.unparse(stmt.func) if hasattr(ast, "unparse") else ""
            if _call_stops(name):
                return False
            if _WARN_CALL_RE.search(name):
                saw_warn = True
    return saw_warn


def _env_default(call: ast.Call) -> ast.expr | None:
    """The default an `os.getenv` / `os.environ.get` call passes, if any.

    Both take it second or as `default=`. Only the positional spelling was
    read, so `os.getenv("MCP_API_KEY", default="")` shipped the same empty
    credential unreported.
    """
    if len(call.args) >= 2:
        return call.args[1]
    for keyword in call.keywords:
        if keyword.arg == "default":
            return keyword.value
    return None


def _scan_python(text: str) -> list[tuple[int, str]]:
    if not _MCP_HINT_RE.search(text):
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    hits: list[tuple[int, str]] = []
    bind_nonloopback = bool(_BIND_NONLOOPBACK_RE.search(text))

    # (a) auth function that fails open on empty/unset secret.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _AUTH_FN_RE.match(node.name):
            for inner in ast.walk(node):
                if isinstance(inner, ast.If) and _is_emptiness_test(inner.test) and _returns_truthy(inner.body):
                    hits.append((inner.lineno, "fail-open-auth"))
                    break

    # (b) placeholder / empty default secret literal.
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if value is None:
            continue
        names = [t.id for t in targets if isinstance(t, ast.Name)]
        if not any(_SECRET_NAME_RE.search(n) for n in names):
            continue
        lineno = getattr(node, "lineno", 0)
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            if value.value.strip().lower() in _WEAK_SECRET_VALUES:
                hits.append((lineno, "placeholder-secret"))
        elif isinstance(value, ast.Call):
            fn = ast.unparse(value.func) if hasattr(ast, "unparse") else ""
            if fn in ("os.environ.get", "os.getenv"):
                default = _env_default(value)
                if isinstance(default, ast.Constant) and default.value == "":
                    hits.append((lineno, "empty-default-secret"))

    # (c) warning-only secret gate while bound non-loopback.
    if bind_nonloopback:
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and _is_emptiness_test(node.test):
                if _body_is_warn_only(node.body):
                    hits.append((node.lineno, "warn-only-auth-gate"))

    return hits


# ---------------------------------------------------------------------------
# Config (JSON / YAML / env / TOML) — placeholder secret + non-loopback bind
# ---------------------------------------------------------------------------

_WEAK_CFG_WORDS = (
    r"changeme|change-me|change_me|secret|password|admin|default|placeholder"
    r"|xxx|example|token|test"
)
# The key is matched only from the start of its `[\w-]` run, and the secret word
# is found by a lookahead before the run is consumed once. `[\w-]*WORD[\w-]*`
# let a match start at every character of a run and place the word at every
# occurrence inside it: 10,000 letters took 1.7 seconds and 5,000 characters of
# `secret` repeated took 66. A match from the run's start exists exactly when
# one from inside it does, so what matches, and where, is unchanged.
_CFG_SECRET_KV_RE = re.compile(
    r"(?<![\w-])[\"']?"
    r"(?=[\w-]*(?:secret|token|api[_-]?key|apikey|password|auth[_-]?key))[\w-]+[\"']?"
    r"[ \t]*[:=][ \t]*"
    r"(?:"
    rf"[\"'](?:{_WEAK_CFG_WORDS}|)[\"']"          # quoted weak word, or empty ""
    rf"|(?:{_WEAK_CFG_WORDS})(?=[\s,}}\]]|$)"      # unquoted weak word at a boundary
    r")",
    re.IGNORECASE | re.MULTILINE,
)


# Auth switched off by a flag rather than by an empty secret. This is the same
# idea spelled differently, and until #731 the scanner only knew the first
# spelling: CVE-2026-90898's Bifrost config reads
# `governance.auth_config.is_enabled: false`, carries no secret at all, and so
# matched nothing. Covers YAML (`auth:` then `enabled: false`, or a dotted
# key), TOML keys and inline tables (`auth.enabled = false`,
# `auth = { enabled = false }`), JSON (`"auth": {"enabled": false}`,
# `"disable_auth": true`) and env flags (`DISABLE_AUTH=true`, `AUTH=off`).
# JSON's quoted keys were missed until the keyword could be followed by its
# closing quote: that quote sat between the keyword and the colon, so the
# nested `"enabled"` and the `"disable_*"` flags matched only where keys go
# unquoted (YAML, env). The keyword keeps its `\b` on both sides, so a longer name
# (`"disable_auth_logging"`, `"enabled_features"`) is still not read as one.
# Not read: a TOML table header (`[auth]`, then `enabled = false` on its own
# line) and an env name that only contains a keyword (`AUTH_ENABLED=false`).
#
# This took 16 seconds on a 4 KB config of `auth:` and blank lines, four times
# the 2 KB time, and 220 seconds on 8 KB of `auth.` repeated, seven times the
# 4 KB time. Three overlapping scans did it, each now fixed without changing
# what matches:
# - A lazy `[\s"'.\w-]*?` before the keyword let a match start anywhere in the
#   run before it, across newlines. It only moved the start, so it is gone,
#   and the finding now names the keyword's line instead of an earlier one.
# - The key path stops at the next auth keyword (a tempered token), so a path
#   of repeated keywords is read once; a match that ran past one also exists
#   from it, on the same line.
# - `\s*\{?\s*` split each whitespace run between two `\s*` every possible way,
#   and the nested `enabled` window could start inside that run. The `{` now
#   takes its own trailing whitespace, and the window starts at a non-space.
_AUTH_KEYWORDS = (
    r"auth|authentication|authorization|auth_config|require_auth|requireauth|security|governance"
)


def _whole_value(words: str) -> str:
    """A config value that is exactly one of `words`.

    Quoted, it ends at its closing quote; bare, at whitespace, a comma, a
    closing brace or bracket, or the end of the text. The values had no end,
    so any word that merely began with one read as auth off: `auth: office365`,
    `auth: 0.5`, `security: normal` and `disable_auth: online` were reported
    HIGH. `none` is listed because it was matched (as `no` followed by more
    letters) and `auth: none` does mean no authentication.
    """
    return rf"""(?:"(?:{words})"|'(?:{words})'|(?:{words})(?=[\s,}}\]]|$))"""


_AUTH_OFF_VALUE = _whole_value("false|0|no|none|off|disabled")
_AUTH_OFF_FLAG_VALUE = _whole_value("true|1|yes|on")

_CFG_AUTH_DISABLED_RE = re.compile(
    rf"""
    (?:
        # auth-ish key, then a false-y value, tolerating a `.`/`_` key path
        \b(?:{_AUTH_KEYWORDS})\b
        (?:(?!\b(?:{_AUTH_KEYWORDS})\b)[\w."'\-])*
        \s*[:=]\s*
        (?:\{{\s*)?
        (?:(?:\S[\s\S]{{0,119}}?)?\b(?:is_enabled|enabled|required|require)\b["']?\s*[:=]\s*)?
        {_AUTH_OFF_VALUE}
      |
        \b(?:disable_auth|no_auth|auth_disabled|skip_auth|allow_anonymous)\b["']?
        \s*[:=]\s*{_AUTH_OFF_FLAG_VALUE}
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _scan_config(text: str) -> list[tuple[int, str]]:
    if not _MCP_HINT_RE.search(text):
        return []
    if not _BIND_NONLOOPBACK_RE.search(text):
        return []
    m = _CFG_SECRET_KV_RE.search(text)
    if m:
        return [(text.count("\n", 0, m.start()) + 1, "placeholder-secret-config")]
    # Auth turned off by a flag, with no secret present to be a placeholder.
    disabled = _CFG_AUTH_DISABLED_RE.search(text)
    if disabled:
        return [(text.count("\n", 0, disabled.start()) + 1, "auth-disabled-config")]
    return []


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_EVIDENCE = {
    "fail-open-auth": (
        "Auth function returns a truthy/allow value when the secret or token is "
        "empty or unset — the gate fails open, admitting unauthenticated callers"
    ),
    "placeholder-secret": (
        "A secret/token is hard-coded to a default/placeholder value — the "
        "server ships effectively unauthenticated until an operator changes it"
    ),
    "empty-default-secret": (
        "A secret/token is read from the environment with an empty-string "
        "default — when the env var is unset the server runs with no credential"
    ),
    "warn-only-auth-gate": (
        "Missing-secret check only logs a warning and continues, while the "
        "server binds a non-loopback interface — unauthenticated network access"
    ),
    "auth-disabled-config": (
        "MCP config switches authentication off by flag (`auth.enabled: false` "
        "/ `is_enabled: false` / `disable_auth: true`) while binding a "
        "non-loopback interface — every caller is an administrator. "
        "CVE-2026-90898 (Bifrost) shipped exactly this default"
    ),
    "placeholder-secret-config": (
        "MCP config sets a secret/token to a default/placeholder (or empty) "
        "value while binding a non-loopback interface — unauthenticated by "
        "default"
    ),
}


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for MCP servers that are unauthenticated-by-default / fail open.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for path in project_root.rglob("*"):
        if path.suffix not in _PY_SUFFIXES + _CONFIG_SUFFIXES:
            continue
        if in_skip_dir(path, project_root):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        hits = (
            _scan_python(text) if path.suffix in _PY_SUFFIXES
            else _scan_config(text)
        )
        if not hits:
            continue

        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        seen_arms: set[str] = set()
        for line, arm in hits:
            if arm in seen_arms:
                continue
            seen_arms.add(arm)
            findings.append(make_finding(
                _RULE_ID,
                rel_path,
                f"{_EVIDENCE[arm]} (CVE-2026-48814, CWE-306/862).",
                line,
            ))

    return findings, scanned_files
