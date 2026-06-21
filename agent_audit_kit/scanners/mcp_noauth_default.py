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
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS

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


def _body_is_warn_only(body: list[ast.stmt]) -> bool:
    """True if the branch warns/logs and then *continues* — no raise / return /
    sys.exit / abort that would stop unauthenticated execution."""
    saw_warn = False
    for stmt in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(stmt, (ast.Raise, ast.Return)):
            return False
        if isinstance(stmt, ast.Call):
            name = ast.unparse(stmt.func) if hasattr(ast, "unparse") else ""
            if "exit" in name or "abort" in name:
                return False
            if _WARN_CALL_RE.search(name):
                saw_warn = True
    return saw_warn


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
            if fn in ("os.environ.get", "os.getenv") and len(value.args) >= 2:
                default = value.args[1]
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
_CFG_SECRET_KV_RE = re.compile(
    r"[\"']?[\w-]*(?:secret|token|api[_-]?key|apikey|password|auth[_-]?key)[\w-]*[\"']?"
    r"[ \t]*[:=][ \t]*"
    r"(?:"
    rf"[\"'](?:{_WEAK_CFG_WORDS}|)[\"']"          # quoted weak word, or empty ""
    rf"|(?:{_WEAK_CFG_WORDS})(?=[\s,}}\]]|$)"      # unquoted weak word at a boundary
    r")",
    re.IGNORECASE | re.MULTILINE,
)


def _scan_config(text: str) -> list[tuple[int, str]]:
    if not _MCP_HINT_RE.search(text):
        return []
    if not _BIND_NONLOOPBACK_RE.search(text):
        return []
    m = _CFG_SECRET_KV_RE.search(text)
    if not m:
        return []
    return [(text.count("\n", 0, m.start()) + 1, "placeholder-secret-config")]


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
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
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
