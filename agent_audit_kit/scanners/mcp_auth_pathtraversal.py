"""MCP bearer-token → session-file path-traversal scanner — CVE-2026-52830.

Flags MCP server authentication code where an **untrusted token / credential
string** (a bearer token, `Authorization` header, or an auth-function parameter)
is concatenated or ``os.path.join``-ed into a **filesystem path** that is then
used for a session existence / read check — **without** rejecting path
separators / ``..`` or resolving-and-containing the result. An attacker who
controls the token controls the path, so a value like ``../../etc/passwd`` or
``../<other-user-session>`` escapes the intended session directory.

Anchor: **CVE-2026-52830** (CVSS 9.4, CWE-22 Path Traversal) — `fast-mcp-telegram`
before 0.19.1 joined the caller-supplied bearer token straight into the session
file path used to check whether a session existed, so a crafted token traversed
out of the session directory. Fixed in 0.19.1.

Detection (Python, stdlib ``ast`` — the same taint mechanism the repo uses; no
new engine):
  1. **Source** — a value read from a request header / bearer token, or a
     parameter of an auth/session-style function whose name looks like a
     token/credential (``token``, ``bearer``, ``auth``, ``credential``,
     ``api_key``, ``session_id``).
  2. **Flow into a path** — that tainted value reaches ``os.path.join(...)``,
     ``Path(...) / token``, ``pathlib`` division, or an f-string / ``+``
     concatenation that builds a path-like string.
  3. **Sink** — the constructed path reaches ``os.path.exists`` / ``os.path.isfile``
     / ``open`` / ``Path.exists`` / ``Path.is_file`` / ``Path.open`` / ``os.stat``.
  4. **Suppressed** when the file also normalizes / rejects: a separator or
     ``..`` check on the token (``"/" in token`` / ``".." in token`` /
     ``os.sep``), ``os.path.normpath`` + ``startswith`` containment,
     ``os.path.realpath`` / ``os.path.abspath`` + containment, ``Path.resolve()``
     + ``is_relative_to`` / ``relative_to``, or ``werkzeug``'s
     ``secure_filename``.

TS / JS / Rust servers use an analogous comment-stripped regex: a request-token
value concatenated (``path.join`` / template literal / ``format!`` /
``PathBuf.push``) into a path with an ``exists`` / ``open`` / ``read`` sink and
no separator/normalize guard.

FP guards: a separator-rejected + resolved-and-contained flow, a constant path,
and non-auth code all PASS.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS

_RULE_ID = "AAK-MCP-AUTH-PATHTRAVERSAL-001"

# The file must look like MCP server auth/session code at all.
_MCP_HINT_RE = re.compile(
    r"\bmcp\b|modelcontextprotocol|FastMCP|McpServer|Bearer|Authorization"
    r"|session|token",
    re.IGNORECASE,
)
# Token / credential source names (parameters + variables).
_TOKEN_NAME_RE = re.compile(
    r"^(?:.*_)?(?:token|bearer|auth|authorization|credential|creds?|api[_-]?key"
    r"|apikey|session[_-]?id|secret)s?$",
    re.IGNORECASE,
)
# Reading a value from a request header / bearer extraction.
_HEADER_SOURCE_RE = re.compile(
    r"headers|get_header|authorization|bearer|request\.", re.IGNORECASE
)
# Normalization / rejection markers that clear the finding.
_GUARD_RE = re.compile(
    r"secure_filename|is_relative_to|relative_to|normpath|realpath|abspath"
    r"|os\.sep|commonpath|commonprefix|\.\.|startswith|resolve\s*\("
    r"|\bsep\b|split\s*\(\s*['\"][/\\]",
    re.IGNORECASE,
)

# Path-construction callees.
_PATH_JOIN = {"os.path.join", "join", "posixpath.join", "ntpath.join"}
_PATH_CTORS = {"Path", "pathlib.Path", "PurePath"}
# Existence / read sinks.
_PATH_SINK_ATTRS = {"exists", "isfile", "is_file", "isdir", "stat", "open", "read_text", "read_bytes", "lexists"}
_PATH_SINK_FULL = {"os.path.exists", "os.path.isfile", "os.path.isdir",
                   "os.path.lexists", "os.stat", "open"}

_PY_SUFFIXES = (".py",)
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_RUST_SUFFIXES = (".rs",)


# ---------------------------------------------------------------------------
# Python (AST)
# ---------------------------------------------------------------------------


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _is_token_source_expr(value: ast.AST) -> bool:
    """True if expr reads a token from a request header / bearer extraction."""
    try:
        src = ast.unparse(value)
    except Exception:
        return False
    return bool(_HEADER_SOURCE_RE.search(src) and _TOKEN_NAME_RE.search(
        # last identifier-ish token in the expr, best effort
        (re.findall(r"[A-Za-z_][\w]*", src) or [""])[-1]
    )) or bool(re.search(r"headers.*(auth|bearer|token)", src, re.IGNORECASE))


def _collect_tainted(tree: ast.AST, seed: set[str]) -> set[str]:
    """Names bound (directly or transitively) to a token source."""
    tainted = set(seed)
    assigns = [n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign))]
    for _ in range(6):
        changed = False
        for node in assigns:
            value = getattr(node, "value", None)
            if value is None:
                continue
            targets: list[str] = []
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        targets.append(t.id)
            elif isinstance(node.target, ast.Name):
                targets.append(node.target.id)
            if not targets:
                continue
            refs_tainted = any(
                isinstance(x, ast.Name) and x.id in tainted for x in ast.walk(value)
            )
            if _is_token_source_expr(value) or refs_tainted:
                for name in targets:
                    if name not in tainted:
                        tainted.add(name)
                        changed = True
        if not changed:
            break
    return tainted


def _expr_uses_tainted(node: ast.AST, tainted: set[str]) -> bool:
    return any(isinstance(x, ast.Name) and x.id in tainted for x in ast.walk(node))


def _builds_path_from_token(node: ast.AST, tainted: set[str]) -> bool:
    """True if this expr builds a path-like value that includes a tainted token:
    os.path.join(..token..), Path(..)/token, f"{dir}/{token}", dir + token."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            name = _attr_chain(sub.func)
            short = name.split(".")[-1]
            if (name in _PATH_JOIN or short == "join" or name in _PATH_CTORS
                    or short in {"Path", "PurePath"}):
                if any(_expr_uses_tainted(a, tainted) for a in sub.args):
                    return True
        # Path(...) / token  or  base / token
        if isinstance(sub, ast.BinOp) and isinstance(sub.op, (ast.Div, ast.Add)):
            if _expr_uses_tainted(sub, tainted):
                # at least one side references a dir-ish / Path expr
                blob = ""
                try:
                    blob = ast.unparse(sub)
                except Exception:
                    pass
                if isinstance(sub.op, ast.Div) or re.search(r"path|dir|Path|\.session|/", blob):
                    return True
        # f-string containing a tainted name and a path separator
        if isinstance(sub, ast.JoinedStr):
            has_tokq = any(
                isinstance(v, ast.FormattedValue) and _expr_uses_tainted(v.value, tainted)
                for v in sub.values
            )
            has_sep = any(
                isinstance(v, ast.Constant) and isinstance(v.value, str) and ("/" in v.value or "\\" in v.value)
                for v in sub.values
            )
            if has_tokq and has_sep:
                return True
    return False


def _scan_python(text: str) -> int | None:
    if not _MCP_HINT_RE.search(text):
        return None
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None

    # Analyse per-function so a token PARAMETER counts as a source and a guard
    # in the same function suppresses.
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # seed: parameters whose name looks like a token/credential
        seed = {a.arg for a in fn.args.args + fn.args.kwonlyargs if _TOKEN_NAME_RE.search(a.arg)}
        tainted = _collect_tainted(fn, seed)
        if not tainted:
            continue

        fn_src = ""
        try:
            fn_src = ast.unparse(fn)
        except Exception:
            pass
        guarded = bool(_GUARD_RE.search(fn_src))

        # names bound to a path built from the token
        path_vars: set[str] = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if _builds_path_from_token(node.value, tainted):
                    path_vars.add(node.targets[0].id)

        # sink: exists/open/etc reached by a path built from the token
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            name = _attr_chain(node.func)
            attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            is_sink = name in _PATH_SINK_FULL or attr in _PATH_SINK_ATTRS
            if not is_sink:
                continue
            reaches = False
            for arg in node.args:
                if _builds_path_from_token(arg, tainted) or _expr_uses_tainted(arg, tainted & path_vars):
                    reaches = True
                if any(isinstance(x, ast.Name) and x.id in path_vars for x in ast.walk(arg)):
                    reaches = True
            # Path(...).exists() — receiver built from token, directly or via a
            # path var (`p = Path(dir) / token; p.exists()`).
            if isinstance(node.func, ast.Attribute):
                recv = node.func.value
                if _builds_path_from_token(recv, tainted):
                    reaches = True
                if isinstance(recv, ast.Name) and recv.id in path_vars:
                    reaches = True
            if reaches and not guarded:
                return node.lineno
    return None


# ---------------------------------------------------------------------------
# TS / JS / Rust (comment-stripped regex)
# ---------------------------------------------------------------------------

_TS_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE = re.compile(r"//[^\n]*")


def _strip_comments(text: str) -> str:
    text = _TS_BLOCK.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    return _TS_LINE.sub("", text)


# token var built into a path via join/template/concat, then an fs check.
_PATH_TOKEN_RE = re.compile(
    r"(?:path\.join|join!|PathBuf|format!|`[^`]*\$\{)[^\n;]*"
    r"\b(?:token|bearer|auth|authorization|credential|sessionId|session_id|apiKey|api_key)\b",
    re.IGNORECASE,
)
_FS_SINK_RE = re.compile(
    r"existsSync|fs\.exists|fs\.access|readFile|createReadStream|openSync"
    r"|\.exists\(\)|std::fs::|File::open|Path::new",
    re.IGNORECASE,
)


def _scan_regex(text: str) -> int | None:
    if not _MCP_HINT_RE.search(text):
        return None
    text = _strip_comments(text)
    if _GUARD_RE.search(text):
        return None
    m = _PATH_TOKEN_RE.search(text)
    if not m:
        return None
    if not _FS_SINK_RE.search(text):
        return None
    return text.count("\n", 0, m.start()) + 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for MCP bearer-token → session-file path traversal (CVE-2026-52830).

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for path in project_root.rglob("*"):
        suf = path.suffix
        if suf not in _PY_SUFFIXES + _TS_SUFFIXES + _RUST_SUFFIXES:
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

        line = _scan_python(text) if suf in _PY_SUFFIXES else _scan_regex(text)
        if line is None:
            continue

        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.append(make_finding(
            _RULE_ID,
            rel_path,
            (
                "An untrusted token / bearer credential is joined into a "
                "filesystem path used for a session existence/read check with "
                "no path-separator rejection or resolve-and-contain guard — a "
                "crafted token traverses out of the session directory "
                "(CVE-2026-52830, CWE-22)."
            ),
            line,
        ))

    return findings, scanned_files
