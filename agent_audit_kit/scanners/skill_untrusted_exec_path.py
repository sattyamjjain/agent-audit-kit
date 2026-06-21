"""Untrusted-search-path executable override in skill/install flows — CWE-426.

Flags install / skill-setup code that resolves an **executable, interpreter, or
build tool from a workspace-controlled source** and then runs it, with no
absolute-path pin or allowlist. The system then executes whatever binary the
workspace points at instead of the intended one.

Anchor: **CVE-2026-53819** (CWE-426 Untrusted Search Path, CVSS 8.7). Per NVD,
"OpenClaw before 2026.5.27 contains an arbitrary code execution vulnerability in
skill install flows where workspace ``.env`` files can override the Homebrew
executable selection ... execute unintended Homebrew-compatible executables
during skill setup to compromise the system."

Untrusted-binary sources detected:
  * a ``.env`` / dotenv-sourced variable (``load_dotenv()`` then
    ``os.environ.get(...)`` / ``os.getenv(...)`` / ``dotenv_values(...)[...]``)
    used as the command;
  * a ``PATH`` prepended with a non-absolute / workspace dir
    (``os.environ["PATH"] = os.getcwd() + os.pathsep + ...``);
  * ``shutil.which(...)`` resolved over such a tainted ``PATH``;
  * a Homebrew / package-manager binary chosen via env override
    (``HOMEBREW_*`` / ``BREW`` env var, or a bare ``brew`` run over a tainted
    PATH).

FP guards: an absolute-path-pinned binary (``/opt/homebrew/bin/brew``), an
``os.path.isabs`` / allowlist check, or a non-install file all PASS. Python is
analysed with stdlib ``ast``; shell install scripts use a guarded regex.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

_RULE_ID = "AAK-SKILL-UNTRUSTED-EXEC-PATH"

# Install / skill-setup context — required so this does not fire on arbitrary
# application code that reads an env var. Matched on filename OR content.
_INSTALL_NAME_RE = re.compile(
    r"install|setup|bootstrap|provision|post[_-]?install|skill", re.IGNORECASE
)
_INSTALL_CONTENT_RE = re.compile(
    r"SKILL\.md|skill[_\s-]*install|post[_-]?install|load_dotenv|dotenv_values"
    r"|homebrew|\bbrew\b|HOMEBREW",
    re.IGNORECASE,
)

# Subprocess / exec sinks whose command we evaluate.
_EXEC_ATTRS = {
    "run", "popen", "call", "check_call", "check_output", "getoutput",
    "getstatusoutput",
}
_OS_EXEC_ATTRS = {
    "system", "popen", "execv", "execve", "execvp", "execvpe", "execl",
    "execle", "execlp", "execlpe", "spawnv", "spawnl",
}

# Allowlist / absolute-pin markers that clear the file.
_PIN_RE = re.compile(
    r"os\.path\.isabs|allow[_-]?list|allowlist|ALLOWED_(?:BINARIES|EXECUTABLES|PATHS)",
)

# Shell: a PATH prepend with a non-absolute element, or sourcing a workspace .env.
_SH_TAINT_PATH_RE = re.compile(
    r"export\s+PATH=(?![\"']?/)[^\n]*:\$PATH"     # PATH=<non-abs>:$PATH
    r"|PATH=\.[:/]"                                 # PATH=.: or PATH=./...
    r"|export\s+PATH=\$\(pwd\)|export\s+PATH=\$PWD",
)
_SH_SOURCE_ENV_RE = re.compile(r"(?:^|\s)(?:source|\.)\s+\.?/?\.env\b", re.MULTILINE)
_SH_BREW_EXEC_RE = re.compile(r"(?<![/\w])(?:brew|npm|node|pip|python|uv)\b")

_PY_SUFFIXES = (".py",)
_SH_SUFFIXES = (".sh", ".bash")


# ---------------------------------------------------------------------------
# Python (AST)
# ---------------------------------------------------------------------------


def _attr_chain(node: ast.AST) -> str:
    """Return a dotted name for an attribute/name expr (best effort)."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _is_env_source(value: ast.AST) -> bool:
    """True if expr reads a value from the process environment / dotenv."""
    for sub in ast.walk(value):
        if isinstance(sub, ast.Call):
            name = _attr_chain(sub.func)
            if name in ("os.environ.get", "os.getenv", "getenv", "dotenv_values"):
                return True
        if isinstance(sub, ast.Subscript):
            base = _attr_chain(sub.value)
            if base in ("os.environ", "environ"):
                return True
    return False


def _is_shutil_which(value: ast.AST) -> bool:
    for sub in ast.walk(value):
        if isinstance(sub, ast.Call) and _attr_chain(sub.func) in (
            "shutil.which", "which",
        ):
            return True
    return False


def _expr_has_abs_literal(value: ast.AST) -> bool:
    """True if expr is (or contains) an absolute-path string literal."""
    for sub in ast.walk(value):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if sub.value.startswith("/") or re.match(r"^[A-Za-z]:\\", sub.value):
                return True
    return False


def _path_is_tainted(tree: ast.AST) -> bool:
    """True if PATH is assigned a non-absolute / workspace-controlled value, or
    a dotenv loader (which can set PATH from a workspace .env) is invoked."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _attr_chain(node.func) in (
            "load_dotenv", "dotenv.load_dotenv",
        ):
            return True
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Subscript):
                    base = _attr_chain(tgt.value)
                    key = tgt.slice
                    keyval = key.value if isinstance(key, ast.Constant) else None
                    if base in ("os.environ", "environ") and keyval == "PATH":
                        # Pure absolute-literal reassignment is fine.
                        if not _expr_has_abs_literal(node.value) or any(
                            isinstance(s, (ast.Name, ast.Call))
                            for s in ast.walk(node.value)
                        ):
                            return True
    return False


def _command_expr(call: ast.Call) -> ast.AST | None:
    """The expression that resolves to the executable for a subprocess/os exec."""
    if call.args:
        first = call.args[0]
        # subprocess.run(["brew", ...]) -> argv[0]
        if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
            return first.elts[0]
        return first
    # executable= kwarg
    for kw in call.keywords:
        if kw.arg == "executable":
            return kw.value
    return None


def _scan_python(text: str) -> int | None:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None

    if _PIN_RE.search(text):
        return None

    # 1. Collect names bound to an untrusted binary source.
    env_bins: set[str] = set()
    which_bins: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            tgt = node.targets[0]
            if not isinstance(tgt, ast.Name):
                continue
            if _expr_has_abs_literal(node.value):
                continue  # explicitly pinned to an absolute path
            if _is_env_source(node.value):
                env_bins.add(tgt.id)
            elif _is_shutil_which(node.value):
                which_bins.add(tgt.id)

    path_tainted = _path_is_tainted(tree)

    # 2. Find an exec sink whose command resolves from an untrusted source.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = _attr_chain(node.func)
        is_sink = (
            fname.split(".")[-1] in _EXEC_ATTRS and "subprocess" in fname
        ) or fname in {f"os.{a}" for a in _OS_EXEC_ATTRS} or fname in (
            "os.system", "os.popen",
        )
        if not is_sink:
            continue
        cmd = _command_expr(node)
        if cmd is None:
            continue
        if _expr_has_abs_literal(cmd):
            continue  # command pinned to an absolute path

        # (a) command references an env-sourced binary var
        names = {s.id for s in ast.walk(cmd) if isinstance(s, ast.Name)}
        if names & env_bins:
            return node.lineno
        # (b) command is/uses a shutil.which result over a tainted PATH
        if (names & which_bins or _is_shutil_which(cmd)) and path_tainted:
            return node.lineno
        # (c) command read directly from the environment
        if _is_env_source(cmd):
            return node.lineno
        # (d) bare binary name resolved over a tainted PATH
        if path_tainted and isinstance(cmd, ast.Constant) and isinstance(cmd.value, str):
            if "/" not in cmd.value and cmd.value:
                return node.lineno
    return None


# ---------------------------------------------------------------------------
# Shell (regex)
# ---------------------------------------------------------------------------


def _scan_shell(text: str) -> int | None:
    if _PIN_RE.search(text):
        return None
    tainted = bool(_SH_TAINT_PATH_RE.search(text) or _SH_SOURCE_ENV_RE.search(text))
    if not tainted:
        return None
    # A build tool / brew invoked by bare name after the taint -> untrusted path.
    m = _SH_BREW_EXEC_RE.search(text)
    if m:
        return text.count("\n", 0, m.start()) + 1
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _in_install_context(path: Path, text: str) -> bool:
    return bool(_INSTALL_NAME_RE.search(path.name) or _INSTALL_CONTENT_RE.search(text))


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan install/skill-setup code for untrusted-search-path exec override.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for path in project_root.rglob("*"):
        if path.suffix not in _PY_SUFFIXES + _SH_SUFFIXES:
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

        if not _in_install_context(path, text):
            continue

        line = (
            _scan_python(text) if path.suffix in _PY_SUFFIXES
            else _scan_shell(text)
        )
        if line is None:
            continue

        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.append(make_finding(
            _RULE_ID,
            rel_path,
            (
                "Install/skill-setup code resolves an executable, interpreter, "
                "or build tool from a workspace-controlled source (a "
                "`.env`-sourced var, an env-overridden / non-absolute `PATH`, "
                "`shutil.which()` over a tainted PATH, or a Homebrew binary "
                "chosen via env) and runs it without an absolute-path pin — a "
                "workspace `.env` can override which binary executes during "
                "setup (CVE-2026-53819, CWE-426 Untrusted Search Path)."
            ),
            line or find_line_number(text, "PATH"),
        ))

    return findings, scanned_files
