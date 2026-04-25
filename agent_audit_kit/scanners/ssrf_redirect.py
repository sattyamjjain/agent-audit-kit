"""AAK-LANGCHAIN-SSRF-REDIR-001 — validate-then-redirect SSRF (CVE-2026-41481).

`langchain-text-splitters` < 1.1.2 shipped this exact pattern in
`HTMLHeaderTextSplitter.split_text_from_url()`:

    if not validate_safe_url(url):
        raise ValueError(...)
    response = requests.get(url)            # redirects enabled by default

The allow-list check fires once on the URL the caller gave us, but
`requests` will silently follow a 302 to `http://169.254.169.254/...`
and pull the metadata back into the parsed Document. The fix in 1.1.2
disables redirects (or revalidates each hop). Same shape applies to
any agent-tooling code that does
`validate_safe_url`-style → fetch-without-redirect-control.

Two detections:

1. AAK-LANGCHAIN-SSRF-REDIR-001 (HIGH) — pattern check on Python
   sources: a known SSRF guard helper is called, and the same value
   flows into `requests.get/.post`, `urllib.request.urlopen`, `httpx.get`,
   `aiohttp.ClientSession.get`, or `httpx.AsyncClient.get` without
   `allow_redirects=False` / `follow_redirects=False`. We also accept
   `Session` objects whose `max_redirects = 0` is set near the call site.
   TS / JS variant: a fetch helper called after a `validateSafeUrl` /
   `validateUrl` allow-list helper without `redirect: 'manual'` or
   `redirect: 'error'`.
2. AAK-LANGCHAIN-SSRF-REDIR-001 (HIGH) — pin check on
   `langchain-text-splitters < 1.1.2`.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, find_line_number, make_finding


_PY_PATCHED = (1, 1, 2)
_SEMVER_RE = re.compile(r"[^\d]*(\d+)\.(\d+)(?:\.(\d+))?")
_REQ_LINE_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.\-]+)\s*(?P<op>==|>=|<=|~=|!=|>|<)?\s*(?P<ver>[0-9][0-9A-Za-z.\-+]*)?"
)

# Names of allow-list/SSRF-guard helpers we recognise. Anything that
# matches one of these followed by a fetch is a candidate.
_VALIDATOR_NAMES = frozenset({
    "validate_safe_url",
    "validate_url",
    "is_safe_url",
    "ensure_safe_url",
    "check_safe_url",
    "ssrf_guard",
    "is_url_safe",
})

# Function names we treat as URL fetchers. We match the *attribute* name
# rather than the full dotted path so `requests.get` / `httpx.get` /
# `await client.get(...)` / `session.get(...)` all hit.
_FETCH_NAMES = frozenset({
    "get",
    "post",
    "put",
    "delete",
    "request",
    "urlopen",
    "fetch",
    "send",
})

# Keyword arguments that indicate the caller has disabled or controls
# redirect handling.
_REDIRECT_OFF_KWARGS = frozenset({
    "allow_redirects",
    "follow_redirects",
    "max_redirects",
    "redirect",
})


_TS_VALIDATOR_RE = re.compile(
    r"\b(?:validateSafeUrl|validateUrl|isSafeUrl|ensureSafeUrl|ssrfGuard)\s*\("
)
_TS_FETCH_RE = re.compile(
    r"""
    \b(?:
        fetch\s*\(
      | axios\s*\.\s*(?:get|post|put|delete|request)\s*\(
      | got\s*(?:\.\s*\w+)?\s*\(
      | request\s*(?:\.\s*\w+)?\s*\(
    )
    """,
    re.VERBOSE,
)
_TS_REDIRECT_OFF_RE = re.compile(
    r"redirect\s*:\s*['\"](?:manual|error)['\"]|maxRedirects\s*:\s*0"
)


def _parse_semver(spec: str | None) -> tuple[int, int, int] | None:
    if not spec:
        return None
    m = _SEMVER_RE.match(str(spec))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


# ---------------------------------------------------------------------------
# Pattern (Python) — AST walk for validate→fetch
# ---------------------------------------------------------------------------


def _attr_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _is_redirect_disabled(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg not in _REDIRECT_OFF_KWARGS or kw.arg is None:
            continue
        # `allow_redirects=False` / `follow_redirects=False`
        if kw.arg in ("allow_redirects", "follow_redirects"):
            if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return True
        # `max_redirects=0`
        if kw.arg == "max_redirects":
            if isinstance(kw.value, ast.Constant) and kw.value.value == 0:
                return True
        # `redirect="manual"` / `redirect="error"`
        if kw.arg == "redirect":
            if isinstance(kw.value, ast.Constant) and kw.value.value in ("manual", "error"):
                return True
    return False


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    try:
        tree = ast.parse(text, str(path))
    except SyntaxError:
        return []

    findings: list[Finding] = []

    class FuncVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._scan_block(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._scan_block(node)
            self.generic_visit(node)

        def _scan_block(self, func: ast.AST) -> None:
            # Collect all Call nodes inside this function, sorted by
            # (lineno, col_offset). ast.walk is BFS so we cannot rely on
            # walk-order to reflect source order.
            calls: list[ast.Call] = [
                node for node in ast.walk(func) if isinstance(node, ast.Call)
            ]
            calls.sort(key=lambda c: (c.lineno, c.col_offset))

            validator_seen = False
            validator_line = 0
            for child in calls:
                callee = _attr_name(child.func)
                if callee in _VALIDATOR_NAMES:
                    validator_seen = True
                    validator_line = child.lineno
                    continue
                if not validator_seen:
                    continue
                if callee not in _FETCH_NAMES:
                    continue
                if _is_redirect_disabled(child):
                    continue
                rel = str(path.relative_to(project_root))
                scanned.add(rel)
                findings.append(make_finding(
                    "AAK-LANGCHAIN-SSRF-REDIR-001",
                    rel,
                    f"validate-then-fetch SSRF: SSRF guard at line "
                    f"{validator_line} is followed by a {callee}() "
                    "call that does not disable redirects "
                    "(CVE-2026-41481 shape).",
                    line_number=child.lineno,
                ))
                return  # one finding per function

    FuncVisitor().visit(tree)
    return findings


def _walk_ts(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for vmatch in _TS_VALIDATOR_RE.finditer(text):
        # Look ahead: is there a fetch within the next 2KB that does NOT
        # disable redirects?
        window = text[vmatch.end() : vmatch.end() + 2048]
        fmatch = _TS_FETCH_RE.search(window)
        if fmatch is None:
            continue
        # Search for redirect-off marker anywhere in the same window.
        if _TS_REDIRECT_OFF_RE.search(window[: fmatch.end() + 256]):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        line = text.count("\n", 0, vmatch.start() + fmatch.start()) + 1
        findings.append(make_finding(
            "AAK-LANGCHAIN-SSRF-REDIR-001",
            rel,
            "validate-then-fetch SSRF (TS): SSRF guard followed by a "
            "fetch/axios/got call without `redirect: 'manual'`/'error' "
            "or `maxRedirects: 0` (CVE-2026-41481 shape).",
            line_number=line,
        ))
        return findings  # one per file is plenty
    return findings


def _check_pattern(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        suffix = path.suffix
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if suffix == ".py":
            findings.extend(_walk_python(text, path, project_root, scanned))
        elif suffix in (".ts", ".tsx", ".js", ".mjs", ".cjs"):
            findings.extend(_walk_ts(text, path, project_root, scanned))
    return findings


# ---------------------------------------------------------------------------
# Pin check — langchain-text-splitters < 1.1.2
# ---------------------------------------------------------------------------


def _check_pin(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    def _fire(rel: str, raw: str, line: int | None) -> None:
        findings.append(make_finding(
            "AAK-LANGCHAIN-SSRF-REDIR-001",
            rel,
            f"langchain-text-splitters pinned at {raw!r} — "
            "CVE-2026-41481 SSRF redirect bypass is patched in 1.1.2.",
            line_number=line,
        ))

    for req in project_root.glob("requirements*.txt"):
        try:
            text = req.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(req.relative_to(project_root))
        for lineno, line in enumerate(text.splitlines(), 1):
            raw = line.split("#", 1)[0].strip()
            if not raw:
                continue
            m = _REQ_LINE_RE.match(raw)
            if not m:
                continue
            name = (m.group("name") or "").lower()
            if name != "langchain-text-splitters":
                continue
            ver = m.group("ver")
            parsed = _parse_semver(ver)
            if parsed is None or parsed < _PY_PATCHED:
                scanned.add(rel)
                _fire(rel, ver or "<no-version>", lineno)

    pyproject = project_root / "pyproject.toml"
    if pyproject.is_file():
        try:
            text = pyproject.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for m in re.finditer(
            r"""['"]langchain-text-splitters['"]?\s*[=<>~]=?\s*['"]?([0-9][0-9A-Za-z.\-+]*)['"]?""",
            text,
        ):
            parsed = _parse_semver(m.group(1))
            if parsed and parsed < _PY_PATCHED:
                scanned.add("pyproject.toml")
                _fire("pyproject.toml", m.group(1), find_line_number(text, m.group(0)))

    for lock_name in ("poetry.lock", "Pipfile.lock", "uv.lock"):
        lock = project_root / lock_name
        if not lock.is_file():
            continue
        try:
            text = lock.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(
            r"""(?:name|package)\s*=\s*['"]langchain-text-splitters['"][^\n]*\n[^\n]*?version\s*=\s*['"]([0-9][0-9A-Za-z.\-+]*)['"]""",
            text,
            re.IGNORECASE,
        ):
            parsed = _parse_semver(m.group(1))
            if parsed and parsed < _PY_PATCHED:
                rel = lock_name
                scanned.add(rel)
                _fire(rel, m.group(1), find_line_number(text, m.group(0)))

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    findings.extend(_check_pattern(project_root, scanned))
    findings.extend(_check_pin(project_root, scanned))
    return findings, scanned
