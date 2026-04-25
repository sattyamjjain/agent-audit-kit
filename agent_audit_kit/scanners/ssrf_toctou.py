"""AAK-SSRF-TOCTOU-001 — DNS-rebind / TOCTOU on URL allow-list (CVE-2026-41488).

The pattern: validate a URL via an SSRF guard (which does its own DNS
resolution), then issue a separate fetch via `requests.get(url)` (which
does its own DNS resolution). Between the two resolutions a malicious
hostname can rotate from a public IP to a private one, defeating the
allow-list — that is the langchain-openai `_url_to_size` bug.

The fix in 1.1.14 resolves once, pins the IP, and reuses a `Session`
mounted with an `HTTPAdapter` that points at the resolved IP.

Detection: in a single function we see a guard call followed by a
fetch on a re-resolved hostname, with no IP-pinning marker between
them. Suppress when the function pins the IP via `socket.getaddrinfo`,
`HTTPAdapter`, `Host:` header, or a `pinned_ip` / `resolved_ip` symbol.

Pin check: `langchain-openai < 1.1.14`.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, find_line_number, make_finding


_PY_PATCHED = (1, 1, 14)
_SEMVER_RE = re.compile(r"[^\d]*(\d+)\.(\d+)(?:\.(\d+))?")
_REQ_LINE_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.\-]+)\s*(?P<op>==|>=|<=|~=|!=|>|<)?\s*(?P<ver>[0-9][0-9A-Za-z.\-+]*)?"
)


_VALIDATOR_NAMES = frozenset({
    "validate_safe_url",
    "validate_url",
    "is_safe_url",
    "ensure_safe_url",
    "check_safe_url",
    "ssrf_guard",
    "is_url_safe",
})

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

# Markers that prove the caller pinned the resolved IP and is therefore
# not subject to a second-DNS-resolution rebind.
_PIN_MARKERS_RE = re.compile(
    r"""
    (?:
        socket\.getaddrinfo
      | HTTPAdapter
      | session\.mount
      | session\.get_adapter
      | resolved_ip
      | pinned_ip
      | resolved_host
      | resolve_once
      | dns_pin
      | host_header_pin
      | requests\.adapters\.HTTPAdapter
    )
    """,
    re.VERBOSE,
)


def _parse_semver(spec: str | None) -> tuple[int, int, int] | None:
    if not spec:
        return None
    m = _SEMVER_RE.match(str(spec))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def _attr_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _func_source(
    text: str, func: ast.FunctionDef | ast.AsyncFunctionDef
) -> str:
    lines = text.splitlines()
    start = max(0, func.lineno - 1)
    end = min(len(lines), (func.end_lineno or func.lineno))
    return "\n".join(lines[start:end])


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

        def _scan_block(
            self, func: ast.FunctionDef | ast.AsyncFunctionDef
        ) -> None:
            calls = sorted(
                (n for n in ast.walk(func) if isinstance(n, ast.Call)),
                key=lambda c: (c.lineno, c.col_offset),
            )
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
                # Suppress if the function already pins the IP somewhere.
                if _PIN_MARKERS_RE.search(_func_source(text, func)):
                    return
                rel = str(path.relative_to(project_root))
                scanned.add(rel)
                findings.append(make_finding(
                    "AAK-SSRF-TOCTOU-001",
                    rel,
                    f"validate-then-fetch DNS-rebind: SSRF guard at "
                    f"line {validator_line} is followed by {callee}() "
                    "with a fresh DNS resolution (CVE-2026-41488 shape). "
                    "Resolve once, pin the IP, and reuse a Session "
                    "mounted on the resolved IP.",
                    line_number=child.lineno,
                ))
                return

    FuncVisitor().visit(tree)
    return findings


def _check_pattern(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in project_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_walk_python(text, path, project_root, scanned))
    return findings


def _check_pin(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    def _fire(rel: str, raw: str, line: int | None) -> None:
        findings.append(make_finding(
            "AAK-SSRF-TOCTOU-001",
            rel,
            f"langchain-openai pinned at {raw!r} — CVE-2026-41488 "
            "TOCTOU/DNS-rebind is patched in 1.1.14.",
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
            if name != "langchain-openai":
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
            r"""['"]langchain-openai['"]?\s*[=<>~]=?\s*['"]?([0-9][0-9A-Za-z.\-+]*)['"]?""",
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
            r"""(?:name|package)\s*=\s*['"]langchain-openai['"][^\n]*\n[^\n]*?version\s*=\s*['"]([0-9][0-9A-Za-z.\-+]*)['"]""",
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
