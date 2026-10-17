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

Guard recognition is two-track, because the original closed list of seven
names only matched guards named the way langchain-openai named its own.
`mcp-contextforge-gateway` < 1.0.3 (CVE-2026-53708 / GHSA-9hgc-g3w5-67cm)
calls its guard `validate_gateway_test_url`: it resolves the host, rejects
private ranges on `/admin/gateways/test`, and then hands the *hostname* to
an httpx client that resolves it a second time. Identical bug, different
name, and the allow-list said nothing. So a callee now counts as a guard
if either its **name** reads like a URL/host check, or its **body** in this
file both resolves a name and range-checks the result.

A leading underscore does not change what a guard is. `fast-mcp-telegram`
< 0.30.1 (CVE-2026-55096, #855) calls its guard `_validate_url_security`, a
module-private helper that checks the literal hostname and never resolves it,
then hands the URL to `httpx.AsyncClient.get`, which resolves the name itself.
The name track was anchored at `^validate_...`, so the underscore alone hid
the guard; names are now matched with leading underscores stripped. The body
track still needs the guard defined in the same file as the fetch, and
upstream's lives in another module, so the name is what finds it there.

Pin check: `langchain-openai < 1.1.14`. It took the first number after the
name, so `langchain-openai<1.1.14`, which admits only affected releases, read
as the fix and was silent, and the extras in `langchain-openai[x]==1.1.14` read
as a name with no version and fired. Manifests and lockfiles are now read as
the CVE pin table reads them (`_dependency_pins`), which also reads the
Pipfile.lock the lockfile pattern listed and never matched.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._dependency_pins import (
    DependencyPin,
    locked_affected_versions,
    pinned_dependency,
    read_lockfile,
    read_manifest,
    read_text,
)
from ._helpers import (
    in_skip_dir,
    make_finding,
    parse_python,
    refusing_overflow,
    source_lines,
    source_segment,
    walk_tree,
)
from ._manifest_deps import MAX_LOCKFILE_BYTES


_PY_PATCHED = (1, 1, 14)
# A bare name is reported too, as the requirements reader always reported one.
_PIN = DependencyPin(("langchain-openai",), _PY_PATCHED, ecosystem="py", report_unversioned=True)


_VALIDATOR_NAMES = frozenset({
    "validate_safe_url",
    "validate_url",
    "is_safe_url",
    "ensure_safe_url",
    "check_safe_url",
    "ssrf_guard",
    "is_url_safe",
})

# The closed set above only recognises guards that happen to be named the way
# langchain-openai named its own. Real projects name theirs after the thing they
# guard — `validate_gateway_test_url` in mcp-contextforge-gateway
# (CVE-2026-53708 / GHSA-9hgc-g3w5-67cm), which resolves the host, rejects
# private ranges, and then hands the *hostname* to an httpx client that resolves
# it a second time. Same bug, different name, and the allow-list missed it.
#
# Two ways in now: a name that reads like a URL/host guard, or (below) a callee
# defined in this file whose body actually resolves and range-checks.
_VALIDATOR_NAME_RE = re.compile(
    r"""
    ^(?:
        (?:validate|verify|check|ensure|assert|guard|sanitize|is)_\w*
        (?:url|uri|host|hostname|endpoint|address|target|gateway|ssrf)\w*
      | \w*(?:url|uri|host|hostname|endpoint|target)_\w*
        (?:valid|safe|allowed|check|guard)\w*
      | \w*ssrf\w*
    )$
    """,
    re.VERBOSE | re.IGNORECASE,
)

# A function body that resolves a name and tests the result against private /
# reserved ranges *is* an SSRF guard, whatever it is called.
_RESOLVES_RE = re.compile(
    r"\bsocket\.gethostbyname\b|\bsocket\.getaddrinfo\b|\bgethostbyname_ex\b"
    r"|\bdns\.resolver\b|\bresolver\.resolve\b"
)
_RANGE_CHECK_RE = re.compile(
    r"\bis_private\b|\bis_loopback\b|\bis_reserved\b|\bis_link_local\b"
    r"|\bip_address\s*\(|\bip_network\s*\(|\bBLOCKED_\w*|\bDENY_\w*|\bPRIVATE_\w*"
)


def _is_validator_name(name: str | None) -> bool:
    """True when `name` reads like a URL/host guard, leading underscores aside.

    `_validate_url_security` (fast-mcp-telegram < 0.30.1, CVE-2026-55096, #855)
    is the same check as `validate_url_security`; matched as written, the
    anchored pattern missed every module-private guard.
    """
    bare = (name or "").lstrip("_")
    if not bare:
        return False
    return bare in _VALIDATOR_NAMES or bool(_VALIDATOR_NAME_RE.match(bare))


def _guard_functions(tree: ast.AST, text: str) -> set[str]:
    """Names of functions in this file that resolve a host and range-check it.

    Catches a guard whose name gives nothing away, as long as its body does the
    two things that make it a guard.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = source_segment(text, node) or ""
        if _RESOLVES_RE.search(body) and _RANGE_CHECK_RE.search(body):
            names.add(node.name)
    return names

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


def _attr_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _func_source(
    text: str, func: ast.FunctionDef | ast.AsyncFunctionDef
) -> str:
    lines = source_lines(text)
    start = max(0, func.lineno - 1)
    end = min(len(lines), (func.end_lineno or func.lineno))
    return "\n".join(lines[start:end])


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    try:
        tree = parse_python(text, path)
    except SyntaxError:
        return []
    findings: list[Finding] = []
    body_guards = _guard_functions(tree, text)

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
                if _is_validator_name(callee) or callee in body_guards:
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

    walk_tree(FuncVisitor().visit, tree)
    return findings


def _check_pattern(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in project_root.rglob("*.py"):
        if in_skip_dir(path, project_root):
            continue
        text = read_text(path, 1_000_000)
        if text is None:
            continue
        with refusing_overflow(path):
            findings.extend(_walk_python(text, path, project_root, scanned))
    return findings


def _check_pin(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    def _fire(rel: str, how: str, line: int | None) -> None:
        findings.append(make_finding(
            "AAK-SSRF-TOCTOU-001",
            rel,
            f"langchain-openai {how} — "
            "CVE-2026-41488 TOCTOU/DNS-rebind is patched in 1.1.14.",
            line_number=line,
        ))

    # The root requirements files and pyproject.toml, read as the CVE pin table
    # reads them (`_dependency_pins`).
    manifests = sorted(project_root.glob("requirements*.txt"))
    if (project_root / "pyproject.toml").is_file():
        manifests.append(project_root / "pyproject.toml")
    for path in manifests:
        manifest = read_manifest(path)
        hit = pinned_dependency(manifest, _PIN) if manifest is not None else None
        if hit is not None:
            rel = str(path.relative_to(project_root))
            scanned.add(rel)
            _fire(rel, f"referenced as {hit.quoted}", hit.line)

    for lock_name in ("poetry.lock", "Pipfile.lock", "uv.lock"):
        # None when absent, unreadable or over MAX_LOCKFILE_BYTES, which the pin table skips too.
        lockfile = read_lockfile(project_root / lock_name, MAX_LOCKFILE_BYTES)
        affected = locked_affected_versions(lockfile, _PIN) if lockfile is not None else []
        if affected:
            scanned.add(lock_name)
            _fire(lock_name, f"pinned at {'.'.join(str(n) for n in affected[0])!r}", None)

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    findings.extend(_check_pattern(project_root, scanned))
    findings.extend(_check_pin(project_root, scanned))
    return findings, scanned
