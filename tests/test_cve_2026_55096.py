"""CVE-2026-55096 (#853, #855): fast-mcp-telegram before 0.30.1, a hostname-only SSRF guard.

NVD: "Downloads are guarded by _validate_url_security, an SSRF denylist that
checks the URL's literal hostname string but never resolves DNS. The fetch
(httpx.AsyncClient.get) does its own resolution at request time."

Two answers, both measured:

- The version pin `AAK-MCP-FASTMCPTELEGRAM-CVE-2026-55096-001` reports releases
  below 0.30.1 (see tests/test_mcp_cve_pins_2026_07.py).
- `AAK-SSRF-TOCTOU-001` names the class, a guard on the hostname and then a
  fetch that resolves again. Until #855 it missed the upstream code: its name
  track was anchored at `^validate_...`, so the leading underscore of
  `_validate_url_security` hid the guard. Names are matched with leading
  underscores stripped now, and the CVE is on that rule.

The class rule does not clear at 0.30.1, and should not. That release resolves
the name inside the guard (fix e6b3032c), but `file_handling.py` is unchanged and
the fetch resolves the name a second time, which is the DNS-rebind window the rule
is named for. The pin is the rule that clears at 0.30.1.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.ssrf_toctou import _is_validator_name, scan

FIXTURE = (
    Path(__file__).parent / "fixtures" / "cves" / "cve-2026-55096-fast-mcp-telegram" / "hostname-guard"
)
TOCTOU = "AAK-SSRF-TOCTOU-001"
PIN = "AAK-MCP-FASTMCPTELEGRAM-CVE-2026-55096-001"

# Upstream's layout: the guard in src/tools/messages/security.py, the download in
# file_handling.py, which imports it. The call site is the same in 0.30.0 and 0.30.1.
_FILE_HANDLING = '''\
import httpx

from src.tools.messages.security import _validate_url_security


async def _download_single_file(http_client: httpx.AsyncClient, url: str) -> bytes:
    is_safe, error_msg = _validate_url_security(url)
    if not is_safe:
        raise ValueError(f"Unsafe URL blocked: {error_msg}")
    response = await http_client.get(url, follow_redirects=False)
    return response.content
'''

# 0.30.0: the literal hostname against a denylist, never resolved.
_GUARD_0_30_0 = '''\
import ipaddress
from urllib.parse import urlparse


def _validate_url_security(url: str) -> tuple[bool, str]:
    hostname = urlparse(url).hostname or ""
    if hostname.lower() in {"localhost", "127.0.0.1", "::1"}:
        return False, f"Localhost access blocked: {hostname}"
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return True, ""
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False, f"Private IP access blocked: {hostname}"
    return True, ""
'''

# 0.30.1 (fix e6b3032c): the guard resolves and checks every address it gets.
_GUARD_0_30_1 = '''\
import ipaddress
import socket
from urllib.parse import urlparse


def _validate_url_security(url: str) -> tuple[bool, str]:
    hostname = urlparse(url).hostname or ""
    try:
        addrinfo = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return False, f"DNS resolution failed for: {hostname}"
    for _family, _type, _proto, _canonname, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False, f"Private IP blocked after DNS resolution: {hostname}"
    return True, ""
'''


def _upstream_tree(root: Path, guard: str) -> Path:
    pkg = root / "src" / "tools" / "messages"
    pkg.mkdir(parents=True)
    (pkg / "security.py").write_text(guard, encoding="utf-8")
    (pkg / "file_handling.py").write_text(_FILE_HANDLING, encoding="utf-8")
    return root


def test_the_pin_carries_the_cve() -> None:
    assert RULES[PIN].cve_references == ["CVE-2026-55096"]


def test_the_class_rule_claims_it_now() -> None:
    """A CVE on a rule is a coverage claim, made once the fixture below fired (#855)."""
    assert "CVE-2026-55096" in RULES[TOCTOU].cve_references


def test_the_upstream_guard_fires() -> None:
    """The 0.30.0 shape, one file: a guard that never resolves, then httpx resolves."""
    findings, _ = scan(FIXTURE)
    assert [(f.rule_id, f.line_number) for f in findings] == [(TOCTOU, 49)]
    assert TOCTOU in {f.rule_id for f in run_scan(FIXTURE).findings}


def test_a_private_and_a_public_name_are_the_same_guard(tmp_path: Path) -> None:
    """The miss was the name track alone: with the underscore gone it fired before."""
    text = (FIXTURE / "server.py").read_text(encoding="utf-8")
    (tmp_path / "server.py").write_text(
        text.replace("_validate_url_security", "validate_url_security"), encoding="utf-8"
    )
    findings, _ = scan(tmp_path)
    assert [f.rule_id for f in findings] == [TOCTOU]


def test_a_guard_imported_from_another_module_fires_on_the_fetch(tmp_path: Path) -> None:
    """Upstream's two-file layout, 0.30.0: the body track cannot see across files,
    so the guard's name is what has to carry it."""
    findings, _ = scan(_upstream_tree(tmp_path, _GUARD_0_30_0))
    assert [(f.rule_id, f.file_path, f.line_number) for f in findings] == [
        (TOCTOU, str(Path("src/tools/messages/file_handling.py")), 10)
    ]


def test_0_30_1_still_fires_because_the_fetch_resolves_again(tmp_path: Path) -> None:
    """Resolving inside the guard closes the CVE, not the rebind window: httpx
    resolves the name again at connect time, the CVE-2026-41488 shape."""
    findings, _ = scan(_upstream_tree(tmp_path, _GUARD_0_30_1))
    assert [(f.rule_id, f.file_path) for f in findings] == [
        (TOCTOU, str(Path("src/tools/messages/file_handling.py")))
    ]


def test_a_guard_that_resolves_once_and_pins_the_ip_stays_quiet(tmp_path: Path) -> None:
    """The fix the rule asks for: resolve once, check that address, fetch that address."""
    (tmp_path / "server.py").write_text(
        '''\
import ipaddress
import socket
from urllib.parse import urlparse


def _validate_url_security(url: str) -> str:
    hostname = urlparse(url).hostname or ""
    resolved_ip = socket.getaddrinfo(hostname, None)[0][4][0]
    ip = ipaddress.ip_address(resolved_ip)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError(f"Private IP blocked after DNS resolution: {hostname}")
    return resolved_ip


async def _download_single_file(http_client, url: str) -> bytes:
    resolved_ip = _validate_url_security(url)
    host = urlparse(url).hostname
    response = await http_client.get(
        url.replace(host, resolved_ip, 1), headers={"Host": host}, extensions={"sni_hostname": host}
    )
    return response.content
''',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert findings == []


def test_underscored_ordinary_names_are_still_not_guards() -> None:
    """Stripping the underscore must not widen what counts as a guard."""
    for name in ("_validate_payload", "_check_quota", "__is_admin", "_fetch_url", "_get", "_", "__"):
        assert not _is_validator_name(name), name
