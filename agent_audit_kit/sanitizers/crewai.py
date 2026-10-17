"""Runtime guards for AAK-CREWAI-CHAIN-2026-04-001.

CrewAI 0.x ships a Code-Interpreter tool, JSON loader, RAG tool and
Docker fallback that, in default configurations, chain into host RCE
when the agent ingests untrusted input. ThaiCERT 2026-04-02 + CERT/CC
VU#221883 disclosed four CVEs that exploit the chain:

    CVE-2026-2275  CodeInterpreterTool unsafe_mode + ctypes fallback
    CVE-2026-2285  JSONSearchTool path traversal
    CVE-2026-2286  RagTool / WebsiteSearchTool SSRF
    CVE-2026-2287  No Docker liveness check on sandbox fallback

Calling the helpers below in the same function as the CrewAI sink
suppresses the corresponding SAST rule (the scanner looks for the
import + call shape).
"""
from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlparse

from agent_audit_kit.scanners._helpers import host_ip, url_hosts


#: RFC 6598's shared address space. `ipaddress` calls it neither private nor
#: global, so no property names it; carrier-grade NAT and Alibaba Cloud's
#: metadata service (100.100.100.200) sit in it.
_SHARED_ADDRESS_SPACE = ipaddress.IPv4Network("100.64.0.0/10")
#: RFC 6052's well-known NAT64 prefix: a DNS64 resolver answers an IPv4-only
#: host with its address in the last 32 bits.
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
#: RFC 8215's local-use NAT64 prefix, read in RFC 6052's /48 form.
_NAT64_LOCAL = ipaddress.IPv6Network("64:ff9b:1::/48")
#: The deprecated IPv4-compatible block, `::a.b.c.d`.
_IPV4_COMPATIBLE = ipaddress.IPv6Network("::/96")


def _carried_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 one carries: NAT64 (`64:ff9b::/96`), local-use
    NAT64 (`64:ff9b:1::/48`), 6to4 (`2002::/16`, `.sixtofour`) or
    IPv4-compatible (`::/96`).

    In the /48 form the IPv4 address sits in bits 48-63 and 72-87, with the
    `u` octet (bits 64-71) and the suffix (bits 88-127) zero, so
    `64:ff9b:1:808:8:800::` carries 8.8.8.8. A network may use a longer prefix
    inside the /48, which puts the address elsewhere; an address that is not
    in the /48 form is not read, so it stays reserved and refused rather than
    being judged by bits that may belong to the prefix."""
    if address in _NAT64 or address in _IPV4_COMPATIBLE:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    if address in _NAT64_LOCAL:
        value = int(address)
        if (value >> 56) & 0xFF or value & ((1 << 40) - 1):
            return None
        return ipaddress.IPv4Address(((value >> 64) & 0xFFFF) << 16 | (value >> 40) & 0xFFFF)
    return address.sixtofour


def _is_internal(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether an address is anywhere but the public internet.

    The check was a list of IPv4 prefixes (`10.`, `127.`, `169.254.`,
    `172.16.` to `172.31.`, `192.168.`, `0.0.0.0`): no IPv6 address at all
    (`::1`, `fd00::/8`, `fe80::/10`) and no shared address space. `ipaddress`
    knows the special-purpose blocks for both families; an IPv4-mapped IPv6
    address is judged as the IPv4 address it maps to (`host_ip`), which is
    where a dual-stack socket sends it.

    An IPv6 address that carries an IPv4 one is judged as that IPv4 address
    (`_carried_ipv4`). NAT64's 64:ff9b::/96 sits inside ::/8, which `ipaddress`
    calls reserved, so on a DNS64 network every IPv4-only host was refused, and
    whether a 6to4 address counted as private depended on the interpreter
    (refused on 3.12, allowed on 3.9).
    """
    if isinstance(address, ipaddress.IPv6Address):
        carried = _carried_ipv4(address)
        if carried is not None:
            address = carried
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
        or (isinstance(address, ipaddress.IPv4Address) and address in _SHARED_ADDRESS_SPACE)
    )


class CrewAIGuardError(ValueError):
    """Raised when a CrewAI guard rejects an untrusted input."""


def require_docker_liveness(client) -> None:
    """CVE-2026-2287 — assert the Docker daemon is alive before
    a CodeInterpreterTool invocation.

    `client` should be a `docker.DockerClient` (or any object exposing
    `.ping()`). Raises CrewAIGuardError if the ping fails.
    """
    if client is None:
        raise CrewAIGuardError(
            "Docker client is None — CodeInterpreterTool refuses to "
            "fall back to the host Python sandbox (CVE-2026-2287)."
        )
    try:
        client.ping()
    except Exception as exc:  # noqa: BLE001 — callers want a single exception type
        raise CrewAIGuardError(
            f"Docker liveness check failed: {exc}. Refusing to fall "
            f"back to host Python (CVE-2026-2287)."
        ) from exc


def validate_jsonloader_path(path: str | Path, *, root: str | Path) -> Path:
    """CVE-2026-2285 — anchor a JSONSearchTool / JSONLoader path to
    `root`. Returns the resolved Path; raises CrewAIGuardError on
    traversal.
    """
    root_resolved = Path(root).resolve()
    try:
        target = Path(path).resolve()
    except (OSError, ValueError) as exc:
        raise CrewAIGuardError(f"unresolvable path {path!r}") from exc
    try:
        target.relative_to(root_resolved)
    except ValueError as exc:
        raise CrewAIGuardError(
            f"path {target} escapes allowed root {root_resolved} "
            "(CVE-2026-2285)."
        ) from exc
    return target


def validate_rag_url(url: str, *, allowlist: list[str]) -> str:
    """CVE-2026-2286 — RagTool / WebsiteSearchTool SSRF guard.

    Rejects URLs whose hostname is not in `allowlist`, or that resolve to an
    address off the public internet (`_is_internal`). Every address the host
    resolves to is checked, IPv4 and IPv6, so a name with a public A record
    and a private AAAA record is refused. Returns the URL unchanged on success.

    A URL whose host URL parsers read differently is rejected too. `urlparse`
    keeps a backslash inside the authority, so it read
    `http://evil.example\\@docs.example/` as docs.example and passed it, while
    requests (urllib3) ends the authority at the backslash and fetches
    evil.example. A guard has to hold whichever client does the fetch.

    It does not close the time-of-check to time-of-use gap. The host is
    resolved here and again by the client that fetches it, so a name whose
    answer changes in between (DNS rebinding, a zero TTL) passes this check
    on a public address and is fetched on a private one. Closing it needs the
    fetch to connect to the address checked here, through a pinned resolver
    or transport, which this helper does not provide.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise CrewAIGuardError(
            f"RagTool refuses scheme {parsed.scheme!r} (CVE-2026-2286)."
        )
    host = parsed.hostname or ""
    if url_hosts(url) != (host,):
        raise CrewAIGuardError(
            f"RagTool: URL parsers read the host of {url!r} differently "
            "(CVE-2026-2286)."
        )
    if host not in set(allowlist):
        raise CrewAIGuardError(
            f"RagTool host {host!r} not in allowlist (CVE-2026-2286)."
        )
    try:
        answers = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError) as exc:
        raise CrewAIGuardError(
            f"RagTool: DNS resolution failed for {host!r}: {exc}"
        ) from exc
    for *_, sockaddr in answers:
        ip = str(sockaddr[0])
        address = host_ip(ip.partition("%")[0])
        if address is None or _is_internal(address):
            raise CrewAIGuardError(
                f"RagTool: {host!r} resolves to private IP {ip} "
                "(CVE-2026-2286 SSRF)."
            )
    return url


def assert_codeinterp_safe_mode(unsafe_mode: bool) -> None:
    """CVE-2026-2275 — refuse CodeInterpreterTool with `unsafe_mode=True`.

    The 'unsafe' flag in CrewAI 0.x lets the tool drop into a host
    Python interpreter where ctypes / `os.system` are reachable.
    """
    if unsafe_mode:
        raise CrewAIGuardError(
            "CodeInterpreterTool(unsafe_mode=True) is forbidden — "
            "host-Python sandbox enables ctypes + os.system reach "
            "(CVE-2026-2275)."
        )


__all__ = [
    "CrewAIGuardError",
    "assert_codeinterp_safe_mode",
    "require_docker_liveness",
    "validate_jsonloader_path",
    "validate_rag_url",
]
