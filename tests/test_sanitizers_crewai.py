"""`agent_audit_kit.sanitizers.crewai.validate_rag_url`, the runtime guard the
AAK-CREWAI-CVE-2026-2286-001 remediation tells users to wrap a RAG URL in.

DNS is stubbed so the suite stays offline: `_resolve_to` makes
`socket.getaddrinfo` answer with fixed addresses, and `_no_dns` fails the test
if the guard reaches it at all.
"""
from __future__ import annotations

import socket

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.sanitizers import crewai
from agent_audit_kit.sanitizers.crewai import CrewAIGuardError, validate_rag_url

_ALLOWED = ["docs.example"]
_BS = "\\"


def _resolve_to(monkeypatch: pytest.MonkeyPatch, *addresses: str) -> None:
    def answer(host: str, port: object, *args: object, **kwargs: object) -> list[tuple]:
        return [
            (socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "",
             (address, 0, 0, 0) if ":" in address else (address, 0))
            for address in addresses
        ]

    monkeypatch.setattr(crewai.socket, "getaddrinfo", answer)


def _no_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(host: str, *args: object, **kwargs: object) -> list[tuple]:
        raise AssertionError(f"the guard resolved {host!r}")

    monkeypatch.setattr(crewai.socket, "getaddrinfo", fail)


def test_an_allowlisted_public_url_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _resolve_to(monkeypatch, "93.184.216.34")
    assert validate_rag_url("https://docs.example/guide", allowlist=_ALLOWED) == "https://docs.example/guide"


def test_a_host_off_the_allowlist_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_dns(monkeypatch)
    with pytest.raises(CrewAIGuardError, match="not in allowlist"):
        validate_rag_url("https://evil.example/guide", allowlist=_ALLOWED)


def test_an_allowlisted_host_on_a_private_address_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _resolve_to(monkeypatch, "169.254.169.254")
    with pytest.raises(CrewAIGuardError, match="private IP"):
        validate_rag_url("https://docs.example/guide", allowlist=_ALLOWED)


@pytest.mark.parametrize("url", [
    # urlparse reads docs.example; requests (urllib3) ends the authority at the
    # backslash and fetches evil.example.
    "http://evil.example" + _BS + "@docs.example/guide",
    # urlparse drops the tab first and reads docs.example the same way.
    "http://evil.example\t" + _BS + "@docs.example/guide",
])
def test_a_url_parsers_read_differently_is_refused(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    _no_dns(monkeypatch)
    with pytest.raises(CrewAIGuardError, match="read the host"):
        validate_rag_url(url, allowlist=_ALLOWED)


@pytest.mark.parametrize("addresses", [
    ("::1",),                          # IPv6 loopback
    ("fd12:3456::7",),                 # IPv6 unique-local
    ("fe80::1",),                      # IPv6 link-local
    ("::ffff:127.0.0.1",),             # IPv4-mapped loopback
    ("100.64.0.1",),                   # shared address space (carrier-grade NAT)
    ("100.100.100.200",),              # Alibaba Cloud's metadata service, in the same block
    ("240.0.0.1",),                    # reserved
    ("224.0.0.251",),                  # multicast
    ("0.0.0.0",),
    ("::",),
    ("93.184.216.34", "fd12:3456::7"),  # one public address does not clear a private one
])
def test_an_allowlisted_host_on_any_internal_address_is_refused(
    monkeypatch: pytest.MonkeyPatch, addresses: tuple[str, ...]
) -> None:
    """The check was a list of IPv4 prefixes over `gethostbyname`'s one IPv4
    answer: no IPv6 address, no 100.64.0.0/10, and a name with a private AAAA
    record passed on its public A record."""
    _resolve_to(monkeypatch, *addresses)
    with pytest.raises(CrewAIGuardError, match="private IP"):
        validate_rag_url("https://docs.example/guide", allowlist=_ALLOWED)


def test_an_allowlisted_host_on_public_addresses_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _resolve_to(monkeypatch, "93.184.216.34", "2606:2800:21f:cb07:6820:80da:af6b:8b2c")
    assert validate_rag_url("https://docs.example/", allowlist=_ALLOWED) == "https://docs.example/"


def test_a_host_that_does_not_resolve_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(host: str, *args: object, **kwargs: object) -> list[tuple]:
        raise socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided")

    monkeypatch.setattr(crewai.socket, "getaddrinfo", fail)
    with pytest.raises(CrewAIGuardError, match="DNS resolution failed"):
        validate_rag_url("https://docs.example/", allowlist=_ALLOWED)


def test_the_rebinding_window_is_stated() -> None:
    """The guard resolves the host and the RAG tool resolves it again, so a name
    whose answer changes in between passes. Pinning the address is out of scope;
    the docstring and the rule say so."""
    assert "rebinding" in (validate_rag_url.__doc__ or "").lower()
    assert "rebinding" in RULES["AAK-CREWAI-CVE-2026-2286-001"].limitations.lower()


@pytest.mark.parametrize(("address", "allowed"), [
    ("64:ff9b::808:808", True),     # NAT64 of 8.8.8.8, a DNS64 network's answer for an IPv4-only host
    ("64:ff9b::a00:1", False),      # NAT64 of 10.0.0.1
    ("2002:808:808::1", True),      # 6to4 of 8.8.8.8
    ("2002:a00:1::", False),        # 6to4 of 10.0.0.1
    ("::808:808", True),            # IPv4-compatible 8.8.8.8
    ("::a00:1", False),             # IPv4-compatible 10.0.0.1
    ("64:ff9b:1:808:8:800::", True),    # local-use NAT64 (RFC 8215), /48 form, of 8.8.8.8
    ("64:ff9b:1:a00:0:100::", False),   # the same of 10.0.0.1
    ("64:ff9b:1::808:808", False),      # a longer local-use prefix: not read, so refused
])
def test_an_ipv6_address_carrying_an_ipv4_one_is_judged_by_it(
    monkeypatch: pytest.MonkeyPatch, address: str, allowed: bool
) -> None:
    """NAT64's 64:ff9b::/96 sits inside ::/8, which ipaddress calls reserved, so
    on a DNS64 network every IPv4-only host was refused; whether a 6to4 address
    was private depended on the interpreter (refused on 3.12, allowed on 3.9).
    Each is judged as the IPv4 address it carries, the same on every Python.
    The local-use 64:ff9b:1::/48 is read in RFC 6052's /48 form only; an
    address in it written for a longer prefix is refused, as before."""
    _resolve_to(monkeypatch, address)
    if allowed:
        assert validate_rag_url("https://docs.example/", allowlist=_ALLOWED) == "https://docs.example/"
    else:
        with pytest.raises(CrewAIGuardError, match="private IP"):
            validate_rag_url("https://docs.example/", allowlist=_ALLOWED)
