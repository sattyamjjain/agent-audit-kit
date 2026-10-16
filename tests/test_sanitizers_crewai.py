"""`agent_audit_kit.sanitizers.crewai.validate_rag_url`, the runtime guard the
AAK-CREWAI-CVE-2026-2286-001 remediation tells users to wrap a RAG URL in.

DNS is stubbed so the suite stays offline: `_resolve_to` makes
`socket.gethostbyname` answer with a fixed address, and `_no_dns` fails the
test if the guard reaches it at all.
"""
from __future__ import annotations

import pytest

from agent_audit_kit.sanitizers import crewai
from agent_audit_kit.sanitizers.crewai import CrewAIGuardError, validate_rag_url

_ALLOWED = ["docs.example"]
_BS = "\\"


def _resolve_to(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    monkeypatch.setattr(crewai.socket, "gethostbyname", lambda host: address)


def _no_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(host: str) -> str:
        raise AssertionError(f"the guard resolved {host!r}")

    monkeypatch.setattr(crewai.socket, "gethostbyname", fail)


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
