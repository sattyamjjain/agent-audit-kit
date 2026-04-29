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

import socket
from pathlib import Path
from urllib.parse import urlparse


_PRIVATE_NETS: tuple[str, ...] = (
    "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "0.0.0.0",
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

    Rejects URLs that resolve to private networks or whose hostname is
    not in `allowlist`. Returns the URL unchanged on success.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise CrewAIGuardError(
            f"RagTool refuses scheme {parsed.scheme!r} (CVE-2026-2286)."
        )
    host = parsed.hostname or ""
    if host not in set(allowlist):
        raise CrewAIGuardError(
            f"RagTool host {host!r} not in allowlist (CVE-2026-2286)."
        )
    try:
        ip = socket.gethostbyname(host)
    except OSError as exc:
        raise CrewAIGuardError(
            f"RagTool: DNS resolution failed for {host!r}: {exc}"
        ) from exc
    if any(ip.startswith(p) for p in _PRIVATE_NETS):
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
