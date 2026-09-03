"""The corpus must not contradict itself about a server's authentication.

`fetch_registry` derives two things from the same registry record and never
compared them:

* ``_auth_mode(server)`` looks across **every** remote and reports
  ``static-credential`` if any of them declares a secret header.
* ``_to_config(server)`` built the scannable config from ``remotes[0]`` **only**.

A server that publishes an anonymous or login entry point first and its
credentialled endpoint second therefore got labelled ``static-credential`` while
being handed to the scanner as a config with no auth on it at all. `AAK-MCP-001`
then reported "no authentication headers", which was true of the config and
false of the server, and the benign-slice false-positive rate carried it: 2 of
the 4 HIGH/CRITICAL findings on 2026-08-24, plus the 1 ambiguous verdict, were
this one conversion bug and not a rule defect.

``_to_config`` was fixed to prefer the first remote that declares headers. This
file is the guard that the *data* stays fixed, because the fix alone did not:
the committed manifest predated it and went on carrying the broken configs while
every test passed. The invariant is checkable offline from committed data —
label and config must agree — and it is the comparison nothing was making.

See `benchmarks/false_positive/RESULTS.md` (root cause B) and `triage.md`.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit.engine import run_scan

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "research" / "state-of-mcp-2026" / "corpus" / "registry-manifest.json"

_HIGH_CRIT = frozenset({"critical", "high"})

# Servers whose config lost its declared auth to the `remotes[0]` conversion.
# Named rather than counted: a regression here should say which server broke.
PREVIOUSLY_MISCONVERTED = (
    "app.thoughtspot/mcp-server",
    "co.curie/commerce",
    "co.huggingface/hf-mcp-server",
)


def _fetch_registry() -> Any:
    """Import `fetch_registry.py` by path — research/ is not an importable package."""
    path = REPO / "research" / "state-of-mcp-2026" / "fetch_registry.py"
    spec = importlib.util.spec_from_file_location("somcp_fetch_registry", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _servers() -> list[dict[str, Any]]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))["servers"]


def _declared_headers(config: dict[str, Any] | None) -> set[str]:
    """Header names the synthesised config actually carries."""
    out: set[str] = set()
    for entry in ((config or {}).get("mcpServers") or {}).values():
        if isinstance(entry, dict):
            out |= {str(h) for h in (entry.get("headers") or {})}
    return out


def _scan_config(config: dict[str, Any]) -> list[Any]:
    tmp = Path(tempfile.mkdtemp(prefix="aak-corpus-test-"))
    try:
        (tmp / "config.mcp.json").write_text(json.dumps(config), encoding="utf-8")
        return list(run_scan(tmp).findings)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- the invariant ----------------------------------------------------------


def test_static_credential_servers_carry_auth_headers_in_their_config() -> None:
    """A server labelled `static-credential` must be handed to the scanner as one.

    This is the comparison that was never made. It reads only committed data, so
    it fails on a stale manifest even when `_to_config` itself is correct.
    """
    offenders = [
        s["name"]
        for s in _servers()
        if s.get("auth_mode") == "static-credential"
        and (s.get("config") or {}).get("mcpServers")
        and not _declared_headers(s.get("config"))
    ]
    assert not offenders, (
        f"{len(offenders)} server(s) labelled 'static-credential' have a config "
        f"with no auth header, so the scanner is told they are unauthenticated: "
        f"{offenders[:10]}. Regenerate the manifest — `_to_config` must convert "
        f"the remote that declares headers."
    )


def test_to_config_prefers_the_remote_that_declares_headers() -> None:
    """The unit-level fix, on the exact shape that produced the false positives.

    `co.huggingface/hf-mcp-server` publishes its `?login` entry point first and
    its `Authorization`-bearing endpoint second.
    """
    fr = _fetch_registry()
    server = {
        "name": "co.huggingface/hf-mcp-server",
        "remotes": [
            {"type": "streamable-http", "url": "https://huggingface.co/mcp?login"},
            {
                "type": "streamable-http",
                "url": "https://huggingface.co/mcp",
                "headers": [{"name": "Authorization", "isSecret": True}],
            },
        ],
    }
    assert fr._auth_mode(server) == "static-credential"
    config = fr._to_config(server)
    assert _declared_headers(config) == {"Authorization"}, (
        "conversion dropped the remote carrying the credential — this is the "
        "`remotes[0]`-only bug that cost 2 false positives on 2026-08-24"
    )


def test_single_remote_without_headers_is_still_converted_faithfully() -> None:
    """The fix must not invent auth. A genuinely credential-less server stays one.

    `ai.spala/public-mcp` is the benign slice's standing TRUE positive; if this
    regressed, the FP rate would improve by going blind.
    """
    fr = _fetch_registry()
    server = {
        "name": "ai.spala/public-mcp",
        "remotes": [{"type": "streamable-http", "url": "https://mcp.spala.ai/mcp"}],
    }
    config = fr._to_config(server)
    assert _declared_headers(config) == set()
    assert fr._auth_mode(server) == "none"


# --- the benign configs, end to end ----------------------------------------


@pytest.mark.parametrize("name", PREVIOUSLY_MISCONVERTED)
def test_previously_misconverted_config_produces_no_high_critical(name: str) -> None:
    """Each benign config that used to fire now produces no HIGH/CRITICAL finding."""
    server = next((s for s in _servers() if s.get("name") == name), None)
    assert server is not None, f"{name} is no longer in the corpus manifest"
    hc = [f for f in _scan_config(server["config"]) if f.severity.value in _HIGH_CRIT]
    assert not hc, (
        f"{name} is a benign server that declares a credential, but produced "
        f"HIGH/CRITICAL findings: {[(f.rule_id, f.evidence) for f in hc]}"
    )


def test_the_true_positive_still_fires() -> None:
    """The paired negative test: precision work must not silence a real finding."""
    server = next(
        (s for s in _servers() if s.get("name") == "ai.spala/public-mcp"), None
    )
    assert server is not None
    ids = {f.rule_id for f in _scan_config(server["config"])}
    assert "AAK-MCP-001" in ids, (
        "the benign slice's standing true positive stopped firing — a lower "
        "false-positive rate bought with a false negative is not an improvement"
    )
