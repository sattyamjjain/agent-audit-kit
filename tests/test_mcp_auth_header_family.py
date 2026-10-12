"""Which headers count as authentication for ``AAK-MCP-001``.

This has now been wrong twice, the same way both times, so the boundary is
pinned as behaviour rather than left to the regex.

* 2026-07-20: the rule recognised only ``Authorization`` / ``Bearer`` /
  ``X-API-Key`` / ``Api-Key``. Two benign-slice servers authenticating with
  ``X-Nefesh-Key`` and ``X-WR-API-Key`` were reported "without authentication".
  #475 added the ``-key`` family.
* 2026-08-24: the slice grew 368 -> 536 and the same class came straight back.
  ``X-Velarion-Agent-Token`` and ``X-SignDocs-Client-Secret`` are credential
  headers too, and #475 had generalised exactly one suffix.

The interesting half of this file is the negatives. A "no authentication"
finding is CRITICAL, so widening the family is not free: every header wrongly
admitted here turns a real unauthenticated server into a silent pass. The
``-id`` and CSRF cases below are the ones that keep that from happening.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.scanners.mcp_config import _server_declares_auth, scan

REF = "${SECRET}"

RECOGNISED = [
    pytest.param({"Authorization": "Bearer x"}, id="authorization"),
    pytest.param({"X-API-Key": REF}, id="x-api-key"),
    pytest.param({"Api-Key": REF}, id="api-key"),
    # #475 - the -key family
    pytest.param({"X-Nefesh-Key": REF}, id="vendor-key"),
    pytest.param({"X-WR-API-Key": REF}, id="vendor-api-key"),
    pytest.param({"X-Goog-Api-Key": REF}, id="goog-api-key"),
    # 2026-08-24 - the -token / -secret families
    pytest.param({"X-Velarion-Agent-Token": REF}, id="vendor-token"),
    pytest.param({"X-SignDocs-Client-Secret": REF}, id="vendor-client-secret"),
    pytest.param({"X-Webhook-Secret": REF}, id="vendor-secret"),
    pytest.param({"acme-api-token": REF}, id="bare-api-token"),
    pytest.param({"acme-access-key": REF}, id="bare-access-key"),
    pytest.param({"apikey": REF}, id="apikey"),
    # x402 pay-to-access: access control rather than identity, but the endpoint
    # is not openly reachable, so "without authentication" would be wrong.
    pytest.param({"X-PAYMENT": REF}, id="x402-payment"),
    # The real signdocs config: the pair is recognised because of the secret half.
    pytest.param(
        {"X-SignDocs-Client-Id": REF, "X-SignDocs-Client-Secret": REF},
        id="client-credentials-pair",
    ),
    # 2026-10-12 - real .vscode/mcp.json files: underscores, a camel-case suffix,
    # and Azure API Management's subscription key.
    pytest.param({"CONTEXT7_API_KEY": "${input:context7-key}"}, id="underscore-api-key"),
    pytest.param({"ServiceApiKey": REF}, id="camel-case-apikey"),
    pytest.param({"Ocp-Apim-Subscription-Key": "${input:apim-key}"}, id="apim-subscription-key"),
]

NOT_RECOGNISED = [
    pytest.param({}, id="no-headers"),
    pytest.param({"Accept": REF}, id="accept-is-content-negotiation"),
    pytest.param({"Content-Type": "application/json"}, id="content-type"),
    # A bare client_id is a PUBLIC identifier. Admitting it would mean a server
    # that identifies its caller without authenticating them reads as authenticated.
    pytest.param({"X-SignDocs-Client-Id": REF}, id="bare-client-id"),
    # `-id` headers generally: these authenticate nothing at all.
    pytest.param({"X-Request-Id": REF}, id="request-id"),
    pytest.param({"X-Trace-Id": REF}, id="trace-id"),
    pytest.param({"X-Correlation-Id": REF}, id="correlation-id"),
    # Tokens that are not credentials. CSRF proves the request came from your own
    # page, not that the caller is anyone -- and the `-token` suffix would
    # otherwise swallow them.
    pytest.param({"X-CSRF-Token": REF}, id="csrf-token"),
    pytest.param({"X-XSRF-Token": REF}, id="xsrf-token"),
    # The new suffixes are suffixes: a name that only contains one is not a key.
    pytest.param({"X-Api-Key-Url": REF}, id="api-key-not-at-the-end"),
    pytest.param({"Ocp-Apim-Subscription-Region": REF}, id="subscription-region"),
]


@pytest.mark.parametrize("headers", RECOGNISED)
def test_recognised_as_authentication(headers: dict) -> None:
    assert _server_declares_auth(headers) is True


@pytest.mark.parametrize("headers", NOT_RECOGNISED)
def test_not_recognised_as_authentication(headers: dict) -> None:
    assert _server_declares_auth(headers) is False


def test_family_stays_value_aware() -> None:
    """A hardcoded literal in a custom auth header is not a declared scheme.

    The credential is then exposed in the config, so the endpoint is effectively
    unprotected and `AAK-MCP-001` should still fire. Widening the header family
    must not quietly widen this too.
    """
    assert _server_declares_auth({"X-Vendor-Token": "sk-live-abc123def456"}) is False
    assert _server_declares_auth({"X-Vendor-Token": REF}) is True
    # The 2026-10-12 suffixes join the same value-aware family.
    assert _server_declares_auth({"CONTEXT7_API_KEY": "k9f2Lq7XvN3mR8tW1zP5"}) is False
    assert _server_declares_auth({"Ocp-Apim-Subscription-Key": "k9f2Lq7XvN3mR8tW1zP5"}) is False


def test_end_to_end_a_vendor_token_server_is_not_reported_unauthenticated(
    tmp_path: Path,
) -> None:
    """The FP as it actually appeared, through the scanner rather than the helper."""
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "company-intelligence": {
                        "type": "http",
                        "url": "https://velarion-scraper-production.up.railway.app/mcp",
                        "headers": {"X-Velarion-Agent-Token": REF},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-001" not in {f.rule_id for f in findings}


def test_end_to_end_a_genuinely_open_server_still_fires(tmp_path: Path) -> None:
    """The true positive the benchmark has carried since 2026-07-20.

    Without this the previous test could be satisfied by disabling the rule.
    """
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "public-mcp": {
                        "type": "http",
                        "url": "https://mcp.spala.ai/mcp",
                        "headers": {"Accept": REF},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-001" in {f.rule_id for f in findings}
