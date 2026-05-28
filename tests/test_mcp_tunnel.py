"""Tests for AAK-MCP-TUNNEL-001..003 — Anthropic MCP Tunnels rule pack.

Reference: Anthropic MCP Tunnels research preview, launched 2026-05-19.

  - Overview: https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/overview
  - Reference: https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/reference
  - Security:  https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/security

Every detection pattern here mirrors a field name or rule documented on
those pages — there are no invented schema fields.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.output.compliance import FRAMEWORKS, format_results
from agent_audit_kit.output.sarif import format_results as format_sarif
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_tunnel import scan


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")


def _ids(findings, prefix: str = "AAK-MCP-TUNNEL-") -> set[str]:
    return {f.rule_id for f in findings if f.rule_id.startswith(prefix)}


# ---------------------------------------------------------------------------
# Registry sanity — every rule must land with the documented shape.
# ---------------------------------------------------------------------------


def test_three_tunnel_rules_are_registered() -> None:
    for rid in ("AAK-MCP-TUNNEL-001", "AAK-MCP-TUNNEL-002", "AAK-MCP-TUNNEL-003"):
        assert rid in RULES, f"missing rule registration: {rid}"


def test_tunnel_001_metadata_shape() -> None:
    r = RULES["AAK-MCP-TUNNEL-001"]
    assert r.severity.name == "CRITICAL"
    assert r.category.name == "MCP_CONFIG"
    assert r.sarif_name == "McpTunnelSsrfDefenseDisabled"
    assert "MCP04:2025" in r.owasp_mcp_references
    assert "MCP06:2025" in r.owasp_mcp_references
    assert {"ASI02", "ASI05"} <= set(r.owasp_agentic_references)
    assert any("Anthropic MCP Tunnels" in ref for ref in r.incident_references)


def test_tunnel_002_metadata_shape() -> None:
    r = RULES["AAK-MCP-TUNNEL-002"]
    assert r.severity.name == "HIGH"
    assert r.category.name == "MCP_CONFIG"
    assert r.sarif_name == "McpTunnelUpstreamNoTrustAnchor"
    assert "MCP07:2025" in r.owasp_mcp_references
    assert "ASI03" in r.owasp_agentic_references


def test_tunnel_003_metadata_shape() -> None:
    r = RULES["AAK-MCP-TUNNEL-003"]
    assert r.severity.name == "CRITICAL"
    assert r.category.name == "MCP_CONFIG"
    assert r.sarif_name == "McpTunnelCredentialHardcoded"
    assert {"MCP02:2025", "MCP07:2025"} <= set(r.owasp_mcp_references)
    assert {"ASI03", "ASI06"} <= set(r.owasp_agentic_references)


# ---------------------------------------------------------------------------
# AAK-MCP-TUNNEL-001 — SSRF defense
# ---------------------------------------------------------------------------


def test_001_disable_ip_validation_fires(tmp_path: Path) -> None:
    _write(tmp_path / "mcp-gateway/config.yaml", """
        listen_addr: ":9443"
        tunnel_domain: acme.tunnel.anthropic.com
        tls:
          cert_file: /etc/mcp-gateway/server.crt
          key_file: /etc/mcp-gateway/server.key
        routes:
          wiki: http://wiki.internal:8080
        upstream:
          disable_ip_validation: true
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-001" in _ids(findings), \
        f"got {[f.rule_id for f in findings]}"


def test_001_public_internet_cidr_fires(tmp_path: Path) -> None:
    _write(tmp_path / "mcp-gateway/config.yaml", """
        listen_addr: ":9443"
        tunnel_domain: acme.tunnel.anthropic.com
        tls:
          cert_file: /e/c.crt
          key_file: /e/k.key
        routes:
          a: http://a.internal:8080
        upstream:
          allowed_ips:
            - 10.0.0.0/8
            - 0.0.0.0/0
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-001" in _ids(findings)


def test_001_overly_broad_ipv4_fires(tmp_path: Path) -> None:
    """A /7 IPv4 covers ~33M addresses — overbroad for a private-network proxy."""
    _write(tmp_path / "mcp-gateway/config.yaml", """
        listen_addr: ":9443"
        tunnel_domain: acme.tunnel.anthropic.com
        tls:
          cert_file: /e/c.crt
          key_file: /e/k.key
        routes:
          a: http://a.internal:8080
        upstream:
          allowed_ips:
            - 8.0.0.0/7
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-001" in _ids(findings)


def test_001_rfc1918_only_passes(tmp_path: Path) -> None:
    """The docs' example (RFC1918-only allow list) must not fire."""
    _write(tmp_path / "mcp-gateway/config.yaml", """
        listen_addr: ":9443"
        tunnel_domain: acme.tunnel.anthropic.com
        tls:
          cert_file: /e/c.crt
          key_file: /e/k.key
        routes:
          wiki: http://wiki.internal:8080
        upstream:
          allowed_ips:
            - 10.0.0.0/8
            - 172.16.0.0/12
            - 192.168.0.0/16
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-001" not in _ids(findings)


# ---------------------------------------------------------------------------
# AAK-MCP-TUNNEL-002 — HTTPS upstream without trust anchor
# ---------------------------------------------------------------------------


def test_002_https_upstream_without_trust_anchor_fires(tmp_path: Path) -> None:
    _write(tmp_path / "mcp-gateway/config.yaml", """
        listen_addr: ":9443"
        tunnel_domain: acme.tunnel.anthropic.com
        tls:
          cert_file: /e/c.crt
          key_file: /e/k.key
        routes:
          docs: https://docs.internal:8443
        upstream:
          allowed_ips:
            - 10.0.0.0/8
    """)
    findings, _ = scan(tmp_path)
    rule_ids = _ids(findings)
    assert "AAK-MCP-TUNNEL-002" in rule_ids


def test_002_ca_file_set_passes(tmp_path: Path) -> None:
    _write(tmp_path / "mcp-gateway/config.yaml", """
        listen_addr: ":9443"
        tunnel_domain: acme.tunnel.anthropic.com
        tls:
          cert_file: /e/c.crt
          key_file: /e/k.key
        routes:
          docs: https://docs.internal:8443
        upstream:
          allowed_ips:
            - 10.0.0.0/8
          tls:
            ca_file: /etc/upstream-ca.pem
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-002" not in _ids(findings)


def test_002_include_system_cas_passes(tmp_path: Path) -> None:
    _write(tmp_path / "mcp-gateway/config.yaml", """
        listen_addr: ":9443"
        tunnel_domain: acme.tunnel.anthropic.com
        tls:
          cert_file: /e/c.crt
          key_file: /e/k.key
        routes:
          docs: https://docs.internal:8443
        upstream:
          allowed_ips:
            - 10.0.0.0/8
          tls:
            include_system_cas: true
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-002" not in _ids(findings)


def test_002_http_only_upstream_passes(tmp_path: Path) -> None:
    """No https in routes → no trust-anchor requirement → no finding."""
    _write(tmp_path / "mcp-gateway/config.yaml", """
        listen_addr: ":9443"
        tunnel_domain: acme.tunnel.anthropic.com
        tls:
          cert_file: /e/c.crt
          key_file: /e/k.key
        routes:
          wiki: http://wiki.internal:8080
        upstream:
          allowed_ips:
            - 10.0.0.0/8
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-002" not in _ids(findings)


# ---------------------------------------------------------------------------
# AAK-MCP-TUNNEL-003 — Hardcoded tunnel credentials
# ---------------------------------------------------------------------------


def test_003_literal_token_in_github_workflow_fires(tmp_path: Path) -> None:
    _write(tmp_path / ".github/workflows/deploy.yml", """
        name: deploy
        jobs:
          deploy:
            runs-on: ubuntu-latest
            env:
              MCP_TUNNEL_TOKEN: tnl_abcdef1234567890.actual_literal_value
            steps:
              - run: echo deploy
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-003" in _ids(findings)


def test_003_github_secrets_reference_passes(tmp_path: Path) -> None:
    _write(tmp_path / ".github/workflows/deploy.yml", """
        name: deploy
        jobs:
          deploy:
            runs-on: ubuntu-latest
            env:
              MCP_TUNNEL_TOKEN: ${{ secrets.MCP_TUNNEL_TOKEN }}
              ANTHROPIC_IDENTITY_TOKEN: ${{ secrets.ANTHROPIC_IDENTITY_TOKEN }}
            steps:
              - run: echo deploy
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-003" not in _ids(findings)


def test_003_gitlab_ci_literal_token_fires(tmp_path: Path) -> None:
    _write(tmp_path / ".gitlab-ci.yml", """
        variables:
          ANTHROPIC_TUNNEL_TOKEN: tnl_live_inline_token_value
        deploy:
          script:
            - echo "deploying"
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-003" in _ids(findings)


def test_003_pem_private_key_under_tunnel_path_fires(tmp_path: Path) -> None:
    _write(tmp_path / "mcp-tunnel/server.key", """
        -----BEGIN PRIVATE KEY-----
        MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC1234testbody
        Z29vZGRheXNhcmVoZXJlYWdhaW5vbmVtb3JldGltZWZvcnRoZWtleQ==
        -----END PRIVATE KEY-----
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-003" in _ids(findings)


def test_003_pem_outside_tunnel_path_passes(tmp_path: Path) -> None:
    """A PEM key in an unrelated path (e.g. tests/fixtures/) must not fire
    — that's secret_exposure's job, not ours. Scoping to tunnel dirs
    keeps the rule precise."""
    _write(tmp_path / "tests/fixtures/some-other-thing/key.pem", """
        -----BEGIN PRIVATE KEY-----
        MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSi
        -----END PRIVATE KEY-----
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-003" not in _ids(findings)


def test_003_k8s_secret_with_inline_data_fires(tmp_path: Path) -> None:
    _write(tmp_path / "k8s/secret.yaml", """
        apiVersion: v1
        kind: Secret
        metadata:
          name: mcp-tunnel-token
          namespace: mcp-tunnel
        type: Opaque
        data:
          token: dG5sX2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-003" in _ids(findings)


def test_003_k8s_secret_with_empty_data_passes(tmp_path: Path) -> None:
    """A placeholder Secret (no inline values) — used as a target for
    `kubectl create secret` — must not fire."""
    _write(tmp_path / "k8s/secret.yaml", """
        apiVersion: v1
        kind: Secret
        metadata:
          name: mcp-tunnel-token
          namespace: mcp-tunnel
        type: Opaque
        data: {}
    """)
    findings, _ = scan(tmp_path)
    assert "AAK-MCP-TUNNEL-003" not in _ids(findings)


# ---------------------------------------------------------------------------
# Engine integration + SARIF
# ---------------------------------------------------------------------------


def test_engine_emits_tunnel_finding_through_run_scan(tmp_path: Path) -> None:
    """The new scanner is wired into engine._OPTIONAL_SCANNERS — verify
    `run_scan()` surfaces a finding without us calling the scanner directly."""
    _write(tmp_path / "mcp-gateway/config.yaml", """
        listen_addr: ":9443"
        tunnel_domain: acme.tunnel.anthropic.com
        tls:
          cert_file: /e/c.crt
          key_file: /e/k.key
        routes:
          wiki: http://wiki.internal:8080
        upstream:
          disable_ip_validation: true
    """)
    result = run_scan(tmp_path)
    ids = {f.rule_id for f in result.findings}
    assert "AAK-MCP-TUNNEL-001" in ids
    # The engine counts evaluated rules (not a set); just verify it's > 0
    # so we know the scanner ran and was registered.
    assert result.rules_evaluated > 0


def test_sarif_carries_security_severity_and_fingerprint(tmp_path: Path) -> None:
    _write(tmp_path / "mcp-gateway/config.yaml", """
        listen_addr: ":9443"
        tunnel_domain: acme.tunnel.anthropic.com
        tls:
          cert_file: /e/c.crt
          key_file: /e/k.key
        routes:
          docs: https://docs.internal:8443
        upstream:
          allowed_ips:
            - 10.0.0.0/8
    """)
    result = run_scan(tmp_path)
    sarif = json.loads(format_sarif(result, project_root=tmp_path))
    run = sarif["runs"][0]

    rule_entries = [r for r in run["tool"]["driver"]["rules"]
                    if r["id"] == "AAK-MCP-TUNNEL-002"]
    assert len(rule_entries) == 1
    rule_meta = rule_entries[0]
    assert rule_meta["name"] == "McpTunnelUpstreamNoTrustAnchor"
    score = float(rule_meta["properties"]["security-severity"])
    assert 0 < score < 10

    results = [r for r in run["results"] if r["ruleId"] == "AAK-MCP-TUNNEL-002"]
    assert results, "expected at least one SARIF result for AAK-MCP-TUNNEL-002"
    res = results[0]
    assert "fingerprints" in res
    assert "primaryLocationFingerprint" in res["fingerprints"]


# ---------------------------------------------------------------------------
# Compliance crosswalk — ISO 42001 + EU AI Act Art. 15 land the rules
# ---------------------------------------------------------------------------


def test_iso42001_framework_is_registered() -> None:
    assert "iso42001" in FRAMEWORKS
    fw = FRAMEWORKS["iso42001"]
    assert "ISO/IEC 42001" in fw["name"]
    # Verify a representative clause picks up an ASI token carried by our rules.
    controls = fw["controls"]
    asi_pool = set()
    for asi_list in controls.values():
        asi_pool.update(asi_list)
    # Our TUNNEL rules carry ASI02 / ASI03 / ASI04 / ASI05 / ASI06.
    assert asi_pool & {"ASI02", "ASI03", "ASI04", "ASI05", "ASI06"}


def test_iso42001_text_report_renders_with_tunnel_finding(tmp_path: Path) -> None:
    _write(tmp_path / "mcp-gateway/config.yaml", """
        listen_addr: ":9443"
        tunnel_domain: acme.tunnel.anthropic.com
        tls:
          cert_file: /e/c.crt
          key_file: /e/k.key
        routes:
          wiki: http://wiki.internal:8080
        upstream:
          disable_ip_validation: true
    """)
    result = run_scan(tmp_path)
    text = format_results(result, "iso42001")
    assert "ISO/IEC 42001" in text
    # Our TUNNEL-001 rule (ASI02 / ASI05) must surface under at least one
    # iso42001 clause that maps to those ASI tokens.
    assert "Clause 6.1.2" in text or "A.6.2.3" in text or "A.6.2.4" in text


def test_eu_ai_act_art15_picks_up_tunnel_rules(tmp_path: Path) -> None:
    """The TUNNEL rules' ASI03/ASI04 references must land them under
    EU AI Act Art. 15 — Robustness & Security."""
    _write(tmp_path / "mcp-gateway/config.yaml", """
        listen_addr: ":9443"
        tunnel_domain: acme.tunnel.anthropic.com
        tls:
          cert_file: /e/c.crt
          key_file: /e/k.key
        routes:
          docs: https://docs.internal:8443
        upstream:
          allowed_ips:
            - 10.0.0.0/8
    """)
    result = run_scan(tmp_path)
    text = format_results(result, "eu-ai-act")
    assert "EU AI Act" in text
    assert "Art. 15" in text
