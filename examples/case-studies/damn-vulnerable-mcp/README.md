# Case Study: Scanning damn-vulnerable-MCP-server Patterns

## Background

[damn-vulnerable-MCP-server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) (1,277+ stars) is the "DVWA for MCP" — a purpose-built vulnerable MCP environment for security testing and education. It provides challenges organized by difficulty (easy/medium/hard) covering command injection, tool poisoning, secret exposure, path traversal, and supply chain attacks.

This case study uses AgentAuditKit to scan MCP configurations inspired by DVMCP's vulnerability patterns, demonstrating automated detection of the same issues the project teaches manually.

## What We Scanned

Two configuration files representing a typical DVMCP-style vulnerable setup:

- **dvmcp-inspired.mcp.json** — MCP server definitions with 5 vulnerability labs
- **dvmcp-settings.json** — Claude Code settings with malicious hooks and trust boundary violations

## How to Reproduce

```bash
# Install AgentAuditKit
pip install agent-audit-kit

# Scan the DVMCP-inspired configs
agent-audit-kit scan examples/case-studies/damn-vulnerable-mcp/configs/

# View detailed JSON output
agent-audit-kit scan examples/case-studies/damn-vulnerable-mcp/configs/ --format json

# Generate SARIF for GitHub Security tab
agent-audit-kit scan examples/case-studies/damn-vulnerable-mcp/configs/ --format sarif
```

## Findings Summary

AgentAuditKit detects vulnerabilities across **7 of 13 security categories** in these configs:

| Category | Findings | Severity | OWASP MCP | OWASP Agentic |
|----------|----------|----------|-----------|---------------|
| MCP Configuration | Shell injection, no auth, headersHelper, unpinned packages, filesystem root | CRITICAL-MEDIUM | MCP01, MCP02, MCP04, MCP05, MCP07 | ASI02, ASI03, ASI04, ASI05 |
| Hook Injection | Network exfiltration, credential theft, privilege escalation | CRITICAL | — | ASI03, ASI05 |
| Trust Boundary | enableAllProjectMcpServers, API proxy, wildcard permissions | CRITICAL-HIGH | MCP02, MCP09 | ASI02, ASI03, ASI04, ASI09 |
| Secret Exposure | Anthropic, OpenAI, AWS, GitHub keys hardcoded | CRITICAL | MCP01 | ASI03 |
| Tool Poisoning | Invisible Unicode, prompt injection, cross-tool manipulation | CRITICAL-HIGH | MCP03 | ASI02, ASI04 |
| Supply Chain | Unpinned packages, no version pinning | HIGH-MEDIUM | MCP04 | ASI04 |
| Transport Security | HTTP endpoint, SSE transport | CRITICAL-MEDIUM | MCP07 | ASI07 |

OWASP ids are OWASP MCP Top 10 v0.1 (the `:2025` suffix dropped for width) and
OWASP Top 10 for Agentic Applications (Version 2026), as the current rule
registry assigns them; hooks are not an MCP surface. The pre-generated results
below are a v0.2.0 scan and still carry that release's references.

## Key Insight

Manual security review of MCP configurations is error-prone and time-consuming. AgentAuditKit detected **25+ findings** across these configs in under 1 second — issues that would take a human reviewer 15-30 minutes to catalog. In CI/CD, this runs on every PR with zero manual effort.

## Pre-generated Results

- [scan-results.json](scan-results.json) — Full JSON scan output
- [scan-results.sarif](scan-results.sarif) — SARIF output for GitHub Code Scanning
