# AgentAuditKit

**Security scanner for MCP-connected AI agent pipelines.**

The missing `npm audit` for the agentic AI stack. Scans MCP configurations, hooks, trust boundaries, secrets, supply chain, agent instructions, tool descriptions, and code-level taint flows.

## Quick Start

```bash
pip install agent-audit-kit
agent-audit-kit scan .
```

## Features

- **74 detection rules** across 11 categories
- **OWASP Agentic Top 10** complete mapping (ASI01-ASI10)
- **OWASP MCP Top 10** complete mapping
- **Adversa AI Top 25** mapping
- **Compliance frameworks**: EU AI Act, SOC2, ISO 27001, HIPAA, NIST AI RMF
- **Tool pinning** for rug pull detection
- **Taint analysis** for @tool function security
- **Multi-agent discovery** across 10 frameworks
- **Auto-fix** for common misconfigurations
- **Security scoring** with A-F grades and SVG badges
- **SARIF output** for GitHub Code Scanning integration
- **Pre-commit hook** and **GitHub Action** for CI/CD

## Commands

| Command | Description |
|---------|-------------|
| `agent-audit-kit scan .` | Scan a project |
| `agent-audit-kit discover` | Find all AI agent configs |
| `agent-audit-kit pin` | Pin tool definitions |
| `agent-audit-kit verify` | Verify tool pins |
| `agent-audit-kit fix` | Auto-fix issues |
| `agent-audit-kit score .` | Show security grade |
| `agent-audit-kit update` | Update vulnerability DB |
