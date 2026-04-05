# AgentAuditKit

[![CI](https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rules: 74](https://img.shields.io/badge/rules-74-red.svg)]()
[![OWASP Agentic: 10/10](https://img.shields.io/badge/OWASP_Agentic-10%2F10-green.svg)]()

**Security scanner for MCP-connected AI agent pipelines.** The missing `npm audit` for the agentic AI stack.

Scans MCP configurations, hooks, trust boundaries, secrets, supply chain, agent instructions, tool descriptions, code-level taint flows, transport security, A2A protocol configs, and license compliance — across 10 agent frameworks.

## Why This Exists

On March 31 2026, Anthropic leaked 512,000 lines of Claude Code source via npm ([CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)). Security researchers found RCE and API key exfiltration via hooks and MCP configs. OWASP published the [MCP Top 10](https://owasp.org/www-project-mcp-top-10/) and [Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). Adversa AI catalogued 25+ MCP vulnerability classes.

AgentAuditKit is the comprehensive response: **74 rules across 11 categories**, mapped to OWASP Agentic Top 10 (10/10), OWASP MCP Top 10 (10/10), and Adversa AI Top 25.

## Quick Start

```bash
pip install agent-audit-kit

# Scan a project
agent-audit-kit scan .

# Show security score
agent-audit-kit scan . --score

# SARIF output for CI/CD
agent-audit-kit scan . --format sarif -o report.sarif --ci --severity high

# Discover all agents on your machine
agent-audit-kit discover

# OWASP coverage matrix
agent-audit-kit scan . --owasp-report

# Compliance check
agent-audit-kit scan . --compliance eu-ai-act
```

## What It Scans

| Category | Rules | What It Detects |
|----------|-------|-----------------|
| MCP Configuration | 10 | Remote servers without auth, shell injection, hardcoded secrets, headersHelper abuse |
| Hook Injection | 9 | Network-capable hooks, credential exfiltration, privilege escalation, obfuscation |
| Trust Boundaries | 7 | enableAllProjectMcpServers, API URL redirects, wildcard permissions |
| Secret Exposure | 9 | Anthropic/OpenAI/AWS/GitHub/GCP keys, high-entropy secrets, .env leaks |
| Supply Chain | 6 | Unpinned packages, known vulns, dangerous install scripts, missing lockfiles |
| Agent Config | 5 | AGENTS.md hijacking, .cursorrules injection, hidden Unicode, credential refs |
| Tool Poisoning | 9 | Invisible Unicode, prompt injection, cross-tool references, rug pull detection |
| Taint Analysis | 8 | @tool param flows to shell/eval/SQL/SSRF/file/deserialization sinks |
| Transport Security | 4 | HTTP instead of HTTPS, TLS disabled, deprecated SSE, tokens in URLs |
| A2A Protocol | 4 | Agent Card auth, internal capabilities, missing schemas, HTTP endpoints |
| Legal Compliance | 3 | Copyleft licenses, missing licenses, DMCA-flagged packages |

## CLI Commands

| Command | Description |
|---------|-------------|
| `agent-audit-kit scan .` | Full security scan |
| `agent-audit-kit discover` | Find all AI agent configs on machine |
| `agent-audit-kit pin .` | Pin tool definitions (rug pull baseline) |
| `agent-audit-kit verify .` | Check tool pins for changes |
| `agent-audit-kit fix . --dry-run` | Auto-fix known issues |
| `agent-audit-kit score .` | Show security grade + SVG badge |
| `agent-audit-kit update` | Update vulnerability database |
| `agent-audit-kit proxy --target URL` | Start runtime MCP proxy |
| `agent-audit-kit kill` | Terminate proxy |

## Scan Options

```
--format [console|json|sarif]   Output format
--severity [critical|high|medium|low|info]   Minimum severity
--ci                            Exit code 1 if findings found
--score                         Show security score/grade
--owasp-report                  OWASP coverage matrix
--compliance FRAMEWORK          EU AI Act, SOC2, ISO 27001, HIPAA, NIST AI RMF
--verify-secrets                Active API key verification
--diff BASE_REF                 Only scan changed files
--llm-scan                      Local LLM semantic analysis (requires Ollama)
--include-user-config           Scan ~/.claude/ configs
--ignore-paths PATHS            Skip comma-separated paths
--rules / --exclude-rules       Filter by rule IDs
```

## Frameworks & Standards Coverage

| Framework | Coverage |
|-----------|----------|
| OWASP Agentic Top 10 (ASI01-ASI10) | **10/10 (100%)** |
| OWASP MCP Top 10 (MCP01-MCP10) | **10/10 (100%)** |
| Adversa AI MCP Security Top 25 | **Fully mapped** |
| EU AI Act | 5 controls mapped |
| SOC 2 Type II | 7 controls mapped |
| ISO 27001:2022 | 6 controls mapped |
| HIPAA Security Rule | 5 controls mapped |
| NIST AI RMF 1.0 | 5 controls mapped |

## Agent Discovery (10 Frameworks)

Automatically discovers configurations for:
Claude Code, Cursor, VS Code Copilot, Windsurf, Amazon Q, Gemini CLI, Goose, Continue, Roo Code, Kiro

## CI/CD Integration

### GitHub Actions
```yaml
- uses: sattyamjjain/agent-audit-kit@v0.2.0
  with:
    severity: low
    fail-on: high
```

### Pre-commit
```yaml
repos:
  - repo: https://github.com/sattyamjjain/agent-audit-kit
    rev: v0.2.0
    hooks:
      - id: agent-audit-kit
```

## Comparison

| Feature | AgentAuditKit | mcp-scan | Snyk Agent | Agent Audit |
|---------|:---:|:---:|:---:|:---:|
| Rules | **74** | ~10 | ~15 | 57 |
| MCP config scanning | Yes | No | Yes | No |
| Hook injection | Yes | No | No | No |
| Agent instruction scanning | Yes | No | No | No |
| Tool poisoning + pinning | Yes | Yes | Yes | No |
| Taint analysis (@tool) | Yes | No | No | Yes |
| A2A protocol | **Yes** | No | No | No |
| OWASP Agentic 10/10 | **Yes** | No | Partial | Yes |
| Compliance frameworks | **5** | 0 | 0 | 0 |
| Auto-fix | **Yes** | No | No | No |
| Runtime proxy | Yes | No | No | No |
| Offline / no network | Yes | No | No | Yes |

## Development

```bash
pip install -e ".[dev]"
pytest -v
agent-audit-kit scan .
```

## License

MIT
