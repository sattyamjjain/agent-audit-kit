# AgentAuditKit

[![CI](https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rules: 74](https://img.shields.io/badge/rules-74-red.svg)]()
[![OWASP Agentic: 10/10](https://img.shields.io/badge/OWASP_Agentic-10%2F10-green.svg)]()

**Security scanner for MCP-connected AI agent pipelines.**

- **March 31, 2026:** Anthropic leaked 512K lines of Claude Code source via npm ([CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)). RCE + API key exfiltration found within hours.
- **The gap:** No scanner checks project-level MCP configs, hooks, trust boundaries, or agent instruction files.
- **AgentAuditKit fills it:** 74 rules across 11 categories, mapped to OWASP Agentic Top 10 (10/10), OWASP MCP Top 10, and Adversa AI Top 25.

---

## Quick Start — GitHub Action (Recommended)

Add one file to your repo. No install required.

```yaml
# .github/workflows/agent-security.yml
name: Agent Security Scan
on: [push, pull_request]

permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sattyamjjain/agent-audit-kit@v1
        with:
          fail-on: high
```

Findings appear as inline PR annotations in the GitHub Security tab. PRs are blocked if findings exceed your threshold.

## Quick Start — CLI

```bash
pip install agent-audit-kit
agent-audit-kit scan .
```

CI mode (SARIF output + exit code enforcement):
```bash
agent-audit-kit scan . --ci
# Equivalent to: --format sarif --fail-on high --output agent-audit-results.sarif
```

With explicit threshold:
```bash
agent-audit-kit scan . --fail-on critical --format console
```

## Quick Start — Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/sattyamjjain/agent-audit-kit
    rev: v0.2.0
    hooks:
      - id: agent-audit-kit
```

---

## What It Scans

| Category | Rules | What It Detects |
|----------|-------|-----------------|
| MCP Configuration | 10 | Remote servers without auth, shell injection, hardcoded secrets, headersHelper abuse, filesystem root access |
| Hook Injection | 9 | Network-capable hooks, credential exfiltration, privilege escalation, obfuscation, source file access |
| Trust Boundaries | 7 | enableAllProjectMcpServers, API URL redirects, wildcard permissions, missing allowlists |
| Secret Exposure | 9 | Anthropic/OpenAI/AWS/GitHub/GCP keys, high-entropy secrets, .env leaks |
| Supply Chain | 6 | Unpinned packages, known vulns, dangerous install scripts, missing lockfiles |
| Agent Config | 5 | AGENTS.md hijacking, .cursorrules injection, hidden Unicode, credential refs |
| Tool Poisoning | 9 | Invisible Unicode, prompt injection, cross-tool references, rug pull detection |
| Taint Analysis | 8 | @tool param flows to shell/eval/SQL/SSRF/file/deserialization sinks |
| Transport Security | 4 | HTTP instead of HTTPS, TLS disabled, deprecated SSE, tokens in URLs |
| A2A Protocol | 4 | Agent Card auth, internal capabilities, missing schemas, HTTP endpoints |
| Legal Compliance | 3 | Copyleft licenses, missing licenses, DMCA-flagged packages |

**74 rules total.** Every finding includes severity, remediation, OWASP references, and CVE links where applicable.

---

## Configuration

Create `.agent-audit-kit.yml` in your project root:

```yaml
severity: medium
fail-on: high
ignore-paths:
  - vendor/
  - third_party/
exclude-rules:
  - AAK-MCP-007    # We intentionally don't pin npx versions
include-user-config: false
```

CLI flags override config file values.

---

## GitHub Action Reference

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `severity` | `low` | Minimum severity to report |
| `fail-on` | `high` | Fail workflow at this severity or above. `none` = never fail |
| `format` | `sarif` | Output format: `sarif`, `json`, `text` |
| `upload-sarif` | `true` | Upload SARIF to GitHub Security tab |
| `include-user-config` | `false` | Scan user-level agent configs |
| `rules` | (all) | Comma-separated rule IDs to run |
| `exclude-rules` | | Comma-separated rule IDs to skip |
| `ignore-paths` | | Comma-separated paths to exclude |
| `config` | | Path to .agent-audit-kit.yml |

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total findings |
| `critical-count` | Critical findings |
| `high-count` | High findings |
| `sarif-file` | Path to SARIF output |
| `exit-code` | 0=pass, 1=findings exceed threshold |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan passed — no findings exceed `fail-on` threshold |
| 1 | Scan failed — one or more findings meet or exceed `fail-on` severity |
| 2 | Error — invalid path, malformed config, etc. |

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `agent-audit-kit scan .` | Full security scan |
| `agent-audit-kit scan . --ci` | CI mode: SARIF + fail-on high |
| `agent-audit-kit scan . --fail-on critical` | Fail only on critical |
| `agent-audit-kit discover` | Find all AI agent configs |
| `agent-audit-kit pin .` | Pin tool definitions |
| `agent-audit-kit verify .` | Check tool pins |
| `agent-audit-kit fix . --dry-run` | Auto-fix issues |
| `agent-audit-kit score .` | Security grade + badge |
| `agent-audit-kit update` | Update vuln database |

---

## SARIF Integration

When using the GitHub Action with `upload-sarif: true`, findings appear:
- As inline annotations on PR diff (exactly which line has the issue)
- In the GitHub Security tab under Code Scanning
- With remediation guidance and OWASP references

---

## Frameworks & Standards

| Framework | Coverage |
|-----------|----------|
| OWASP Agentic Top 10 (ASI01-ASI10) | **10/10 (100%)** |
| OWASP MCP Top 10 | **Fully mapped** |
| Adversa AI MCP Security Top 25 | **Fully mapped** |
| EU AI Act, SOC2, ISO 27001, HIPAA, NIST AI RMF | `--compliance` flag |

---

## Agent Discovery

Detects configs for: Claude Code, Cursor, VS Code Copilot, Windsurf, Amazon Q, Gemini CLI, Goose, Continue, Roo Code, Kiro

---

## Comparison

| Feature | AgentAuditKit | mcp-scan | Snyk Agent Scan |
|---------|:---:|:---:|:---:|
| Rules | **74** | ~10 | ~15 |
| GitHub Action | **Yes** | No | No |
| MCP config scanning | Yes | No | Yes |
| Hook injection | Yes | No | No |
| Tool poisoning + pinning | Yes | Yes | Yes |
| Taint analysis | Yes | No | No |
| OWASP Agentic 10/10 | **Yes** | No | Partial |
| Compliance frameworks | **5** | 0 | 0 |
| Auto-fix | **Yes** | No | No |
| Offline / no network | Yes | No | No |

---

## Contributing

```bash
git clone https://github.com/sattyamjjain/agent-audit-kit
cd agent-audit-kit
pip install -e ".[dev]"
pytest -v
agent-audit-kit scan .
```

## License

MIT
