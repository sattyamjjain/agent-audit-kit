<p align="center">
  <h1 align="center">AgentAuditKit</h1>
  <p align="center"><strong>The missing <code>npm audit</code> for AI agents.</strong></p>
</p>

<p align="center">
  <a href="https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml"><img src="https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agent-audit-kit/"><img src="https://img.shields.io/pypi/v/agent-audit-kit.svg" alt="PyPI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="#what-it-scans"><img src="https://img.shields.io/badge/rules-77-red.svg" alt="Rules: 77"></a>
  <a href="#frameworks--standards"><img src="https://img.shields.io/badge/OWASP_Agentic-10%2F10-green.svg" alt="OWASP Agentic: 10/10"></a>
  <a href="#frameworks--standards"><img src="https://img.shields.io/badge/OWASP_MCP-10%2F10-green.svg" alt="OWASP MCP: 10/10"></a>
</p>

---

Security scanner for MCP-connected AI agent pipelines. Finds misconfigurations, hardcoded secrets, tool poisoning, rug pulls, trust boundary violations, and tainted data flows across **13 agent platforms**.

- **77 rules** across 11 security categories
- **13 scanner modules** including Python/TypeScript/Rust taint analysis
- **9 CLI commands**: scan, discover, pin, verify, fix, score, update, proxy, kill
- **OWASP coverage**: Agentic Top 10 (10/10), MCP Top 10 (10/10), Adversa AI Top 25
- **Compliance mapping**: EU AI Act, SOC 2, ISO 27001, HIPAA, NIST AI RMF
- **Zero cloud dependencies** — runs fully offline, zero network calls in the scan path

### Why This Exists

In early 2026, [30 MCP CVEs dropped in 60 days](https://www.heyuan110.com/posts/ai/2026-03-10-mcp-security-2026/). [CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852) demonstrated source code exfiltration via a single Claude Code config flag. [CVE-2026-32211](https://dev.to/michael_onyekwere/cve-2026-32211-what-the-azure-mcp-server-flaw-means-for-your-agent-security-14db) (CVSS 9.1) hit Azure MCP servers. Meanwhile, every AI coding assistant adopted MCP with zero security tooling.

---

## Quick Start

### GitHub Action (Recommended)

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
      - uses: sattyamjjain/agent-audit-kit@v0.2.0
        with:
          fail-on: high
```

Findings appear as **inline PR annotations** in the GitHub Security tab via SARIF.

### CLI

```bash
pip install agent-audit-kit
agent-audit-kit scan .
```

### Pre-commit Hook

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
|----------|:-----:|-----------------|
| **MCP Configuration** | 10 | Remote servers without auth, shell injection, hardcoded secrets, headersHelper abuse, SSRF, filesystem root access |
| **Hook Injection** | 9 | Network-capable hooks, credential exfiltration, privilege escalation, obfuscated payloads, source file references |
| **Trust Boundaries** | 7 | `enableAllProjectMcpServers`, API URL redirects, wildcard permissions, missing deny rules, missing allowlists |
| **Secret Exposure** | 9 | Anthropic/OpenAI/AWS/GitHub/GitLab/GCP keys, Shannon entropy detection, .env leaks, private key files |
| **Supply Chain** | 6 | Unpinned packages, known vulnerable deps, dangerous install scripts, missing lockfiles, MCP-specific CVEs |
| **Agent Config** | 5 | AGENTS.md/CLAUDE.md/.cursorrules hijacking, hidden Unicode, credential references, encoded payloads |
| **Tool Poisoning** | 9 | Invisible Unicode, prompt injection, cross-tool references, rug pull detection (SHA-256 pinning) |
| **Taint Analysis** | 8 | `@tool` param flows to shell/eval/SQL/SSRF/file/deserialization sinks (Python AST) |
| **Transport Security** | 4 | HTTP endpoints, TLS disabled, deprecated SSE, tokens in URL query strings |
| **A2A Protocol** | 7 | Agent Card auth, internal capabilities, missing schemas, HTTP endpoints, JWT lifetime/validation, impersonation |
| **Legal Compliance** | 3 | Copyleft licenses (AGPL/SSPL), missing licenses, DMCA-flagged packages |

**77 rules total.** Every finding includes severity, evidence, remediation, OWASP references, Adversa references, and CVE links where applicable.

### Agent Platforms Scanned

Claude Code, Cursor, VS Code Copilot, Windsurf, Amazon Q, Gemini CLI, Goose, Continue, Roo Code, Kiro + user-level global configs.

### Language Support

| Language | Scanning Method | What It Finds |
|----------|----------------|---------------|
| **Python** | AST analysis | `@tool` param flows to dangerous sinks (eval, subprocess, SQL, file I/O, HTTP) |
| **TypeScript** | Regex-based | `eval()`, `child_process.exec`, `fs.writeFileSync` in MCP server files |
| **Rust** | Regex-based | `Command::new(format!())`, `unsafe` blocks, SQL macros without parameterization |

---

## CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `agent-audit-kit scan .` | Full security scan |
| `agent-audit-kit scan . --ci` | CI mode: SARIF + `--fail-on high` |
| `agent-audit-kit discover` | Find all AI agent configs on the machine |
| `agent-audit-kit pin .` | Pin tool definitions (SHA-256 hashes) |
| `agent-audit-kit verify .` | Check tools against pins (detect rug pulls) |
| `agent-audit-kit fix . --dry-run` | Auto-fix common misconfigurations |
| `agent-audit-kit score .` | Security grade (A-F) + SVG badge |
| `agent-audit-kit update` | Update vulnerability database |
| `agent-audit-kit proxy --port 8765 --target URL` | Start MCP interception proxy |
| `agent-audit-kit kill` | Terminate running proxy |

### Scan Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `console` | Output: `console`, `json`, `sarif` |
| `--severity` | `low` | Minimum severity to report |
| `--fail-on` | `none` | Exit 1 at this severity: `critical`, `high`, `medium`, `low`, `none` |
| `--output` / `-o` | stdout | Write output to file |
| `--ci` | | Shorthand: `--format sarif --fail-on high -o agent-audit-results.sarif` |
| `--config` | | Path to `.agent-audit-kit.yml` |
| `--rules` | all | Comma-separated rule IDs to include |
| `--exclude-rules` | | Comma-separated rule IDs to skip |
| `--ignore-paths` | | Comma-separated paths to exclude |
| `--include-user-config` | | Also scan `~/.claude/`, `~/.cursor/`, etc. |
| `--score` | | Show security score and grade |
| `--owasp-report` | | Generate OWASP coverage matrix |
| `--compliance FRAMEWORK` | | Compliance report: `eu-ai-act`, `soc2`, `iso27001`, `hipaa`, `nist-ai-rmf` |
| `--verify-secrets` | | Probe APIs to check if leaked keys are live (opt-in) |
| `--diff BASE_REF` | | Only report findings in files changed since BASE_REF |
| `--llm-scan` | | Local LLM semantic analysis via Ollama (opt-in) |
| `--verbose` / `-v` | | Detailed scan progress |

### Exit Codes

| Code | Meaning |
|:----:|---------|
| 0 | Scan passed — no findings exceed `--fail-on` threshold |
| 1 | Scan failed — findings meet or exceed `--fail-on` severity |
| 2 | Error — invalid path, malformed config, etc. |

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

CLI flags always take precedence over config file values.

---

## GitHub Action Reference

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `severity` | `low` | Minimum severity to report |
| `fail-on` | `high` | Fail at this severity or above (`none` = never fail) |
| `format` | `sarif` | Output format: `sarif`, `json`, `console` |
| `upload-sarif` | `true` | Upload SARIF to GitHub Security tab |
| `include-user-config` | `false` | Scan user-level agent configs |
| `rules` | | Comma-separated rule IDs to include |
| `exclude-rules` | | Comma-separated rule IDs to skip |
| `ignore-paths` | | Comma-separated paths to exclude |
| `config` | | Path to `.agent-audit-kit.yml` |

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings |
| `critical-count` | Count of CRITICAL findings |
| `high-count` | Count of HIGH findings |
| `sarif-file` | Path to SARIF output file |
| `exit-code` | 0 = pass, 1 = findings exceed threshold |

---

## SARIF Integration

With `upload-sarif: true` (default), findings appear:
- As **inline annotations** on PR diffs showing exactly which line has the issue
- In the **Security tab** under Code Scanning with full remediation guidance
- With **OWASP references** and **CVE links** for each finding

SARIF output conforms to [SARIF 2.1.0](https://json.schemastore.org/sarif-2.1.0.json) with `fingerprints`, `partialFingerprints`, `fixes[]`, `security-severity` scores, and `%SRCROOT%` relative paths.

---

## Security Scoring

```bash
agent-audit-kit score .
# Security Score: 85/100  Grade: B
```

| Grade | Score | Meaning |
|:-----:|:-----:|---------|
| A | 90-100 | Excellent — minimal risk |
| B | 75-89 | Good — minor issues |
| C | 60-74 | Fair — needs attention |
| D | 40-59 | Poor — significant risk |
| F | 0-39 | Critical — immediate action required |

Generate an SVG badge for your README: `agent-audit-kit score . --badge`

---

## Frameworks & Standards

| Framework | Coverage |
|-----------|----------|
| **OWASP Agentic Top 10** (ASI01-ASI10) | 10/10 (100%) |
| **OWASP MCP Top 10** (MCP01-MCP10) | 10/10 (100%) |
| **Adversa AI MCP Security Top 25** | Fully mapped |
| **EU AI Act** | `--compliance eu-ai-act` |
| **SOC 2 Type II** | `--compliance soc2` |
| **ISO 27001:2022** | `--compliance iso27001` |
| **HIPAA Security Rule** | `--compliance hipaa` |
| **NIST AI RMF 1.0** | `--compliance nist-ai-rmf` |

---

## Tool Pinning & Rug Pull Detection

MCP servers can silently change tool definitions after you approve them. AgentAuditKit detects this:

```bash
# Create initial pins (commit tool-pins.json to git)
agent-audit-kit pin .

# In CI, verify nothing changed
agent-audit-kit verify .
```

Detects: tool definitions changed (AAK-RUGPULL-001), new tools added (AAK-RUGPULL-002), tools removed (AAK-RUGPULL-003).

---

## Comparison

| Feature | AgentAuditKit | mcp-scan | Snyk Agent Scan | Microsoft AGT |
|---------|:---:|:---:|:---:|:---:|
| Detection rules | **77** | ~10 | ~30 | ~20 |
| Agent platforms | **13** | 1 | 3 | 1 |
| GitHub Action | **Yes** | No | Yes | No |
| Tool poisoning + pinning | **Yes** | Yes | Yes | No |
| Taint analysis (Python/TS/Rust) | **Yes** | No | Partial | No |
| OWASP Agentic 10/10 | **Yes** | No | Partial | Yes |
| OWASP MCP 10/10 | **Yes** | No | No | No |
| Compliance frameworks | **5** | 0 | 0 | 0 |
| Auto-fix | **Yes** | No | No | No |
| Secret verification | **Yes** | No | No | No |
| A2A protocol scanning | **Yes** | No | No | No |
| Offline / zero cloud | **Yes** | No | No | Yes |
| Runtime proxy | **Yes** | No | No | Yes |
| Open source | **MIT** | Partial | No | MIT |

---

## VS Code Extension

A VS Code/Cursor extension is available in `vscode-extension/`:

```bash
cd vscode-extension && npm install && npm run compile
```

Provides inline diagnostics on file save with quick-fix suggestions.

---

## Contributing

```bash
git clone https://github.com/sattyamjjain/agent-audit-kit
cd agent-audit-kit
pip install -e ".[dev]"
pytest -v                          # 441 tests, 90% coverage
ruff check agent_audit_kit/        # Lint
mypy agent_audit_kit/ --ignore-missing-imports  # Type check
agent-audit-kit scan .             # Self-scan
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development guide.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/sattyamjjain/agent-audit-kit/security/advisories) or see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
