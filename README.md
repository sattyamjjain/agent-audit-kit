<p align="center">
  <h1 align="center">AgentAuditKit</h1>
  <p align="center"><strong>The missing <code>npm audit</code> for AI agents.</strong></p>
</p>

<p align="center">
  <a href="https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml"><img src="https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agent-audit-kit/"><img src="https://img.shields.io/pypi/v/agent-audit-kit.svg" alt="PyPI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="#what-it-scans"><img src="https://img.shields.io/badge/rules-144-blue.svg" alt="Rules: 144"></a>
  <a href="#frameworks--standards"><img src="https://img.shields.io/badge/OWASP_Agentic-10%2F10-green.svg" alt="OWASP Agentic: 10/10"></a>
  <a href="#frameworks--standards"><img src="https://img.shields.io/badge/OWASP_MCP-10%2F10-green.svg" alt="OWASP MCP: 10/10"></a>
  <a href="https://sattyamjjain.github.io/agent-audit-kit/"><img src="https://img.shields.io/badge/MCP_Security_Index-live-blue.svg" alt="MCP Security Index"></a>
  <a href="CHANGELOG.cves.md"><img src="https://img.shields.io/badge/CVE%E2%86%92rule_SLA-48h-orange.svg" alt="48h CVE-to-rule SLA"></a>
</p>

---

<p align="center">
  <a href="https://asciinema.org/a/9X7N1ztuuIYi9T2P" target="_blank"><img src="https://asciinema.org/a/9X7N1ztuuIYi9T2P.svg" alt="AgentAuditKit Demo" width="700"/></a>
</p>

Security scanner for MCP-connected AI agent pipelines. Finds misconfigurations, hardcoded secrets, tool poisoning, rug pulls, trust boundary violations, and tainted data flows across **13 agent platforms**.

- **<!-- rule-count:total -->144<!-- /rule-count --> rules** across 11 security categories, covering the 2026 CVE wave
- **28 scanner modules** including AST-based Python taint analysis and regex pattern scanners for TypeScript/JavaScript and Rust
- **16 CLI commands**: `scan`, `discover`, `pin`, `verify`, `fix`, `score`, `update`, `proxy`, `kill`, `watch`, plus `export-rules`, `verify-bundle`, `sbom`, `report`, `install-precommit`, and the Security-Advisories scan flag
- **OWASP coverage**: Agentic Top 10 (10/10), MCP Top 10 (10/10), Adversa AI Top 25
- **Compliance mapping** (11 frameworks): EU AI Act Art. 15 + 55, SOC 2, ISO 27001, ISO/IEC 42001, HIPAA, NIST AI RMF, Singapore Agentic AI, India DPDP 2023, **Alabama Personal Data Protection Act (HB 351, 2026)**, **Tennessee SB 1580 Health Care AI (PRA)** — PDF reports via `agent-audit-kit report --format pdf --framework <name>`
- **Supply chain**: deterministic rule bundle (`export-rules`), Sigstore-signed releases, CycloneDX + SPDX SBOM (`sbom`)
- **MCP Security Index**: weekly public leaderboard at [sattyamjjain.github.io/agent-audit-kit](https://sattyamjjain.github.io/agent-audit-kit/) — per-server grade cards (A–F), 90-day [disclosure policy](docs/disclosure-policy.md)
- **AAK Response SLA**: rule coverage within **48 hours** of any disclosed MCP CVE — ledger in [CHANGELOG.cves.md](CHANGELOG.cves.md)
- **Zero cloud dependencies** — runs fully offline, zero network calls in the default scan path

### Why This Exists

In early 2026, [30 MCP CVEs dropped in 60 days](https://www.heyuan110.com/posts/ai/2026-03-10-mcp-security-2026/). [CVE-2026-33032](https://nvd.nist.gov/vuln/detail/CVE-2026-33032) (Nginx-UI MCP auth bypass, CVSS 9.8) exposed a shared-handler pattern that several other servers have. [CVE-2025-59536](https://nvd.nist.gov/vuln/detail/CVE-2025-59536) turned a project-local Claude Code hook into RCE. [CVE-2026-34070](https://nvd.nist.gov/vuln/detail/CVE-2026-34070) hit LangChain's `load_prompt()` with absolute-path and `..` traversal. [CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852) demonstrated source-code exfiltration via a single Claude Code config flag. A 2,614-server survey found **82% of public MCP servers** had path-traversal issues. Meanwhile, every AI coding assistant adopted MCP with sparse security tooling.

AgentAuditKit is the deterministic, auditor-ready OSS scanner that closes the gap.

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
      - uses: sattyamjjain/agent-audit-kit@v0.3.0
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
    rev: v0.3.0
    hooks:
      - id: agent-audit-kit
```

### Try It Now

Scan a deliberately vulnerable config to see AgentAuditKit in action:

```bash
git clone https://github.com/sattyamjjain/agent-audit-kit
cd agent-audit-kit
pip install -e .
agent-audit-kit scan examples/vulnerable-configs/04-hook-exfiltration/
```

11 vulnerability examples covering all security categories in the [examples/](examples/) directory. See also the [damn-vulnerable-MCP-server case study](examples/case-studies/damn-vulnerable-mcp/).

---

## What It Scans

| Category | Rules | What It Detects |
|----------|:-----:|-----------------|
| **MCP Configuration** | 33 | Missing auth middleware (CVE-2026-33032 class), empty IP allowlists, wildcard CORS, path traversal in resource handlers, SSRF (CWE-918), OAuth 2.1 misconfig (PKCE/S256/DPoP), Tasks primitive leakage (SEP-1686), shell injection |
| **Tool Poisoning** | 14 | Invisible Unicode / bidi, skill frontmatter injection, SKILL.md post-install commands, data-exfil primitives, skill name hijacking, cross-tool references, rug-pull (SHA-256 pinning) |
| **Hook Injection** | 12 | Hook RCE (CVE-2025-59536 class), `shell=True` + interpolation, pre-trust execution, network-capable hooks, credential exfiltration |
| **Supply Chain** | 12 | Vulnerable LangChain versions (CVE-2026-34070, CVE-2025-68664), marketplace.json signatures / permissions / typosquat / mutable refs, unpinned packages, dangerous install scripts |
| **A2A Protocol** | 12 | Missing mutual auth, unbounded delegation, transitive trust, replay protection, schema confusion, HTTP endpoints, JWT lifetime/validation, impersonation |
| **Secret Exposure** | 9 | Anthropic/OpenAI/AWS/GitHub/GitLab/GCP keys, Shannon-entropy detection, `.env` leaks, private-key files |
| **Agent Config** | 9 | Routines permission escalation + schedule injection + audit-log gaps, AGENTS.md/CLAUDE.md/.cursorrules hijacking, hidden Unicode, encoded payloads, internal scanner-fail signal |
| **Taint Analysis** | 9 | `@tool` param flows to shell/eval/SQL/SSRF/file/deserialization sinks (Python AST), `load_prompt()` user-path reachability |
| **Trust Boundaries** | 7 | `enableAllProjectMcpServers`, API URL redirects, wildcard permissions, missing deny rules, missing allowlists |
| **Transport Security** | 4 | HTTP endpoints, TLS disabled, deprecated SSE, tokens in URL query strings |
| **Legal Compliance** | 3 | Copyleft licenses (AGPL/SSPL), missing licenses, DMCA-flagged packages |

**<!-- rule-count:total -->144<!-- /rule-count --> rules total.** Every finding includes severity, evidence, remediation, OWASP references, Adversa references, and CVE links where applicable.

### Agent Platforms Scanned

Claude Code, Cursor, VS Code Copilot, Windsurf, Amazon Q, Gemini CLI, Goose, Continue, Roo Code, Kiro + user-level global configs.

### Language Support

| Language | Scanning Method | What It Finds |
|----------|----------------|---------------|
| **Python** | AST analysis (stdlib `ast`) | `@tool` param flows to dangerous sinks (eval, subprocess, SQL, file I/O, HTTP); LangChain `load_prompt()` user-path reachability |
| **TypeScript / JS** | Regex pattern scan | `eval()`, `child_process.exec`, `fs.writeFileSync`, SSRF patterns, OAuth token passthrough in MCP server files |
| **Rust** | Regex pattern scan | `Command::new(format!())`, `unsafe` blocks, SQL macros without parameterization |

_Note: Phase 2 scanners (`ssrf_patterns`, `oauth_misconfig`, `mcp_auth_patterns`, `hook_rce`, `skill_poisoning`, `mcp_tasks`) are regex-based; a tree-sitter AST migration is tracked in [issue #22](https://github.com/sattyamjjain/agent-audit-kit/issues/22)._

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
| `agent-audit-kit export-rules --out rules.json` | Write deterministic rule bundle + SHA-256 (Sigstore-signable) |
| `agent-audit-kit verify-bundle rules.json [--signature sig]` | Verify bundle digest or Sigstore signature |
| `agent-audit-kit sbom . --format {cyclonedx,spdx}` | Emit CycloneDX 1.5 / SPDX 2.3 SBOM for MCP deps |
| `agent-audit-kit report . --framework FRAMEWORK --format pdf` | Auditor-ready compliance report (EU AI Act / SOC 2 / ISO 27001 / HIPAA / NIST AI RMF) |
| `agent-audit-kit install-precommit` | Add the hook to `.pre-commit-config.yaml` |

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
| `--strict-loading` | | Fail loudly if any optional scanner module can't be imported (default: silently skip) |
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

See [`docs/comparisons.md`](docs/comparisons.md) for a fully-sourced version. Verifiable claims only.

| Feature | AgentAuditKit | Microsoft AGT | Snyk Agent Scan | Semgrep Multimodal |
|---------|:---:|:---:|:---:|:---:|
| Scope | Static scanner + compliance PDFs | Runtime governance | Static + runtime | Multimodal SAST |
| Detection rules (static) | **<!-- rule-count:total -->144<!-- /rule-count -->** | Runtime policies, not rules | ~30 | LLM-assisted |
| OWASP Agentic 10/10 | **Yes** | Yes | Partial | Partial |
| OWASP MCP 10/10 | **Yes** | No (runtime-focused) | No | No |
| Auditor-ready PDF compliance | **11 frameworks** | No | 0 | 0 |
| Regional frameworks (IN/SG/AL/TN) | **Yes** | No | No | No |
| Sigstore-signed rule bundle | **Yes** | SLSA provenance | No | No |
| CycloneDX + SPDX SBOM output | **Yes** | No | No | No |
| Public 48h CVE-to-rule SLA | **Yes** | No | No | No |
| Public grade leaderboard | **Yes** (MCP Security Index) | No | No | No |
| Pin + drift verification | **Yes** | Yes (runtime rings) | No | No |
| Auto-fix CVE dependency bumps | **Yes** (`fix --cve`) | No | No | No |
| GitHub Security Advisories | **Yes** (`--advisories`) | No | No | No |
| Secret verification | **Yes** | No | No | No |
| A2A protocol scanning | **12 rules** | Agent Mesh | No | No |
| Healthcare-AI legal triggers | **Yes** (TN SB 1580, KS/WA/UT) | No | No | No |
| Offline / zero cloud | **Yes** | Yes | No | Optional |
| License | **MIT** | MIT | Proprietary | Proprietary |

**Microsoft AGT is an ally, not a competitor.** It governs agents at
runtime; agent-audit-kit audits them at CI time and produces the PDF an
auditor needs. Use both — the overlap is small, the reinforcement is
high. See [docs/comparisons.md](docs/comparisons.md) for the full
positioning write-up.

---

## VS Code Extension

A VS Code/Cursor extension is available in `vscode-extension/`:

```bash
cd vscode-extension && npm install && npm run compile
```

Provides inline diagnostics on file save with quick-fix suggestions.

---

## MCP Security Index

Public leaderboard of MCP servers we scan weekly:
**[sattyamjjain.github.io/agent-audit-kit](https://sattyamjjain.github.io/agent-audit-kit/)**

- Per-server grade cards (A–F)
- Weekly snapshots in `data/history.json`
- **90-day coordinated disclosure** before anything lands on a public card — see [`docs/disclosure-policy.md`](docs/disclosure-policy.md)
- Maintainer-fix earlier gets published the day the fix lands, with credit

## AAK Response SLA

We publicly commit to shipping rule coverage within **48 hours** of any disclosed MCP CVE. The ledger is [`CHANGELOG.cves.md`](CHANGELOG.cves.md) and a [GitHub Action](.github/workflows/cve-watcher.yml) watches NVD's MCP keyword feed every 6 hours.

## Supply chain

Every `v*` release publishes:

- **Wheel + sdist** on PyPI via OIDC Trusted Publisher
- **Docker image** on GHCR (`ghcr.io/sattyamjjain/agent-audit-kit:<tag>`) with SLSA provenance attestation
- **Sigstore keyless-signed rule bundle** (`rules.json` + `rules.json.sha256`)
- **CycloneDX + SPDX SBOM** (`sbom.cdx.json`, `sbom.spdx.json`)

Verify a bundle:

```bash
agent-audit-kit verify-bundle rules.json --signature rules.json.sigstore
```

---

## Contributing

```bash
git clone https://github.com/sattyamjjain/agent-audit-kit
cd agent-audit-kit
pip install -e ".[dev]"
pytest -v                          # 504 tests
ruff check .                       # Lint
mypy agent_audit_kit/              # Type check (52 source files, 0 errors)
agent-audit-kit scan .             # Self-scan
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development guide.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/sattyamjjain/agent-audit-kit/security/advisories) or see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
