<p align="center">
  <h1 align="center">AgentAuditKit</h1>
  <p align="center"><strong>The missing <code>npm audit</code> for AI agents.</strong></p>
</p>

<p align="center">
  <a href="https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml"><img src="https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agent-audit-kit/"><img src="https://img.shields.io/pypi/v/agent-audit-kit.svg" alt="PyPI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="#what-it-scans"><img src="https://img.shields.io/badge/rules-219-blue.svg" alt="Rules: 219"></a>
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

- **<!-- rule-count:total -->219<!-- /rule-count --> rules** across 11 security categories, covering the 2026 CVE wave
- **<!-- scanner-count:total -->73<!-- /scanner-count --> scanner modules** including AST-based Python taint analysis and regex pattern scanners for TypeScript/JavaScript and Rust
- **16 CLI commands**: `scan`, `discover`, `pin`, `verify`, `fix`, `score`, `update`, `proxy`, `kill`, `watch`, plus `export-rules`, `verify-bundle`, `sbom`, `report`, `install-precommit`, and the Security-Advisories scan flag
- **OWASP coverage**: Agentic Top 10 (10/10), MCP Top 10 (10/10), Adversa AI Top 25
- **Compliance mapping** (13 frameworks): EU AI Act Art. 15 + 55, SOC 2, ISO 27001, ISO/IEC 42001, HIPAA, NIST AI RMF, **NSA MCP Security CSI (U/OO/6030316-26, May 2026)**, Singapore Agentic AI, India DPDP 2023, **Alabama Personal Data Protection Act (HB 351, 2026)**, **Tennessee SB 1580 Health Care AI (PRA)**, **MCP 2026 Roadmap (May 2026)** — PDF reports via `agent-audit-kit report --format pdf --framework <name>`
- **Supply chain**: deterministic rule bundle (`export-rules`), Sigstore-signed releases, CycloneDX + SPDX SBOM (`sbom`)
- **MCP Security Index**: weekly public leaderboard at [sattyamjjain.github.io/agent-audit-kit](https://sattyamjjain.github.io/agent-audit-kit/) — per-server grade cards (A–F), 90-day [disclosure policy](docs/disclosure-policy.md)
- **AAK Response SLA**: rule coverage within **48 hours** of any disclosed MCP CVE — ledger in [CHANGELOG.cves.md](CHANGELOG.cves.md)
- **Zero cloud dependencies** — runs fully offline, zero network calls in the default scan path

### Why This Exists

In early 2026, [30 MCP CVEs dropped in 60 days](https://www.heyuan110.com/posts/ai/2026-03-10-mcp-security-2026/). [CVE-2026-33032](https://nvd.nist.gov/vuln/detail/CVE-2026-33032) (Nginx-UI MCP auth bypass, CVSS 9.8) exposed a shared-handler pattern that several other servers have. [CVE-2025-59536](https://nvd.nist.gov/vuln/detail/CVE-2025-59536) turned a project-local Claude Code hook into RCE. [CVE-2026-34070](https://nvd.nist.gov/vuln/detail/CVE-2026-34070) hit LangChain's `load_prompt()` with absolute-path and `..` traversal. [CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852) demonstrated source-code exfiltration via a single Claude Code config flag. A 2,614-server survey found **82% of public MCP servers** had path-traversal issues. On 2026-05-01, [OX Security disclosed 10+ CVEs](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/) across DocsGPT, GPT-Researcher, Agent-Zero, LettaAI, LiteLLM, LangFlow, Flowise, Bisheng, and Langchain-Chatchat — all rooted in the same MCP STDIO command-injection class `AAK-MCP-STDIO-CMD-INJ-*` covers. Meanwhile, every AI coding assistant adopted MCP with sparse security tooling.

AgentAuditKit is the deterministic, auditor-ready OSS scanner that closes the gap.

> **Architectural note:** AAK rules are multi-arm adjudicators (pin arm + source/config arm + explicit-reject short-circuit + adjudicator log), not single-shot regex matchers. See [docs/notes/adjudicator-pattern.md](docs/notes/adjudicator-pattern.md) for the four-arm structure and the Mozilla / arXiv precedents.

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
      - uses: sattyamjjain/agent-audit-kit@v0.3.32
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
    rev: v0.3.32
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
| **MCP Configuration** | <!-- category-count:MCP_CONFIG -->49<!-- /category-count --> | Missing auth middleware (CVE-2026-33032 class), empty IP allowlists, wildcard CORS, path traversal in resource handlers, SSRF (CWE-918), OAuth 2.1 misconfig (PKCE/S256/DPoP), Tasks primitive leakage (SEP-1686), shell injection, MCPwn middleware-asymmetry, Azure MCP no-auth (CVE-2026-32211), MCP Inspector vendored fork (CVE-2026-23744), 2026-07-28 stateless-MCP migration (`Mcp-Session-Id` reliance, removed `tasks/list`, sticky-session deployment, un-cached client `tools/list`), deny-by-default attested admission (signed clearance / `/.well-known/mcp-clearance` / pinned trust root — arXiv:2605.24248), Anthropic MCP Tunnels gateway (SSRF defense disabled / `upstream.disable_ip_validation`, HTTPS upstream missing `upstream.tls.ca_file` trust anchor, tunnel token + TLS private keys hardcoded in CI / committed Kubernetes Secrets — research preview 2026-05-19), stdio launcher injection (`npx`/`node`/`bash`/`sh`/`python` with `-c`/`-e`/`--eval`, or non-pinned interpolated argv — CVE-2026-40933), tool-gate enforcement asymmetry (allowlist / read-only / non-destructive check applied in `tools/list` but not `tools/call` — CVE-2026-46519) |
| **Supply Chain** | <!-- category-count:SUPPLY_CHAIN -->40<!-- /category-count --> | Vulnerable LangChain / langchain-text-splitters versions, named pin rules for `astro-mcp-server` / `chatgpt-mcp-server` / `docsgpt` / `gpt-researcher` / `litellm` / `mcp-calculate-server` / `semantic-kernel` / `@anthropic-ai/claude-code` / `apache-doris-mcp-server` / `excel-mcp-server`, OX MCP-STDIO command-injection (Python/TS/Java/Rust) — `AAK-MCP-STDIO-CMD-INJ-001..004` — Stainless-generator lineage, marketplace.json signatures / typosquat / mutable refs, unpinned packages, dangerous install scripts |
| **Tool Poisoning** | <!-- category-count:TOOL_POISONING -->26<!-- /category-count --> | Invisible Unicode / bidi, skill frontmatter injection, SKILL.md post-install commands, data-exfil primitives, skill name hijacking, cross-tool references, rug-pull (SHA-256 pinning), `@mcp.tool` unsafe-eval (CVE-2026-44717 generalization), OpenAPI smells (Hermes paper LAZY/BLOATED/TANGLED), Metis POMDP refusal-refeed + scoring-sink, SkillsVote lifecycle attribution, MCP Calculate Server pin. Indirect-prompt-injection detection (`AAK-POISON-001..006`) runs against tool descriptions **and** every per-parameter `inputSchema.properties.*.description` (recursive — nested objects, array items, `anyOf`/`allOf`/`oneOf`), so instruction text hidden in a single argument's docstring is caught |
| **Secret Exposure** | <!-- category-count:SECRET_EXPOSURE -->17<!-- /category-count --> | Anthropic/OpenAI/AWS/GitHub/GitLab/GCP keys, Shannon-entropy detection, `.env` leaks, private-key files, hardcoded credential surface, token-leak via log sinks (CVE-2026-20205) |
| **Agent Config** | <!-- category-count:AGENT_CONFIG -->15<!-- /category-count --> | Routines permission escalation + schedule injection + audit-log gaps, AGENTS.md/CLAUDE.md/.cursorrules hijacking, hidden Unicode, encoded payloads, internal scanner-fail signal, Project Deal economic-drift detection |
| **A2A Protocol** | <!-- category-count:A2A_PROTOCOL -->13<!-- /category-count --> | Missing mutual auth, unbounded delegation, transitive trust, replay protection, schema confusion, HTTP endpoints, JWT lifetime/validation, impersonation, multi-agent shared-state without lock (Code-as-Harness) |
| **Hook Injection** | <!-- category-count:HOOK_INJECTION -->12<!-- /category-count --> | Hook RCE (CVE-2025-59536 class), `shell=True` + interpolation, pre-trust execution, network-capable hooks, credential exfiltration |
| **Taint Analysis** | <!-- category-count:TAINT_ANALYSIS -->12<!-- /category-count --> | `@tool` param flows to shell/eval/SQL/SSRF/file/deserialization sinks (Python AST), `load_prompt()` user-path reachability, transport-flip MITM (DocsGPT + GPT-Researcher). SQL-injection sinks (`AAK-TAINT-005`) now detected in TypeScript/JS MCP servers too — interpolated/concatenated `.query()`/`.execute()`, `knex.raw`, Prisma `$queryRawUnsafe` — matching the Python + Rust scanners (OX MCP-SDK disclosure class) |
| **Transport Security** | <!-- category-count:TRANSPORT_SECURITY -->11<!-- /category-count --> | HTTP endpoints, TLS disabled, deprecated SSE, tokens in URL query strings, transport body-size limits (CVE-2026-39313), SSRF redirect bypass (CVE-2026-41481), DNS-rebinding (CVE-2025-66414/66416, CVE-2026-35568/35577) |
| **Legal Compliance** | <!-- category-count:LEGAL_COMPLIANCE -->12<!-- /category-count --> | Copyleft licenses (AGPL/SSPL), missing licenses, DMCA-flagged packages, India PII surface, US-state consumer privacy (Alabama HB 351, Tennessee SB 1580), Singapore Agentic AI, healthcare AI triggers, EU AI Act Article 15 multilingual-eval coverage advisory (binding 2026-08-02) |
| **Trust Boundaries** | <!-- category-count:TRUST_BOUNDARY -->12<!-- /category-count --> | `enableAllProjectMcpServers`, API URL redirects, wildcard permissions, missing deny rules, missing allowlists, Claude Code folder-trust bypass (CVE-2026-40068) |

**<!-- rule-count:total -->219<!-- /rule-count --> rules total.** Every finding includes severity, evidence, remediation, OWASP references, Adversa references, and CVE links where applicable.

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
| `--compliance FRAMEWORK` | | Compliance report: `eu-ai-act`, `soc2`, `iso27001`, `hipaa`, `nist-ai-rmf`, `mcp-2026-roadmap` |
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
| **OWASP Agentic Top 10** (ASI01-ASI10) | 10/10 (100%) — density by slot below |
| **OWASP MCP Top 10** (MCP01-MCP10) | 10/10 (100%) |

<details>
<summary>OWASP Agentic Top 10 — density by slot</summary>

<!-- owasp-coverage:start -->
| ASI | Title | # rules |
| --- | --- | --- |
| **ASI01** | Goal Hijack | 11 |
| **ASI02** | Tool Misuse | 36 |
| **ASI03** | Memory Poisoning | 51 |
| **ASI04** | Identity & Privilege Abuse | 37 |
| **ASI05** | Cascading Failures | 32 |
| **ASI06** | Unauthorized Capability Acquisition | 27 |
| **ASI07** | Plan Injection | 9 |
| **ASI08** | Agent Communication Poisoning | 4 |
| **ASI09** | Resource Abuse | 14 |
| **ASI10** | Supply-Chain | 20 |
<!-- owasp-coverage:end -->

</details>

| **Adversa AI MCP Security Top 25** | Fully mapped |
| **EU AI Act** | `--compliance eu-ai-act` |
| **SOC 2 Type II** | `--compliance soc2` |
| **ISO 27001:2022** | `--compliance iso27001` |
| **HIPAA Security Rule** | `--compliance hipaa` |
| **NIST AI RMF 1.0** | `--compliance nist-ai-rmf` |
| **MCP 2026 Roadmap (May 2026)** | `--compliance mcp-2026-roadmap` |

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
| Detection rules (static) | **<!-- rule-count:total -->219<!-- /rule-count -->** | Runtime policies, not rules | ~30 | LLM-assisted |
| OWASP Agentic 10/10 | **Yes** | Yes | Partial | Partial |
| OWASP MCP 10/10 | **Yes** | No (runtime-focused) | No | No |
| Auditor-ready PDF compliance | **12 frameworks** | No | 0 | 0 |
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
