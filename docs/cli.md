# CLI reference

Moved out of the README on 2026-09-12 so the front page stays scannable.
Nothing here was cut; it is the same content with a home of its own.


### Commands

| Command | Description |
|---------|-------------|
| `agent-audit-kit scan .` | Full security scan |
| `agent-audit-kit scan . --ci` | CI mode: SARIF + `--fail-on high` |
| `agent-audit-kit discover` | Find all AI agent configs on the machine |
| `agent-audit-kit pin .` | Pin tool definitions (SHA-256 hashes) |
| `agent-audit-kit verify .` | Check tools against pins (detect rug pulls) |
| `agent-audit-kit fix . --dry-run` | Auto-fix common misconfigurations |
| `agent-audit-kit suggest run.sarif --pr` | Markdown remediation body for `gh pr create --body-file -` |
| `agent-audit-kit suggest run.sarif --auto-pr` | Apply allow-listed mechanical fixes on a branch and open a **draft** PR |
| `agent-audit-kit score .` | Security grade (A-F) + SVG badge |
| `agent-audit-kit update` | Update vulnerability database |
| `agent-audit-kit proxy --port 8765 --target URL` | Start MCP interception proxy |
| `agent-audit-kit kill` | Terminate running proxy |
| `agent-audit-kit export-rules --out rules.json` | Write deterministic rule bundle + SHA-256 (Sigstore-signable) |
| `agent-audit-kit verify-bundle rules.json [--signature sig]` | Verify bundle digest or Sigstore signature |
| `agent-audit-kit sbom . --format {cyclonedx,spdx}` | Emit CycloneDX 1.5 / SPDX 2.3 SBOM for MCP deps |
| `agent-audit-kit vex .` | Emit an OpenVEX 0.2.0 exploitability document, joined to the SBOM on purl |
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
| `--sessions PATH` | | Run the session-scoped rules over agent transcripts — OpenAI Agents SDK traces, LangGraph checkpoints, JSONL. See [Session transcripts](https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/session-transcripts.md) |
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
## SARIF Integration

This action **emits** SARIF (the `sarif-file` output); it does **not** upload to
Code Scanning itself. Add the canonical `github/codeql-action/upload-sarif` step
so findings appear in the **Security tab** and as **inline PR annotations**:

```yaml
permissions:
  security-events: write   # required for the upload
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: sattyamjjain/agent-audit-kit@v0.6.3
    id: scan
    with:
      fail-on: high
  - uses: github/codeql-action/upload-sarif@v3
    if: always()           # upload even when the scan step failed the build
    with:
      sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

SARIF output conforms to [SARIF 2.1.0](https://json.schemastore.org/sarif-2.1.0.json)
with `fingerprints`, `partialFingerprints`, `security-severity` scores, and
`%SRCROOT%` relative paths. Each finding carries **OWASP references** and **CVE
links** via the rule-level `help`; per-finding remediation is in result
`properties`. (No SARIF `fixes[]` — those require machine-applicable
`artifactChanges`, so emitting prose there would make Code Scanning reject the
upload.)

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