# Examples

Self-contained vulnerability demos and integration guides for AgentAuditKit.

## Quick Start

```bash
pip install agent-audit-kit

# Scan a single example
agent-audit-kit scan examples/vulnerable-configs/01-no-auth-remote/

# Scan all examples
bash examples/run-all-examples.sh
```

## Vulnerable Configs

11 intentionally vulnerable configurations covering all 11 security categories. Each directory contains the vulnerable files and an `expected-findings.json` listing the rules that should trigger.

| # | Example | Rules Triggered | OWASP MCP | OWASP Agentic | CVE Reference |
|---|---------|----------------|-----------|---------------|---------------|
| 01 | [No Auth Remote](vulnerable-configs/01-no-auth-remote/) | AAK-MCP-001, AAK-MCP-009, AAK-TRANSPORT-001/003 | MCP01, MCP04 | AG07 | CVE-2026-32211 |
| 02 | [Shell Injection](vulnerable-configs/02-shell-injection/) | AAK-MCP-005/006/007/008/010, AAK-SUPPLY-001 | MCP04, MCP06 | AG01, AG06 | — |
| 03 | [Hardcoded Secrets](vulnerable-configs/03-hardcoded-secrets/) | AAK-MCP-003, AAK-SECRET-001/002/003/004/006 | MCP08 | AG05 | — |
| 04 | [Hook Exfiltration](vulnerable-configs/04-hook-exfiltration/) | AAK-HOOK-001 through 009 | MCP09 | AG04, AG08 | CVE-2026-21852 |
| 05 | [Trust Boundary Violations](vulnerable-configs/05-trust-boundary-violations/) | AAK-TRUST-001 through 006 | MCP03, MCP07 | AG02, AG09 | CVE-2026-21852 |
| 06 | [Tool Poisoning](vulnerable-configs/06-tool-poisoning/) | AAK-POISON-001 through 006 | MCP02, MCP05 | AG01, AG03 | — |
| 07 | [Tainted Tool Function](vulnerable-configs/07-tainted-tool-function/) | AAK-TAINT-001 through 008 | MCP05 | AG01 | — |
| 08 | [Transport Insecurity](vulnerable-configs/08-transport-insecurity/) | AAK-TRANSPORT-001 through 004, AAK-MCP-001 | MCP04 | AG07 | — |
| 09 | [A2A Insecure Agent](vulnerable-configs/09-a2a-insecure-agent/) | AAK-A2A-001 through 007 | — | AG02, AG10 | — |
| 10 | [Supply Chain Risks](vulnerable-configs/10-supply-chain-risks/) | AAK-SUPPLY-001/003/004, AAK-MCP-005/007 | MCP06, MCP10 | AG06 | — |
| 11 | [Legal Compliance](vulnerable-configs/11-legal-compliance/) | AAK-LEGAL-001/002, AAK-SUPPLY-004 | — | — | — |

## Case Studies

- [**damn-vulnerable-MCP-server Patterns**](case-studies/damn-vulnerable-mcp/) — Scans configs inspired by the DVMCP project (1,277+ stars), the recognized MCP security testbed.

## CI/CD Integration

Copy-paste-ready configurations:

- [GitHub Actions + SARIF](ci-integration/github-actions-sarif.yml) — Inline PR annotations via GitHub Security tab
- [GitLab CI](ci-integration/gitlab-ci-scan.yml) — Security scan stage with artifact output
- [Pre-commit Hook](ci-integration/pre-commit-config.yaml) — Scan before every commit
- [Docker One-Liner](ci-integration/docker-one-liner.sh) — Scan any directory without installing Python
