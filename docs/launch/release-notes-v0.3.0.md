# Release notes — v0.3.0

**Released:** 2026-04-18 (launch Tuesday 13:00 UTC)

Biggest release in the project's history. v0.3.0 adds the 2026 CVE
wave coverage, the AAK Response SLA, the MCP Security Index
scaffolding, and a distribution set big enough to live in every
developer workflow.

## Highlights

- **46 new rules across 10 families.** Total catalogue: **78 → 124**
  rules. Every rule ships with NVD or OWASP/CWE references, positive
  and negative fixtures, remediation text, and framework mappings.
- **AAK-INTERNAL-SCANNER-FAIL.** Engine-level exception hardening: a
  scanner that crashes no longer aborts the whole scan. The crash
  emits an INFO finding and the remaining scanners still run.
- **Pin-drift scanner.** AAK-RUGPULL-001/002/003 now fire during
  normal `agent-audit-kit scan`, not just `verify`.
- **TS/Rust scanner rename.** `typescript_scan.py` →
  `typescript_pattern_scan.py`, same for Rust. The old names remain as
  back-compat shims that emit a `DeprecationWarning`. Docs no longer
  claim "taint analysis" where the code is pattern-based.
- **`--strict-loading` CLI flag.** Opt-in: fail loudly when any
  optional scanner module can't be imported.
- **AAK Response SLA — public 48h CVE-to-rule.** See
  `CHANGELOG.cves.md` for the ledger.
- **Sigstore-signed rule bundle + SBOM.** `agent-audit-kit export-rules`
  and `agent-audit-kit verify-bundle`; CycloneDX + SPDX SBOM via
  `agent-audit-kit sbom`.
- **Auditor-ready compliance report.** `agent-audit-kit report
  . --framework {eu-ai-act,soc2,iso27001,hipaa,nist-ai-rmf}
  --format pdf`. Falls back to text when `reportlab` isn't installed.
- **MCP Security Index.** Weekly leaderboard of 500 public MCP
  servers, per-server grade cards, 90-day coordinated disclosure
  policy. Code under `benchmarks/`; CI workflow
  `.github/workflows/mcp-security-index.yml`.
- **Distribution: everywhere.** Docker image at
  `ghcr.io/sattyamjjain/agent-audit-kit:v0.3.0`, VS Code extension,
  GitLab CI template, GitHub Action, pre-commit hook (`agent-audit-kit
  install-precommit`).

## Breaking changes

None at the rule-id level. Three scanner modules were renamed, but the
old module paths import the new ones with a `DeprecationWarning`.

## Upgrade

```bash
pip install -U agent-audit-kit
```

Or with the GitHub Action:

```yaml
- uses: sattyamjjain/agent-audit-kit@v0.3.0
  with:
    fail-on: high
```

## Deprecations (to remove in v0.4.0)

- `agent_audit_kit.scanners.typescript_scan` → use
  `agent_audit_kit.scanners.typescript_pattern_scan`.
- `agent_audit_kit.scanners.rust_scan` → use
  `agent_audit_kit.scanners.rust_pattern_scan`.

## Acknowledgements

NVD for the authoritative CVE records. OWASP for the MCP Top 10 and
Agentic 2026 projects. Anthropic for the MCP spec work at the Linux
Foundation Agentic AI Foundation.

## Next

v0.4.0 work starts immediately. Planned themes: tree-sitter AST-based
taint tracing for TS/Rust; JetBrains plugin; calibrate the scoring
scale on the full 10,000-server corpus; shop the scanner to OWASP as
the MCP Top 10 reference implementation.
