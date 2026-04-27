# AgentAuditKit vs. GitLab Agentic SAST (18.11 GA)

GitLab 18.11 (2026-04-17) shipped Agentic SAST behind the Ultimate
tier. This is a no-marketing, dated-source comparison so AAK
consumers can pick the right tool for their stack.

| Dimension | AgentAuditKit | GitLab Agentic SAST 18.11 |
|---|---|---|
| License | MIT, OSS | Proprietary, Ultimate-tier paywall |
| Distribution | PyPI + Marketplace + Docker + VS Code ext | GitLab CI / Premium offering only |
| Rule count | 175 (v0.3.8) | Not publicly disclosed |
| OWASP Agentic Top 10 mapping | Per-rule, public JSON manifest | Claimed; mapping not published |
| MCP Top 10 mapping | Per-rule | Not advertised |
| AICM (CSA) mapping | Yes | Not advertised |
| Out-of-band corpus refresh | `aak corpus update` (signed) | No equivalent — rules ship on product release cadence |
| SARIF diff (regression-only gating) | `aak diff --baseline ... --current ...` | Not advertised |
| VS Code extension | Yes (open-source) | No |
| PR-title indirect prompt injection | AAK-PRTITLE-IPI-001 (CVSS 9.4) | Not advertised in 18.11 changelog |
| MCP function-hijacking detection | AAK-MCP-FHI-001 (arXiv 2604.20994) | Not advertised |
| Atlassian MCP CVEs | AAK-MCP-ATLASSIAN-CVE-2026-27825/27826 | Generic SAST may catch; no per-CVE rule |
| Sigstore-attested releases | Yes | Not applicable |
| Self-scan / dogfood gate | `.github/workflows/self-scan.yml` (PR-blocking) | Not applicable to a managed product |

## Where GitLab is genuinely stronger

- **DAST + IAST integration**: GitLab integrates SAST + DAST + IAST in
  one pipeline. AAK is SAST + supply-chain only.
- **Multi-tenant org-level dashboards**: GitLab's Vulnerability Reports
  aggregate across the org. AAK ships SARIF; consumers wire their own
  dashboard.
- **Ecosystem coverage**: GitLab's traditional SAST has rule packs for
  ~30 languages. AAK targets the agent / MCP slice specifically.

## Where AAK is genuinely stronger

- **Same-day defense for new payload families**: Out-of-band signed
  corpus refresh decouples threat-data updates from product releases.
- **PR-title IPI rule**: First-to-market on Comment-and-Control class
  (CVSS 9.4, 2026-04-25 disclosure).
- **MCP function-hijacking rule**: First-to-market on the BFCL FHI
  class (arXiv 2604.20994, 2026-04-23, 70-100% ASR).
- **Free + OSS**: No tier paywall, no per-seat licensing.
- **SARIF regression gating**: `aak diff` lets PR-blocking workflows
  gate on `newly_introduced` only — eliminates the "huge backlog
  blocks every PR" failure mode that GitLab Ultimate users report.

## Sources

- GitLab 18.11 release announcement: https://www.helpnetsecurity.com/2026/04/17/gitlab-18-11-agentic-ai/
- AAK v0.3.8 release notes: ../releases/v0.3.8.md
- OWASP Agentic Top 10: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

Last updated: 2026-04-27
