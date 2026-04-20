# Changelog

All notable changes to AgentAuditKit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2] - 2026-04-20

**Headline: MCPwn coverage + third-party OAuth-app surface + OWASP Agentic 2026 coverage proof.**

Closes the KEV-listed CVE-2026-33032 (MCPwn) with a targeted middleware-
asymmetry detector, ships first-class coverage for the April 19 2026
Vercel × Context.ai OAuth breach class, and gates every future PR on
OWASP Agentic Top 10 2026 coverage.

### Added — rule coverage (6 new rules)

- **AAK-MCPWN-001** (CRITICAL) — twin-route middleware-asymmetry
  detector across Go/Gin, Python/FastAPI, and Node/Express. This is
  CVE-2026-33032 itself, not a generic MCP-config check: if `/mcp`
  has AuthRequired() and `/mcp_message` doesn't, the rule fires. Also
  recognises the `router.Group("/", AuthRequired())` patched pattern
  so 2.3.4+ doesn't produce false positives. Maps CVE-2026-33032
  and CVE-2026-27944.
- **AAK-FLOWISE-001** (CRITICAL) — CVE-2026-40933 (GHSA-c9gw-hvqq-f33r,
  CVSS 10.0). Pin-check on `flowise` / `flowise-components` < 3.1.0,
  plus a flow-config pass that flags MCP adapter nodes with
  `customFunction` / `runCode` / `executeCommand` sinks. Auto-fixable
  via `agent-audit-kit fix --cve`.
- **AAK-OAUTH-SCOPE-001** (HIGH) — third-party OAuth client granted
  broad Google Workspace scopes (admin.*, cloud-platform, drive,
  directory.*, gmail.modify/send). Repos add trusted client IDs to
  `.aak-oauth-trust.yml`.
- **AAK-OAUTH-3P-001** (MEDIUM) — repo depends on an agent-platform
  SDK (context-ai, langsmith, helicone, langfuse, humanloop, MCP SDK).
  Informational finding so reviewers audit OAuth-scope footprints
  before merge.
- Together AAK-OAUTH-* tag `incident_references=["VERCEL-2026-04-19"]`,
  the first use of the new incident-provenance field.

### Added — schema + tooling

- **`SCHEMA_VERSION = 2`** bump in `agent_audit_kit/models.py`:
  - New `incident_references: list[str]` field (Task G).
    Backfilled:
    - `AAK-STDIO-001` → `OX-MCP-2026-04-15` (retrofit).
    - `AAK-OAUTH-SCOPE-001` / `AAK-OAUTH-3P-001` → `VERCEL-2026-04-19`.
    - `AAK-MCPWN-001` → `MCPWN-2026-04-16`.
  - New `aicm_references: list[str]` field (Task E) — CSA AI Controls
    Matrix control IDs. Seeded 10 mappings (DSP-17, IAM-01/02/16,
    STA-02/08, CEK-08, LOG-06).
- **`--compliance aicm`** — new scan flag that emits a CSV sorted by
  AICM control ID. `output/aicm.py` is the formatter.
- **OWASP Agentic 2026 coverage gate** — `tests/test_owasp_agentic_coverage.py`
  fails CI if any of ASI01…ASI10 has zero backing rules. Paired with
  `scripts/gen_owasp_coverage.py` that regenerates
  `docs/owasp-agentic-coverage.md` on demand.
- **SARIF `fingerprint-strategy`** — `auto` (default) / `line-hash` /
  `disabled`. `action.yml` exposes the input; `entrypoint.sh` threads
  it. Fixes the GH Code Scanning de-dup regression that marketplace
  runners (detached source) hit without self-emitted fingerprints.
- **CSA MCP Security Baseline watcher** — `scripts/watch_csa_mcp_baseline.py`
  polls the CSA Resource Center + modelcontextprotocol-security.io
  weekly, files a tracking issue on drop, and persists seen versions
  in `.aak/csa-mcp-baseline-state.json` so each version triggers once.
- **`docs/rule-schema.md`** — documents v1 + v2 field set and the
  SARIF tag projection.

### Changed

- Rule count 144 → **148** (6 new rules, 2 of which technically land
  as pairs under the OAuth umbrella).
- `rules.json` regenerated (SHA-256 `5c7b1c47cd067e86a533d6084925472a356442afbefcd8af6f3a0b3c3afd393b`).
- `CHANGELOG.cves.md` now lists the MCPwn + Flowise entries and
  demotes the pre-v0.3.2 "covered by AAK-MCP-011/012/020" claim for
  CVE-2026-33032 to secondary coverage (primary is now AAK-MCPWN-001).

### Verified sources

- [NVD CVE-2026-33032](https://nvd.nist.gov/vuln/detail/CVE-2026-33032) — MCPwn, CVSS 9.8, KEV 2026-04-13.
- [Rapid7 ETR](https://www.rapid7.com/blog/post/etr-cve-2026-33032-nginx-ui-missing-mcp-authentication/).
- [Picus MCPwn writeup](https://www.picussecurity.com/resource/blog/cve-2026-33032-mcpwn-how-a-missing-middleware-call-in-nginx-ui-hands-attackers-full-web-server-takeover).
- [GHSA-c9gw-hvqq-f33r](https://github.com/advisories/GHSA-c9gw-hvqq-f33r) — Flowise, CVSS 10.0, fixed 3.1.0.
- [Vercel April 2026 bulletin](https://vercel.com/kb/bulletin/vercel-april-2026-security-incident).
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
- [GitHub Docs — SARIF support for Code Scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning).
- [CSA AI Controls Matrix v1.0](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix).
- [CSA MCP Security Resource Center](https://cloudsecurityalliance.org/blog/2025/08/20/securing-the-agentic-ai-control-plane-announcing-the-mcp-security-resource-center).

## [0.3.1] - 2026-04-19

**Headline: Ox MCP supply-chain coverage + rule-count single source of truth + SARIF fingerprints.**

Ships rule coverage for every disclosed MCP CVE from the last 48 hours, honoring
the public [AAK Response SLA](CHANGELOG.cves.md).

### Added — rule coverage (6 new rules)

- **AAK-STDIO-001** (CRITICAL) — Ox Security's Apr-16 disclosure covered
  10 CVEs rooted in the same shape: user-controllable input reaching
  STDIO command executors in MCP servers. One AST-based Python scanner
  plus a TS regex pass closes the whole family in one rule. Maps
  CVE-2026-30615, CVE-2025-65720, CVE-2026-30617, CVE-2026-30618,
  CVE-2026-30623, CVE-2026-30624, CVE-2026-30625, CVE-2026-33224,
  CVE-2026-26015.
- **AAK-WINDSURF-001** (HIGH) — zero-click `.windsurf/mcp.json`
  auto-registration (CVE-2026-30615): flags `auto_approve:true` /
  `auto_execute:true`, world-writable parent dirs, and unpinned server
  commands.
- **AAK-NEO4J-001** (MEDIUM) — `mcp-neo4j-cypher < 0.6.0` read-only
  bypass via APOC (CVE-2026-35402). Version-pin check + source pattern
  detection (`read_only=True` + APOC call in the same file).
  `auto_fixable=True` — `agent-audit-kit fix --cve` bumps the pin.
- **AAK-CLAUDE-WIN-001** (HIGH) — Claude Code Windows ProgramData
  hijack (CVE-2026-35603). Requires sibling `setup.ps1` with `icacls`
  ACL hardening when a `managed-settings.json` lives in a ProgramData
  path.
- **AAK-LOGINJ-001** (MEDIUM) — log injection via CRLF/ANSI in tool
  params (CVE-2026-6494, CWE-117). AST pass: `@tool` parameters flowing
  into `logger.*` / `print` / `sys.stdout` / `console.log` without
  sanitization.
- **AAK-SEC-MD-001** (LOW) — MCP-server repos without SECURITY.md /
  `security_contact`. Anthropic Apr-2026 baseline expectation.

### Added — trust / DevEx

- **Rule-count single source of truth**: `scripts/sync_rule_count.py`
  rewrites the `rules-<N>-blue` badge, the `action.yml` description,
  and `agent_audit_kit.__init__.RULE_COUNT` from `rules.json`. Wired
  into `.github/workflows/sync-rule-count.yml` (auto-commits drift) and
  `.pre-commit-config.yaml` (blocks human drift locally). Regression
  fence in `tests/test_rule_count_sync.py`.
- **SARIF upgrades** (`output/sarif.py`):
  - `partialFingerprints.primaryLocationLineHash` is now SHA-256 of
    **line content + rule ID**, so GH Code Scanning de-dupes across
    pushes even when line numbers shift, and flags as new when the
    content changes. Falls back to a location-based hash when the
    file can't be read.
  - `helpUri` → `https://agent-audit-kit.dev/rules/{rule_id}` per rule.
  - `results[].properties.security-severity` included on every result
    (was only on the rule descriptor).
- **PR comment + `$GITHUB_STEP_SUMMARY`** (`output/pr_summary.py`):
  scan results render as a Markdown table (Rule | Severity | Location |
  Suggestion) written to `$GITHUB_STEP_SUMMARY` every run, and posted
  as a sticky PR comment (marker-based) when `comment-on-pr=true`.
  New `action.yml` input: `comment-on-pr` (default `true`).
  New CLI flags: `--step-summary` / `--no-step-summary` and
  `--pr-summary-out PATH`.

### Changed

- Rule count 138 → **144**.
- `description:` in `action.yml` now includes the current rule count
  ("144 rules, OWASP Agentic Top 10 + MCP Top 10").
- `rules.json` regenerated and re-signed with the new rule set.

### Fixed

- `README.md` comparison table row claiming "138 rules" for A2A
  scanning (it's always been 12 rules); regression guarded by the
  rule-count sync test.

### Supply chain

Every release artifact continues to ship alongside a Sigstore-signed
`rules.json`, CycloneDX and SPDX SBOMs, and SLSA build provenance on
the Docker image.

## [0.3.0] - 2026-04-18

Retroactive SLA coverage for the 2026 MCP CVE wave. See [v0.3.0 release
notes](docs/launch/release-notes-v0.3.0.md) for the full scope — 46 new
rules across the 10 ROADMAP §2.2 families (AAK-MCP-011..020, SSRF,
OAUTH, HOOK-RCE, LANGCHAIN, MARKETPLACE, ROUTINE, A2A-008..012,
TASKS, SKILL). Rule count 77 → 138.

## [0.2.0] - 2026-04-05

Initial public release.

### Added

- **74 security rules** across 11 scanner categories: MCP configuration, hook injection, trust boundaries, secret exposure, supply chain, agent config, tool poisoning, taint analysis, transport security, A2A protocol, and legal compliance.
- **11 scanners** with full coverage of MCP-connected AI agent pipelines.
- **9 CLI commands**: `scan`, `discover`, `pin`, `verify`, `fix`, `score`, `update`, and CI-mode shortcuts.
- **SARIF 2.1.0** output with GitHub Security tab integration and inline PR annotations.
- **GitHub Action** (`sattyamjjain/agent-audit-kit@v1`) for zero-install CI scanning.
- **Pre-commit hook** for local scanning before every commit.
- **OWASP coverage**: full mapping to OWASP Agentic Top 10 (10/10), OWASP MCP Top 10, and Adversa AI Top 25.
- **Compliance mapping** for EU AI Act, SOC2, ISO 27001, HIPAA, and NIST AI RMF via `--compliance` flag.
- **Tool pinning** (`pin` and `verify` commands) to detect rug-pull and supply chain drift.
- **Taint analysis** tracking `@tool` parameter flows to shell, eval, SQL, SSRF, file, and deserialization sinks.
- **Security scoring** with letter grades and embeddable badges via `score` command.
- **Auto-fix** with `fix --dry-run` for safe remediation of common findings.
- **Agent discovery** supporting Claude Code, Cursor, VS Code Copilot, Windsurf, Amazon Q, Gemini CLI, Goose, Continue, Roo Code, and Kiro.

[0.2.0]: https://github.com/sattyamjjain/agent-audit-kit/releases/tag/v0.2.0
