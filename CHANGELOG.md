# Changelog

All notable changes to AgentAuditKit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.4] - 2026-04-24

**Headline: DNS-rebinding SDK class (CVE-2025-66414/66416, CVE-2026-35568,
CVE-2026-35577), Splunk MCP token-in-log (CVE-2026-20205), GitHub Actions
Immutable-Action / SHA-pin gate, in-flight CVE pin-checks (CVE-2026-40576,
CVE-2026-40608), OWASP Agentic public JSON artefact, repo-metadata sync.**

Closes the April-2026 DNS-rebinding cluster across the Python, Java, TS and
Apollo MCP SDKs, ships a token-in-log sink detector covering the Splunk
MCP bulletin, wires a SHA-pin regression fence for downstream users on the
GitHub Actions 2026 roadmap, and publishes the OWASP Agentic reference-tool
submission packet with a machine-readable coverage artefact.

### Added — rule coverage (6 new rules, 151 → 157)

- **AAK-DNS-REBIND-001** (CRITICAL, Category.TRANSPORT_SECURITY) — MCP
  `StreamableHTTP*` transport exposed without a Host-header allow-list.
  Covers CVE-2025-66414, CVE-2025-66416 (Python `mcp`), CVE-2026-35568
  (Java `io.modelcontextprotocol.sdk:mcp-core`), CVE-2026-35577
  (`@apollo/mcp-server`). New scanner `scanners/dns_rebind.py` walks
  `.py`/`.ts`/`.js`/`.mjs`/`.cjs` sources for `StreamableHTTPSessionManager`,
  `streamable_http`, `StreamableHTTPTransport` and suppresses only when a
  host allow-list marker (`TrustedHostMiddleware`, `allowed_hosts=`,
  `allowedHosts:`, `validate_host`, `HostHeaderFilter`) is reachable
  anywhere in the project.
- **AAK-DNS-REBIND-002** (HIGH, Category.SUPPLY_CHAIN) — vulnerable MCP SDK
  version pinned in a manifest. Patched floors: Python `mcp` ≥ 1.23.0, TS
  `@modelcontextprotocol/sdk` ≥ 1.21.1, Java `mcp-core` ≥ 0.11.0,
  `@apollo/mcp-server` ≥ 1.7.0. Scans `requirements*.txt`, `pyproject.toml`,
  `package.json` (dependencies / devDependencies / peerDependencies),
  `pom.xml`, `build.gradle`, `build.gradle.kts`.
- **AAK-SPLUNK-TOKLOG-001** (HIGH, Category.SECRET_EXPOSURE) — token-shaped
  values (Bearer, JWT, `splunkd_session`, `st-*`, `sk-ant-*`, `ghp_*`) or
  unredacted token-named variables interpolated into a log sink
  (`logger.info/warn/error`, `print`, `console.log`, `System.out.println`).
  Suppresses on explicit redact markers (`***`, `<redacted>`, `mask(...)`).
  New scanner `scanners/log_token_leak.py`. Pin-check for
  `splunk-mcp-server < 1.0.3` (CVE-2026-20205).
- **AAK-GHA-IMMUTABLE-001** (MEDIUM, Category.SUPPLY_CHAIN) — third-party
  GitHub Action pinned by tag or branch instead of 40-character commit SHA.
  `actions/*` and `github/*` are exempt (Immutable-Actions publishers).
  Local composite actions (`./path/to/action`) are exempt. New scanner
  `scanners/gha_hardening.py` walks `.github/workflows/*.yml` via PyYAML so
  every `uses:` step shape is covered. Aligned to the GitHub Actions 2026
  Security Roadmap.
- **AAK-EXCEL-MCP-001** (CRITICAL, Category.SUPPLY_CHAIN) — CVE-2026-40576,
  `excel-mcp-server <= 0.1.7` path-traversal in `get_excel_path()` combined
  with the default 0.0.0.0 bind on SSE / Streamable-HTTP. Pin-check in
  `scanners/supply_chain.py`. Patched in 0.1.8.
- **AAK-NEXT-AI-DRAW-001** (MEDIUM, Category.TRANSPORT_SECURITY) —
  CVE-2026-40608, `next-ai-draw-io < 0.4.15` body-accumulation OOM in the
  embedded HTTP sidecar. Pin-check in `scanners/transport_limits.py` next
  to AAK-MCPFRAME-001 (same class).

### Added — coverage artefacts

- `public/owasp-agentic-coverage.json` — machine-readable OWASP Agentic
  Top 10 2026 coverage schema (v1) with ASI slot density, CVE references,
  AICM references per rule. Regenerated on every release by
  `scripts/gen_owasp_coverage.py`. `tests/test_owasp_public_json.py`
  enforces the schema and ≥3 rule density floor.
- `docs/launch/owasp-reference-tool-submission.md` — pre-filled submission
  packet for the OWASP Agentic reference-tool registry. Closes #24 + #25.

### Added — release-mechanics / tooling

- `scripts/sync_repo_metadata.py` — single source of truth for
  `sattyamjjain/agent-audit-kit@vX.Y.Z` pins across `README.md`,
  `docs/**/*.md` (excluding frozen `release-notes-v*.md` history), and the
  canonical GitHub repo description string. `--check` exits non-zero on
  drift, `--write` rewrites, `--description` prints the string.
- `.github/workflows/sync-repo-metadata.yml` — triggers on
  `release.published` + `workflow_dispatch`; rewrites pins and edits the
  repo description via `gh repo edit`. Uses SHA-pinned actions only.
- `tests/test_repo_metadata_sync.py` — regression fence: every README pin
  must match the live `pyproject.toml` version.

### Fixed

- Closed the cross-category drift where the README badge showed
  "rules-151" while the OpenGraph / repo-description field was stuck at
  "77 rules". The new sync workflow plus regression test remove the class.
- README example snippets now bump in lock-step with the release tag
  instead of requiring a manual edit.

### Deferred to v0.3.5

- CSA MCP Security Baseline v1.0 mapping — not yet public as of 2026-04-24.
  Watcher (`scripts/watch_csa_mcp_baseline.py`) remains armed.
- CVE-2026-31504 (Linux kernel fanout UAF) — out-of-scope for an MCP /
  agent-pipeline scanner. Closed on the CVE-response queue with rationale.

## [0.3.3] - 2026-04-21

**Headline: mcp-framework + Apache Doris pin-checks, Anthropic MCP SDK
STDIO hardening, CVE-watcher dedup, AICM density to ≥51%, CycloneDX
AI-BOM emitter.**

Clears the 48h SLA on CVE-2026-39313 and CVE-2025-66335, adds the
SDK-level inheritance check the OX Security 2026-04-15 disclosure asked
for, roots out the watcher regression that opened five copies of
CVE-2026-6599, and lifts the AICM mapping density from a 7% starter to
a real procurement-facing 63%.

### Added — rule coverage (3 new rules, 148 → 151)

- **AAK-MCPFRAME-001** (MEDIUM) — CVE-2026-39313, mcp-framework < 0.2.22
  HTTP-body DoS. Detection: `package.json` pin-check + TS/JS regex for
  `readRequestBody`-style chunk-concat accumulating into a string
  without a `Content-Length` / `maxMessageSize` guard. Ships in a new
  `scanners/transport_limits.py`. Strips `//` and `/* ... */` comments
  before matching the size-guard regex so docstring mentions do not
  spuriously suppress.
- **AAK-DORIS-001** (HIGH) — CVE-2025-66335, apache-doris-mcp-server
  < 0.6.1 SQL injection via query-context neutralization bypass.
  Pin-check scans `requirements*.txt`, `pyproject.toml`,
  `Pipfile(.lock)`, `poetry.lock`, `uv.lock`. Lives in
  `scanners/supply_chain.py`.
- **AAK-ANTHROPIC-SDK-001** (HIGH) — SDK-level STDIO sanitization
  inheritance check covering the OX Security 2026-04-15 class.
  Anthropic declined to CVE — "sanitization is the developer's
  responsibility". Fires only when (a) an upstream MCP SDK is declared
  in a manifest (Python `mcp`/`modelcontextprotocol`, TS
  `@modelcontextprotocol/sdk`, Java `io.modelcontextprotocol:*`, Rust
  equivalents), (b) a STDIO transport is exposed, and (c) no
  sanitizer, HTTP opt-out, or documented risk acceptance is present.
  Opt-out via `.agent-audit-kit.yml` with `accepts_stdio_risk: true`
  plus a non-empty `justification:`. Ships in a new
  `scanners/mcp_sdk_hardening.py`. Tagged
  `incident_references=["OX-MCP-2026-04-15"]`.

### Added — OWASP Agentic 2026 density floor

- `tests/test_owasp_agentic_coverage.py` now enforces a **≥3 rules per
  ASI slot** density floor (parametrized). The marketing claim
  "OWASP Agentic Top 10: 10/10" is now backed by a test that fails
  CI if any slot falls below three rules.
- `AAK-A2A-003`, `AAK-A2A-011`, `AAK-A2A-012` gain `ASI08` tags
  (Agent Communication Poisoning) — lifts ASI08 coverage from 1 rule
  to 3.
- `scripts/gen_owasp_coverage.py` additionally rewrites a
  `<!-- owasp-coverage:start -->`…`<!-- owasp-coverage:end -->`
  marker in `README.md` so the rendered coverage table stays in lockstep
  with the code.

### Added — CSA AICM density to ≥51%

- `_AICM_TAGS` in `agent_audit_kit/rules/builtin.py` expands from 10
  rules (7%) to **95 rules (63%)**, covering the SECRET-*, SUPPLY-*,
  TRUST-*, TRANSPORT-*, A2A-*, POISON-*, TAINT-*, SSRF-*, OAUTH-*,
  SKILL-*, MARKETPLACE-*, HOOK-*, and CVE-response families. Each
  family maps to the canonical AICM control domain (DSP / IAM / STA /
  CEK / AIS / LOG / IVS / CCC).
- `tests/test_aicm.py` gets a **density floor assertion** — the suite
  now fails CI if fewer than 75 rules carry an AICM tag.
- `--compliance aicm` CSV output reflects the expanded mapping
  automatically; no CLI change needed.

### Added — CycloneDX AI-BOM emitter

- `agent-audit-kit sbom --format aibom` emits a CycloneDX 1.5 AI/ML-BOM
  on top of the existing SBOM primitive. Adds:
  - `components` entries with `type: "machine-learning-model"` for each
    detected vendor SDK (anthropic/Claude, openai/GPT, cohere/Command).
  - A `formulation` block listing detected agent-platform SDKs
    (LangChain, LangSmith, LangGraph, LangFuse, Helicone, Humanloop,
    MCP SDK) with pURLs where the pin can be extracted.
  - `metadata.properties`: `aak:rule-bundle-sha256` (pulled from
    `rules.json.sha256` if present), `aak:aibom: "1"` marker, and one
    `aak:incident-fired` per fired incident reference so the BOM can
    double as attestation evidence.
- Covered by `tests/test_cyclonedx_aibom.py`.

### Fixed — CVE-response watcher dedup (Task A)

- `scripts/cve_watcher.py` was only deduping against
  `CHANGELOG.cves.md`. A CVE sitting in the SLA queue without a rule
  yet never reached the changelog, so the 6-hourly cron re-opened it.
  Over 48h this filed five copies of CVE-2026-6599 (#47/#48/#50/#52/#55)
  and three of CVE-2025-66335.
- Rewritten with three layers of dedup (any one suppresses):
  1. `CHANGELOG.cves.md`.
  2. Persistent `.aak/cve-watcher-state.json` (cached across workflow
     runs via `actions/cache`).
  3. Open `cve-response` issue titles + bodies via the GitHub REST API.
- New `scripts/close_duplicate_cve_issues.py` groups existing open
  `cve-response` issues by extracted CVE ID, keeps the lowest-numbered,
  closes the rest with a cross-reference body. Ran against live repo
  during this release: closed #48, #50, #51, #52, #54, #55, #56 (7
  dups).
- `.github/workflows/cve-watcher.yml` now wires `GITHUB_TOKEN` +
  `GITHUB_REPOSITORY` into the diff step and restores the state file
  from `actions/cache`.
- Covered by `tests/test_cve_watcher_dedup.py` — five scenarios
  including the observed "same CVE × 3 cron runs" replay.

### Added — provenance plumbing

- `CHANGELOG.cves.md` gains entries for CVE-2026-39313,
  CVE-2025-66335, and the OX-MCP-2026-04-15 incident class.
- `watch.py` parameter annotations updated from the string-form
  `"callable | None"` to the proper `Callable[[int, list[Any]], None]`
  (incidental mypy-1.x compatibility fix carried over from 0.3.2.1
  hotfix).
- `scanners/marketplace_manifest.py` ships the Python 3.10 `tomli`
  fallback that made CI green for 0.3.2 — kept for 0.3.3.

### Thanks

OX Security for the 2026-04-15 "Mother of all AI supply chains"
disclosure; Apache Doris for the 0.6.1 patch turnaround; the CSA AICM
working group for publishing a v1 control catalog we can map to.

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
