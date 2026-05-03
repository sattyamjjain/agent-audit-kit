# Changelog

All notable changes to AgentAuditKit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.13] - 2026-05-03

**Headline: backlog-triage release — 1 new CVE rule (191 total) +
2 new product surfaces (`aak notify` Slack webhook + pre-commit
one-liner installer).** Closes 13 backlog issues in one ship: 8 GFI
trivials (#9, #10, #11, #13, #14, #16, #17, #18, plus #12 already
shipped), the chatgpt-mcp CVE pin (#80), the pre-commit installer
(#65), the Slack webhook (#66 minimum), 4 superseded umbrellas
(#15, #21, #26, #64), and 8 duplicate CVE-bot tickets (#131-#138).

### Added — Rule (1)

- **AAK-CHATGPT-MCP-CVE-2026-7061-PIN-001** (HIGH, CVSS 7.3) —
  `Toowiredd/chatgpt-mcp-server <=0.1.0` OS command injection in
  `src/services/docker.service.ts`. Package isn't on npm — consumers
  install via `git+https://` or `github:Toowiredd/...` shorthand
  in package.json. Pin-check fires whenever the package appears in
  any npm manifest (every published version is vulnerable; no
  upstream patch as of ship date). Architectural class is also
  caught by `AAK-MCP-STDIO-CMD-INJ-002`. Closes #80.

### Added — CLI surfaces

- `aak notify [PATH]` — runs a scan and dispatches findings to the
  sinks declared in `.aak-notify.yaml`. Slack `incoming-webhook`
  ships in this release; PagerDuty + Linear are explicit
  `NotImplementedError` stubs so consumers can build configs ahead
  of v0.4.0. Supports `--dry-run` and `--config`. Closes #66.
- `scripts/install-pre-commit.sh` — one-liner installer
  (`curl -fsSL .../install-pre-commit.sh | bash`). Auto-detects
  the latest GitHub Release tag, appends to existing
  `.pre-commit-config.yaml` or creates a new one, runs
  `pre-commit install`. Closes #65.

### Added — CLI flags / docs / fixtures (#9, #10, #11, #13, #14, #16, #17, #18)

- `aak <subcommand> --version` on every subcommand (21 decorators).
- `aak scan --quiet/-q` suppresses header / summary / tip footer
  on console-format output.
- `aak discover --format json` emits a stable schema for
  programmatic use (`{count, agents}`).
- `aak score` ANSI-colors the grade (A/B green, C yellow, D/F red).
- `.editorconfig` codifies repo conventions.
- `docs/circleci.md` + `docs/azure-pipelines.md` mirror the GH
  Actions integration guide.
- `tests/test_supply_chain.py` — 4 boundary cases for
  `_version_in_range` + the requirements-glob path.

### New module

- `agent_audit_kit/integrations/notify.py` — `SlackSink`,
  `PagerDutySink` (stub), `LinearTicketSink` (stub),
  `load_notify_config`, `run_notify`. Designed so consumers can
  declare every sink they want today; only Slack actually posts.

### Tests

- 14 new tests: 4 chatgpt-mcp pin (`tests/test_v0_3_13_rules.py`),
  10 notify sinks (`tests/test_integrations_notify.py`). Total
  928 passing (was 914).

### Triage closures (no code change)

- `#15` "77 rules" doc — superseded (repo at 191).
- `#21` v0.3.0 tracker umbrella — superseded.
- `#26` v0.3.0 stretch umbrella — half-shipped, items re-filed.
- `#64` Hosted aak.dev SARIF dashboard — wontfix in this repo
  (spin off to `aak-dashboard` if ever pursued).
- `#131-#138` — duplicates of CVEs already class-covered by
  `AAK-MCP-STDIO-CMD-INJ-001/002/003/004` and triaged in the
  morning v0.3.11/v0.3.12 batch. Watcher dedup follow-up logged.

## [0.3.12] - 2026-05-03

> Note: v0.3.11 was tagged with a stale `pyproject.toml` (still
> reading `0.3.10`) and so the PyPI publish job rejected the
> `0.3.10` wheel as a duplicate; the GitHub Release was skipped.
> The same content ships as v0.3.12 with a corrected manifest. The
> v0.3.11 tag is retained as a permanent failed-release marker;
> it has no PyPI artefact, no GitHub Release, and no `aak`
> consumer should ever see it on the index.

**Headline: 2 new CVE rules (190 total) + README scanner-count drift
fix — astro-mcp-server CVE-2026-7591 SQLi (pin + TS/JS source
detector), LiteLLM CVE-2026-30623 pin floor (auto-fix-wired), and
`scripts/sync_scanner_count.py` to keep README's `<!-- scanner-count
-->` anchor in lockstep with `agent_audit_kit/scanners/`.**

This release closes the public 48-hour CVE-to-rule SLA on two fresh
disclosures: CVE-2026-7591 against TimBroddin/astro-mcp-server (NVD
2026-05-01, no upstream patch released yet — every published version
is vulnerable) and CVE-2026-30623 against BerriAI/litellm (patched in
v1.83.7 on 2026-04-30). It also fixes a long-standing README claim
("28 scanner modules") that drifted past the actual filesystem count
of 57 detectors over twelve minor revs.

### Added — Rules (2)

- **AAK-ASTROMCP-SQLI-CVE-2026-7591-001** (HIGH) — TimBroddin/
  astro-mcp-server SQL injection in `src/index.ts` MCP-tool query
  construction via `request.params.arguments`. Two detector arms:
  pin-check on `package.json` / `package-lock.json` / `yarn.lock` /
  `pnpm-lock.yaml` fires whenever the package is present (every
  published version <=1.1.1 is vulnerable, no patch as of ship date),
  and a TS/JS source detector fires when files importing the package
  build queries via string concatenation or untagged template
  literals. Tagged-template SQL helpers (`drizzle-orm`,
  `postgres-js`, `sql-template-tag`) escape interpolations safely
  and are intentionally not matched. CVE anchor: NVD 2026-05-01.
- **AAK-LITELLM-CVE-2026-30623-PIN-001** (HIGH, auto-fixable) —
  `litellm` pinned at <1.83.7 in any Python manifest
  (`requirements*.txt`, `pyproject.toml`, `Pipfile*`, `poetry.lock`,
  `uv.lock`). Complements `AAK-MCP-STDIO-CMD-INJ-001` (which catches
  the source-side architectural shape) by surfacing a discrete
  finding for consumers running pin-check mode. Wired into
  `aak fix --cve` so the auto-fixer rewrites a `requirements*.txt`
  pin in place. Patch anchor: BerriAI/litellm v1.83.7 on 2026-04-30.

### Changed

- README "28 scanner modules" prose → `<!-- scanner-count:total
  -->NN<!-- /scanner-count --> scanner modules` anchor, kept in
  lockstep with the filesystem count via
  `scripts/sync_scanner_count.py`. Same posture as
  `sync_rule_count.py`: pre-commit hook blocks human drift; the
  existing `sync-rule-count.yml` workflow auto-runs
  `sync_scanner_count.py` after relevant pushes and commits the
  bumped files back.
- `agent_audit_kit/__init__.py` — added `SCANNER_COUNT` constant
  alongside `RULE_COUNT`.

### Tests

- 11 new tests: 6 cover the astro-mcp pin + source matrix
  (vulnerable pin fires, concat-source fires, parameterized passes,
  tagged-template passes, no-import-scope-gate passes, pin+source
  side-by-side); 4 cover the LiteLLM pin floor (vulnerable fires,
  safe-pin passes, floor-pin passes, `fix --cve` codemod bumps the
  pin in place); 1 guards the README scanner-count anchor against
  filesystem drift.

### Carry list — for next release

- Four MCP-server CVEs from the 2026-05-01 OX/BackBox roundup
  (DocsGPT, GPT-Researcher, Agent-Zero, LettaAI) need their own
  pin-check + source pattern + fixture sets — deferred from today
  because each is independently >S effort.
- The 2026-05-02 plan's deferred P0 list (Flowise CVE-2025-59528,
  Cursor CVE-2026-26268, OpenClaw CVE-2026-32922 escalation variant,
  LMDeploy CVE-2026-33626) re-evaluates against fresh primary sources
  in the next prompt rather than carrying over silently.

## [0.3.10] - 2026-04-29

**Headline: 8 new rules (188 total), 4 new product surfaces — CrewAI
four-CVE chain (CERT/CC VU#221883), AIVSS v0.8 scoring, LangChain
prompt-loader CVE-2026-34070, Prisma AIRS catalog mapper, OpenClaw
provisional rule, `aak watch-cve` daemon, public coverage page,
`aak rule lint`.**

This release lands the v0.3.10 plan in full: 5 SAST rules + 1 meta
rule for the CrewAI exploit chain, OWASP AIVSS v0.8 scoring during
the public-review window, four new CLI surfaces (`aak score
<sarif> --aivss`, `aak watch-cve`, `aak coverage --source
prisma-airs`, `aak rule lint`), and three open-issue resolutions
(fixture license declarations, parity per-region drift tests, SARIF
runtime-context spec).

### Added — Rules (8)

- **AAK-CREWAI-CHAIN-2026-04-001** (CRITICAL, meta) — fires when all
  four CrewAI 0.x exploit-chain shapes are reachable in one module.
- **AAK-CREWAI-CVE-2026-2275-001** (CRITICAL) — `CodeInterpreterTool(
  unsafe_mode=True)` host-Python sandbox escape.
- **AAK-CREWAI-CVE-2026-2285-001** (HIGH) — `JSONSearchTool` /
  `JSONLoader` path traversal via untrusted file_path.
- **AAK-CREWAI-CVE-2026-2286-001** (HIGH) — `RagTool` /
  `WebsiteSearchTool` SSRF without allow-list / private-net guard.
- **AAK-CREWAI-CVE-2026-2287-001** (HIGH) — `CodeInterpreterTool` no
  Docker liveness gate; silent fallback to host Python.
- **AAK-LANGCHAIN-PROMPT-LOADER-PATH-001** (HIGH) —
  `langchain.prompts.load_prompt(path)` traversal (CVE-2026-34070,
  patched in `langchain-core>=0.3.74`).
- **AAK-PRISMA-AIRS-COVERAGE-001** (INFO, meta) — Prisma AIRS catalog
  coverage manifest.
- **AAK-OPENCLAW-PRIVESC-001** (HIGH, provisional) — OpenClaw
  `OpenClawAgent(role=...)` missing / forgable; IronPlate
  2026-04-07 weekly intel CVSS 9.9.

### Added — CLI commands

- `aak score <sarif> --aivss` — annotate SARIF with AIVSS v0.8
  scores (AARS, environmental, threat, exploit-availability).
- `aak coverage --source prisma-airs` — coverage matrix vs the
  public Prisma AIRS attack catalog. `--fail-under N` for CI.
- `aak watch-cve --feeds ox,cert-cc,thaicert,ironplate` — CVE-feed
  daemon. Polling + dedup + dispatch framework; per-feed fetchers
  land in v0.3.11.
- `aak rule lint --ci` — validate the RuleDefinition registry against
  AAK metadata invariants.

### Added — Runtime helpers

- `agent_audit_kit.scoring.aivss.score_finding(rule_meta, runtime_ctx)`
  + `annotate_sarif(sarif, get_rule)` — AIVSS v0.8 annotator.
- `agent_audit_kit.checks.path_under_root(path, root)` — generic
  path-traversal guard, suppresses
  `AAK-LANGCHAIN-PROMPT-LOADER-PATH-001`.
- `agent_audit_kit.checks.openclaw.assert_role_allowlisted(role,
  allowlist=...)` — suppresses `AAK-OPENCLAW-PRIVESC-001`.
- `agent_audit_kit.sanitizers.crewai`:
  `assert_codeinterp_safe_mode`, `validate_jsonloader_path`,
  `validate_rag_url`, `require_docker_liveness` — suppress the four
  CrewAI sub-rules.

### Added — Manifests & data

- `agent_audit_kit/data/aivss-v08-defaults.json` — per-rule AARS /
  environmental / threat / exploit defaults.
- `agent_audit_kit/data/prisma-airs-catalog.json` + `-aak-map.json`
  — public Prisma AIRS catalog subset + AAK rule mapping.
- `scripts/build_coverage_page.py` + `.github/workflows/coverage-page.yml`
  — nightly public coverage page (HTML + JSON) on gh-pages.

### Housekeeping

- O10 — `tests/fixtures/LICENSES.md` declares derivation + license
  per fixture set.
- O11 — `tests/test_parity_region_drift.py` adds per-region drift
  tests + windowed report (28d / 1s edge cases).
- O12 — `docs/spec/sarif-runtime-context.md` proposes
  `properties.runtime_context` for SARIF.

### Tests

- `tests/test_v0_3_10_rules.py` (10) + `tests/test_v0_3_10_features.py`
  (15) + `tests/test_parity_region_drift.py` (4).

Total suite: 898 passing.


## [0.3.9] - 2026-04-28

**Headline: 5 new rules (180 total), 4 new CLI commands, runtime
parity-drift detector, Pipelock v2.3 policy bridge, and a stdio LSP
adapter that drops AAK findings into Zed and VS Code.**

This release lands the v0.3.9 plan in full: 3× P0 SAST rules for the
2026-04-24/25/26 cluster (Project Deal economic drift, LangGraph
ToolNode regression, DeepSeek V4 MoE tool injection), one P2 rule for
the BlackHat Asia 2026 social-agent hijack class, an OX-disclosed CVE
coverage manifest with a public badge, a Pipelock v2.3 → AAK config
translator, an `aak inspect-ide` CLI that publishes LSP diagnostics
(plus a Zed extension), a runtime `@aak.parity.check` decorator with
`aak parity report`, and corpus-manifest provenance fields
(`source_url` / `license` / `fetched_at`).

### Added — Rules (5)

- **AAK-PROJECT-DEAL-DRIFT-001** (HIGH) — pricing function calls an
  LLM with a templated `model=` and no `@aak.parity.check`. Anthropic
  Project Deal class (LLM09 / economic harm).
- **AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001** (MEDIUM,
  auto-fixable) — `ToolNode([...])` positional list; LangGraph
  prebuilt 1.0.11 silently coerces. Codemod queued via
  `aak suggest --apply-trivial` in v0.4.0.
- **AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001** (HIGH) — DeepSeek V4 MoE-routed
  tool description sourced from a request body / document loader
  without `sanitize_tool_description`. LLM01 with MoE-specific
  surface.
- **AAK-TIKTOK-AGENT-HIJACK-001** (HIGH) — social-agent reply sink
  reachable from user-content source without a human-in-loop gate.
  BlackHat Asia 2026 (Jiacheng Zhong) hijack class (LLM08).
- **AAK-OX-COVERAGE-MANIFEST-001** (INFO, meta) — drives the
  OX-disclosed CVE coverage badge + `aak coverage --source ox`.

### Added — CLI commands (4)

- `aak coverage --source ox` — prints AAK's static coverage of the
  OX disclosure timeline. `--format text|json|badge`.
- `aak pipelock import <policy.yaml>` — translates a Pipelock v2.3
  policy into a `.agent-audit-kit.yml`. `--dry-run` prints to stdout.
- `aak inspect-ide [PATH]` — runs AAK and emits LSP-shape
  diagnostics. `--serve` starts a stdio LSP server (Zed / VS Code
  language clients can attach).
- `aak parity report` — reads the in-process `@aak.parity.check`
  registry and runs the parity assertion. `--window` accepts `7d`,
  `24h`, `60m`, `30s`.

### Added — Runtime helpers

- `agent_audit_kit.parity.check(...)` decorator — records every
  invocation's `(dimensions, metric)` tuple; thread-safe.
- `agent_audit_kit.checks.economic_drift.assert_parity(...)` —
  per-bucket mean drift assertion. `ParityDriftError` on failure.
- `agent_audit_kit.sanitizers.deepseek.sanitize_tool_description` —
  strips control characters + routing-poison tokens, truncates.
  Calling it in the same function suppresses the SAST rule.
- `agent_audit_kit.autofix.langgraph_toolnode.fix(text)` —
  idempotent text-level rewrite for the ToolNode regression.

### Added — Editor / IDE

- `editors/zed/extension.toml` — Zed extension that auto-launches
  `agent-audit-kit inspect-ide --serve`.
- `agent_audit_kit/ide/lsp_diag.py` — minimal stdio LSP server,
  `diagnostics_for(path)` helper.

### Added — Coverage / housekeeping

- `agent_audit_kit/data/ox-cve-manifest.json` — 19 OX-disclosed CVE
  entries, all currently covered.
- `schema/ox-cve-manifest.schema.json` — JSON Schema for the
  manifest.
- `.github/workflows/badge-ox-coverage.yml` — auto-publishes
  `public/badges/ox-coverage.json` when the manifest changes.
- `public/corpora/manifest.json` — bumped `schema_version` to `2`;
  every entry now carries `source_url`, `license`, `fetched_at`.
- `agent_audit_kit/corpus/manifest.py` — `CorpusEntry` carries the
  new provenance fields.

### Tests

- `tests/test_v0_3_9_rules.py` — 14 cases covering the 4 new SAST
  scanners + the autofix codemod (vulnerable + safe + scope-gate).
- `tests/test_v0_3_9_features.py` — 10 cases for parity decorator,
  drift assertion, sanitiser idempotence + truncation.
- `tests/test_v0_3_9_features_p1.py` — 15 cases for OX coverage,
  Pipelock translator, IDE LSP adapter (CLI + library).

Total suite: 869 passing.


## [0.3.8] - 2026-04-27

5 new SAST rules + 5 fixture sets + supporting infrastructure for
Comment-and-Control PR title indirect-prompt-injection, MCP function
hijacking (FHI), Atlassian RCE chain, the wild IPI payload corpus,
and the MCPJam Inspector vendored fork. Released alongside the
critical Dockerfile / engine ignore_paths fix from 0.3.7.


## [0.3.7] - 2026-04-26

**Headline: critical Action / Dockerfile fix — published v0.3.6 was
unwriteable for every consumer; v0.3.7 makes the GitHub Marketplace
listing actually work.**

No new rules. No new scanners. v0.3.7 is a release-mechanics patch:
the Dockerfile fix is load-bearing for any consumer who ran the
Action from Marketplace and hit `Permission denied:
'agent-audit-results.sarif'`. Engine ignore_paths fix lands at the
same time so `--ignore-paths` finally works the way the docs claim.

### Fixed

- **Critical: Docker container ran as `USER scanner`** (UID 999) but
  `/github/workspace` is mounted from the runner's checkout owned by
  the runner UID; the container could not write the SARIF output.
  Every consumer of `sattyamjjain/agent-audit-kit@v0.3.6` (and
  earlier) saw `Permission denied: 'agent-audit-results.sarif'`.
  Surfaced via the new dogfood self-scan workflow (PR #71) — the
  loop validates that what we publish actually runs end-to-end.
  Dropped the `USER scanner` directive; container isolation, not
  in-container UID, is the load-bearing security boundary for an
  ephemeral GitHub Docker Action.
- **`engine.run_scan` now applies `--ignore-paths` globally** instead
  of only via the `secret_exposure` scanner kwarg. Every scanner now
  honours the flag. 5 new tests in `tests/test_engine_ignore_paths.py`
  fence the behaviour (subpath match, prefix-not-substring, exact
  file match, trailing-slash insensitivity, multi-scanner suppression).

### Added — release infrastructure

- `.github/workflows/self-scan.yml` — runs the local Action against
  this repo on every push / PR. `default-scan` job (full ruleset,
  `fail-on: critical`) plus `preset-mcp-ox-2026-04` job that
  exercises the `--preset` input end-to-end.

### Upgrade impact

- **Anyone using `sattyamjjain/agent-audit-kit@v0.3.6`** should bump
  to `@v0.3.7` immediately. v0.3.6 silently failed to produce SARIF
  output. Workflow YAML is otherwise compatible — no input/output
  changes.

## [0.3.6] - 2026-04-26

**Headline: OX MCP STDIO architectural class — Python/TS/Java/Rust SDK
rules, marketplace-fetch detection, Azure/LMDeploy/Splunk variants,
mcp-ox-2026-04 preset.**

Converts AAK's posture from CVE-by-CVE response to class coverage. 8
CVEs (CVE-2026-30615, 30617, 30623, 22252, 22688, 33224, 40933, 6980)
all trace to `StdioServerParameters(command=<network_input>)` across
the upstream MCP SDKs; v0.3.6 ships one rule per language plus the
marketplace-fetch single-line shape Cloudflare's MCP-defender writeup
called out as the highest-risk bug in the wild.

### Added — rule coverage (8 new rules, 161 → 169)

- **AAK-MCP-STDIO-CMD-INJ-001** (CRITICAL, SUPPLY_CHAIN, Python) —
  `StdioServerParameters(command=...)` from `mcp.client.stdio` /
  `modelcontextprotocol.client` reached via tainted source. AST walk
  with calls sorted by source line.
- **AAK-MCP-STDIO-CMD-INJ-002** (CRITICAL, TypeScript) —
  `new StdioClientTransport({...})` after a fetch / req.body /
  process.env / JSON.parse marker. Regex pass.
- **AAK-MCP-STDIO-CMD-INJ-003** (CRITICAL, Java) —
  `StdioServerParameters.Builder().command(...).args(...).build()`
  after a HttpServletRequest / RestTemplate / WebClient /
  ObjectMapper.readValue / System.getenv marker. Nested-paren-safe
  regex (split into opener + terminator-window scan).
- **AAK-MCP-STDIO-CMD-INJ-004** (CRITICAL, Rust, regex-only) —
  `Command::new(...)` adjacent to mcp_sdk / modelcontextprotocol
  imports after a reqwest / serde_json / std::env / hyper / actix /
  axum body-extractor marker. ~10% FP rate on macro-heavy codebases
  until #22 lands tree-sitter-rust.
- **AAK-MCP-MARKETPLACE-CONFIG-FETCH-001** (CRITICAL, SUPPLY_CHAIN) —
  fetch(URL) → StdioServerParameters in same function. Suppression
  via `.aak-mcp-marketplace-trust.yml` with required justification.
- **AAK-AZURE-MCP-NOAUTH-001** (HIGH, MCP_CONFIG, server-side) — repos
  publishing Azure-MCP-shaped servers without auth middleware on
  `/mcp/*` routes. Sister to v0.3.5's consumer-side AAK-AZURE-MCP-001.
  CVE-2026-32211.
- **AAK-LMDEPLOY-VL-SSRF-001** (HIGH, TRANSPORT_SECURITY) — LMDeploy
  VL image-loader fetches user-controlled URLs without allow-list.
  CVE-2026-33626 (GHSA-only at cut; NVD enrichment pending).
- **AAK-SPLUNK-MCP-TOKEN-LEAK-001** (HIGH, SECRET_EXPOSURE,
  config variant) — splunk-mcp-server config files routing token
  sourcetypes to `_internal` / `_audit` indexes. Distinct from v0.3.4's
  runtime taint detector AAK-SPLUNK-TOKLOG-001.

### Added — preset infrastructure

- `agent_audit_kit/presets/__init__.py` + `load_preset()` registry.
- `agent_audit_kit/presets/mcp-ox-2026-04.yaml` bundles 12 OX-class
  rules.
- CLI flag `--preset <name>` + `preset:` input in `action.yml` +
  positional arg in `entrypoint.sh`.
- Per-preset doc at `docs/presets/mcp-ox-2026-04.md`.

### Caveats

- Rust adapter is regex-only until #22 lands tree-sitter-rust.
- CVE-2026-33626 ships citing GHSA index entry; NVD enrichment
  pending. Pin floor will tighten in v0.3.7.

## [0.3.5] - 2026-04-25

**Headline: LangChain SSRF redirect (CVE-2026-41481), URL-allow-list TOCTOU /
DNS rebinding (CVE-2026-41488), Azure MCP missing-auth (CVE-2026-32211),
toxic-flow source/sink scanner (Snyk Agent Scan parity, feature-flagged),
pre-commit `rev:` pin sync, GitHub verified-creator application packet.**

Closes the watcher-filed 48h SLA on #61 and #62, ships the broader
validate-then-fetch class as two distinct rules (redirect bypass vs. DNS
rebinding TOCTOU), pulls Snyk's toxic-flow scanner into the AAK rule set
behind a feature flag, and removes the README pre-commit `rev:` drift the
v0.3.4 sync workflow missed.

### Added — rule coverage (4 new rules, 157 → 161)

- **AAK-LANGCHAIN-SSRF-REDIR-001** (HIGH, Category.TRANSPORT_SECURITY) —
  validate-then-fetch SSRF: a function calls a known SSRF guard helper
  (`validate_safe_url`, `is_safe_url`, `validateSafeUrl`, …) and then
  fetches via `requests.get` / `httpx.get` / `urllib.urlopen` / `fetch` /
  `axios.get` / `got` without `allow_redirects=False`,
  `follow_redirects=False`, `redirect: 'manual'`, or `maxRedirects: 0`.
  CVE-2026-41481 (langchain-text-splitters < 1.1.2). New scanner
  `scanners/ssrf_redirect.py` walks Python AST (sorted by source line so
  BFS-walk doesn't reorder fetch-before-guard) and applies a regex pass
  for TS/JS sources. Pin-check across `requirements*.txt`,
  `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `uv.lock`.
- **AAK-SSRF-TOCTOU-001** (MEDIUM, Category.TRANSPORT_SECURITY) —
  validate-then-fetch DNS-rebind / TOCTOU. Same SSRF guard but the rule
  fires on the second-DNS-resolution shape: guard call followed by a
  fetch with no IP-pinning marker (`socket.getaddrinfo`, `HTTPAdapter`,
  `pinned_ip`, `Host:` header pin) in the same function. CVE-2026-41488
  (langchain-openai < 1.1.14). New scanner `scanners/ssrf_toctou.py`.
- **AAK-AZURE-MCP-001** (HIGH, Category.MCP_CONFIG) — Azure MCP server
  consumed without authentication. Detects `.mcp.json` / `.azure-mcp/`
  configs that point at an Azure MCP endpoint without `Authorization:`,
  mTLS client cert, or Azure-AD / managed-identity token. CVE-2026-32211
  (CVSS 9.1, server-side default ships with no auth). Extends
  `scanners/supply_chain.py`.
- **AAK-TOXICFLOW-001** (HIGH, Category.TOOL_POISONING) — Snyk Agent Scan
  parity. Per-scan tool-graph from MCP servers in `.mcp.json` and
  `@tool`/`@mcp.tool`-decorated Python functions. Emits a finding for
  every (sensitive_source, external_sink) pair listed in
  `agent_audit_kit/data/toxic_flow_pairs.yml` unless allow-listed in
  `.aak-toxic-flow-trust.yml` with a non-empty justification. Behind
  `AAK_TOXIC_FLOW=1` feature flag for v0.3.5; full deny-graph design
  review queues for v0.4.0. New scanner `scanners/toxic_flow.py`, data
  file `agent_audit_kit/data/toxic_flow_pairs.yml`.

### Added — release-mechanics / docs

- `scripts/sync_repo_metadata.py` extended with
  `_PRECOMMIT_BLOCK_RE` — rewrites `rev: vX.Y.Z` lines under
  `repo: https://github.com/sattyamjjain/agent-audit-kit` only (won't
  touch unrelated pre-commit hooks). New regression test
  `test_pre_commit_rev_pin_matches_version` proves the README pre-commit
  example aligns with `pyproject.toml` on every PR.
- `docs/launch/github-verified-creator-application.md` — pre-filled
  application packet for the GitHub Marketplace verified-creator badge,
  citing PyPI OIDC trusted publishing, Sigstore attestations, SLSA
  provenance v1, Immutable-Action manifest, and the 749-test +
  161-rule signed bundle.

### Fixed

- README pre-commit example pinned at `rev: v0.3.0` while v0.3.4 was
  current — surfaced by browsing main on 2026-04-25. The new
  `_PRECOMMIT_BLOCK_RE` pass and its regression test prevent recurrence.

### Issue closures

- Closes #61 (CVE-response: CVE-2026-41481) — covered by
  AAK-LANGCHAIN-SSRF-REDIR-001.
- Closes #62 (CVE-response: CVE-2026-41488) — covered by
  AAK-SSRF-TOCTOU-001.

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
