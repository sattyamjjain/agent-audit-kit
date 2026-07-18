# AAK CVE-to-Rule Ledger

We triage newly disclosed MCP CVEs continuously and ship rule coverage as fast
as we responsibly can — no fixed public deadline (see `ROADMAP_2026.md §2.3`).
This file is the audit trail of what shipped and when.

Format: one line per CVE, `CVE-YYYY-NNNNN` → `AAK-XXX-NNN` with the
shipped-at timestamp. The GitHub Action `.github/workflows/cve-watcher.yml`
diffs NVD's MCP keyword feed against this file and opens a `cve-response`
issue (retaining the `sla-48h` label as a release-gate mechanism key) for
anything new.

## MCP 2026-07-28 ratification reconciliation — 2026-07-16 (v0.3.50)

The 2026-07-28 MCP specification is still a **release candidate** as of this
date: the RC was locked on 2026-05-21 (milestone `2026-07-28-RC`) and the final,
ratified spec publishes on **2026-07-28** (12 days out). Every AAK rule shipped
in July for that spec is therefore *correctly* labelled "release candidate" — no
rule is relabelled "ratified" ahead of publication. This attestation records that
each rule's cited SEP number was re-verified against primary sources and is
accurate; nothing needed correcting.

Primary sources: [SEP-2596 PR #2596](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2596)
(labelled `final`, milestone `2026-07-28-RC`),
[SEP-2577/2596 spec-incorporation PR #2791](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2791),
[2026-07-28 RC blog](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/).

| Rule(s) | Cited SEP(s) | Verified meaning | Status |
|---|---|---|---|
| AAK-MCP-DEPRECATED-001..003 | SEP-2577 + SEP-2596 | SEP-2577 annotation-deprecates Roots/Sampling/Logging; SEP-2596 is the 12-month feature-lifecycle & deprecation policy | ✓ accurate · RC label correct |
| AAK-OAUTH-006 | SEP-2468 (RFC 9207) | `iss` authorization-response validation | ✓ accurate · RC label correct |
| AAK-MCP-STATELESS-001 | SEP-2567, SEP-2575, SEP-1442 | session removal / stateless transport; optional initialization handshake | ✓ accurate · RC label correct |
| AAK-MCP-STATELESS-002 | SEP-1686, SEP-2663 | experimental Tasks primitive → Tasks extension | ✓ accurate · RC label correct |

Separately, **AAK-OAUTH-007** (new in v0.3.50) is cited to the **ratified** MCP
2025-11-25 authorization spec — RFC 8707 Resource Indicators are mandatory today
(`resource` parameter on authorization + token requests; server-side audience
validation), independent of the 2026-07-28 RC. It is not part of this RC
reconciliation.

## Shipped in v0.3.50 (2026-07-18) — 2026-07-15..17 wave

Response to a second 2026-07 disclosure wave (24 CVEs, issues #445–#468) the NVD
watcher filed while the earlier backlog was being cleared. Fourteen CVEs cluster
onto seven pinnable packages (many share one fix version) and ship as version-pins
(`mcp_cve_pins_2026_07`, now 22 pins); one is covered by an existing pin; nine are
dispositioned (PHP / GitHub Action / WordPress ecosystems, no vendor fix, or no NVD
version data). Packages + floors verified against PyPI / npm; `mcp` and `n8n-mcp`
pins use precise token regexes so they never trip `fastmcp` / `mcp-text-editor` /
`n8n`.

| Incident / Anchor | Reference | AAK rule(s) / disposition | Shipped |
|---|---|---|---|
| CVE-2026-52869 + CVE-2026-52870 + CVE-2026-59950 (MCP Python SDK `mcp` < 1.28.1 — cross-client session injection, task cross-access, WebSocket no-Origin) | [NVD CVE-2026-52869](https://nvd.nist.gov/vuln/detail/CVE-2026-52869) (HIGH, CVSS 7.1) | **AAK-MCP-SDK-CVE-2026-52869-001** (NEW: HIGH, SUPPLY_CHAIN — pin `mcp` >= 1.28.1) | 2026-07-18 |
| CVE-2026-46339 + CVE-2026-49353 + CVE-2026-62312 (9Router `9router` < 0.5.2 — unauthenticated MCP bridge → command exec / RCE) | [NVD CVE-2026-46339](https://nvd.nist.gov/vuln/detail/CVE-2026-46339) (CRITICAL, CVSS 10) | **AAK-MCP-9ROUTER-CVE-2026-46339-001** (NEW: CRITICAL, SUPPLY_CHAIN — pin `9router` >= 0.5.2) | 2026-07-18 |
| CVE-2026-54052 + CVE-2026-55608 (n8n-MCP `n8n-mcp` < 2.57.4 — multi-tenant workflow-backup isolation bypass) | [NVD CVE-2026-54052](https://nvd.nist.gov/vuln/detail/CVE-2026-54052) (CRITICAL, CVSS 9.9) | **AAK-MCP-N8NMCP-CVE-2026-54052-001** (NEW: CRITICAL, SUPPLY_CHAIN — pin `n8n-mcp` >= 2.57.4) | 2026-07-18 |
| CVE-2026-44968 + CVE-2026-44970 + CVE-2026-44969 (dbt-mcp `dbt-mcp` < 1.17.1 — dbt-flag injection into subprocess argv; tool-arg leakage via telemetry + file logging) | [NVD CVE-2026-44968](https://nvd.nist.gov/vuln/detail/CVE-2026-44968) (MEDIUM, CVSS 6.3) | **AAK-MCP-DBTMCP-CVE-2026-44968-001** (NEW: MEDIUM, SUPPLY_CHAIN — pin `dbt-mcp` >= 1.17.1) | 2026-07-18 |
| CVE-2026-46341 (Apify MCP `@apify/actors-mcp-server` < 0.9.21 — `fetch-apify-docs` `startsWith()` allowlist bypass → SSRF) | [NVD CVE-2026-46341](https://nvd.nist.gov/vuln/detail/CVE-2026-46341) (MEDIUM, CVSS 6.1) | **AAK-MCP-APIFY-CVE-2026-46341-001** (NEW: MEDIUM, SUPPLY_CHAIN — pin `@apify/actors-mcp-server` >= 0.9.21) | 2026-07-18 |
| CVE-2026-58195 (Agentic-Flow `agentic-flow` < 2.0.14 — MCP tool params interpolated into `execSync()` → OS command injection) | [NVD CVE-2026-58195](https://nvd.nist.gov/vuln/detail/CVE-2026-58195) (HIGH, CVSS 8.8) | **AAK-MCP-AGENTICFLOW-CVE-2026-58195-001** (NEW: HIGH, SUPPLY_CHAIN — pin `agentic-flow` >= 2.0.14) | 2026-07-18 |
| CVE-2026-15415 (AWS HealthOmics MCP `awslabs.aws-healthomics-mcp-server` < 0.0.36 — `workflow_files` directory traversal writes outside the bundle dir) | [NVD CVE-2026-15415](https://nvd.nist.gov/vuln/detail/CVE-2026-15415) (MEDIUM, CVSS 5.5) | **AAK-MCP-HEALTHOMICS-CVE-2026-15415-001** (NEW: MEDIUM, SUPPLY_CHAIN — pin >= 0.0.36) | 2026-07-18 |
| CVE-2026-62208 (OpenClaw before 2026.6.5 — Authorization headers forwarded during MCP SSE redirects) | [NVD CVE-2026-62208](https://nvd.nist.gov/vuln/detail/CVE-2026-62208) (MEDIUM, CVSS 6.5) | **Covered** by `AAK-MCP-OPENCLAW-CVE-2026-62195-001` (fires < 2026.6.6, which includes the < 2026.6.5 affected range); CVE added to that rule's references | 2026-07-18 |
| CVE-2026-46512 / 46513 / 46514 / 46515 (Frogman headless-PBX MCP < 1.6.2 / 1.6.3 — dialplan injection → Asterisk RCE, raw API-token storage, plaintext creds in audit log, PERM_READ over-exposure) | [NVD CVE-2026-46512](https://nvd.nist.gov/vuln/detail/CVE-2026-46512) (CRITICAL, CVSS 9.9) | **Documented, not pinned** — Frogman is a PHP application (`Tools/*.php`, `oc_*` tables); AAK's pin detector reads PyPI/npm manifests only | 2026-07-18 |
| CVE-2026-47751 (Claude Code Action < 1.0.74 — checks out attacker PR head + auto-enables all project MCP servers from a malicious `.mcp.json` → runner RCE + secret exfil) | [NVD CVE-2026-47751](https://nvd.nist.gov/vuln/detail/CVE-2026-47751) (CVSS n/a) | **Documented, not pinned** — a GitHub Action pinned in `.github/workflows` (`uses: anthropics/claude-code-action@vX`), not a PyPI/npm manifest artifact | 2026-07-18 |
| CVE-2026-9810 (AI Copilot WordPress plugin < 1.5.4 — OAuth token not bound to a WP user → unauth admin MCP-tool execution) | [NVD CVE-2026-9810](https://nvd.nist.gov/vuln/detail/CVE-2026-9810) (CVSS n/a) | **Documented, not pinned** — a WordPress/PHP plugin; unsupported ecosystem for the pin detector | 2026-07-18 |
| CVE-2026-57860 (ForgeCode `forgecode` — auto-loads + executes a repo's `.mcp.json` on startup with no confirmation → RCE from an untrusted repo) | [NVD CVE-2026-57860](https://nvd.nist.gov/vuln/detail/CVE-2026-57860) (HIGH, CVSS 7.8) | **Documented, not pinned** — NVD/advisory name no fixed version (design-level auto-exec); untrusted-`.mcp.json`-launch class | 2026-07-18 |
| CVE-2026-9135 + CVE-2026-7755 (IBM Langflow OSS — ToolGuard dynamic-CodeInput code injection bypassing `allow_custom_components=false`; RCE via incomplete MCP-config validation) | [NVD CVE-2026-9135](https://nvd.nist.gov/vuln/detail/CVE-2026-9135) (CRITICAL, CVSS 9.9) | **Documented, not pinned** — NVD published no CPE data and the affected range is ambiguous (`1.0.0`–`1.10.0` vs "up to 1.9.2"); will pin once the fixed version is confirmed (tracked) | 2026-07-18 |

## Shipped in v0.3.50 (2026-07-16)

Response to the 2026-07-13..15 disclosure wave (13 CVEs, issues #429–#442).
Eight have a vendor fix + a pinnable PyPI/npm artifact and ship as version-pins
(`mcp_cve_pins_2026_07`); five have no pinnable artifact, no vendor fix, or an
unsupported ecosystem and are dispositioned below. Package names, fix floors, and
(where NVD published CPE data) affected ranges were verified against PyPI / npm /
NVD before shipping.

| Incident / Anchor | Reference | AAK rule(s) / disposition | Shipped |
|---|---|---|---|
| CVE-2026-15643 (AWS HealthLake MCP `awslabs.healthlake-mcp-server` < 0.0.14 — `next_token` pagination SSRF exfiltrates AWS temporary credentials to an attacker endpoint) | [NVD CVE-2026-15643](https://nvd.nist.gov/vuln/detail/CVE-2026-15643) (HIGH, CVSS 7.3) | **AAK-MCP-HEALTHLAKE-CVE-2026-15643-001** (NEW: HIGH, SUPPLY_CHAIN — pin >= 0.0.14) | 2026-07-16 |
| CVE-2026-61427 (PraisonAI `praisonai` < 4.6.78 — MCP HTTP-stream unauthenticated by default; `--api-key` defaults to None → `tools/list` + `tools/call`) | [NVD CVE-2026-61427](https://nvd.nist.gov/vuln/detail/CVE-2026-61427) (HIGH, CVSS 7.3) | **AAK-MCP-PRAISONAI-CVE-2026-61427-001** (NEW: HIGH, SUPPLY_CHAIN — pin >= 4.6.78) | 2026-07-16 |
| CVE-2026-58500 (MCP Appium `appium-mcp` < 1.85.10 — `createLocatorGeneratorUI` HTML/JS injection → `window.parent.postMessage` invokes arbitrary MCP tools) | [NVD CVE-2026-58500](https://nvd.nist.gov/vuln/detail/CVE-2026-58500) (HIGH, CVSS 8.2) | **AAK-MCP-APPIUM-CVE-2026-58500-001** (NEW: HIGH, SUPPLY_CHAIN — pin >= 1.85.10) | 2026-07-16 |
| CVE-2026-45805 (Penpot MCP `@penpot/mcp` < 2.15.0 — ReplServer on `0.0.0.0:4403` exposes unauthenticated `/execute` → JS RCE) | [NVD CVE-2026-45805](https://nvd.nist.gov/vuln/detail/CVE-2026-45805) (HIGH, CVSS 8.8) | **AAK-MCP-PENPOT-CVE-2026-45805-001** (NEW: CRITICAL, SUPPLY_CHAIN — pin >= 2.15.0) | 2026-07-16 |
| CVE-2026-62195 (OpenClaw `openclaw` 2026.5.20–<2026.6.6 — MCP loopback authorization bypass lets lower-trust callers run owner-only tools) | [NVD CVE-2026-62195](https://nvd.nist.gov/vuln/detail/CVE-2026-62195) (HIGH, CVSS 8.3; NVD CPE `2026.5.20` <= v < `2026.6.6`) | **AAK-MCP-OPENCLAW-CVE-2026-62195-001** (NEW: HIGH, SUPPLY_CHAIN — pin >= 2026.6.6, introduced 2026.5.20) | 2026-07-16 |
| CVE-2026-49988 (Repomix `repomix` < 1.14.1 — MCP `attach_packed_output`/`read_repomix_output` reads local files without the `runSecretLint()` boundary) | [NVD CVE-2026-49988](https://nvd.nist.gov/vuln/detail/CVE-2026-49988) (CVSS n/a) | **AAK-MCP-REPOMIX-CVE-2026-49988-001** (NEW: MEDIUM, SUPPLY_CHAIN — pin >= 1.14.1) | 2026-07-16 |
| CVE-2026-53512 + CVE-2026-53518 (Better Auth `better-auth` / `@better-auth/oauth-provider` < 1.6.11 — refresh-token grant skips `client_secret`; auth-code non-atomic find-then-delete → code replay; both reachable via `mcp`/`oidcProvider` plugins) | [NVD CVE-2026-53512](https://nvd.nist.gov/vuln/detail/CVE-2026-53512) (CVSS n/a) | **AAK-MCP-BETTERAUTH-CVE-2026-53512-001** (NEW: HIGH, SUPPLY_CHAIN — pin >= 1.6.11) | 2026-07-16 |
| CVE-2026-61462 (mcp-gitlab — `job_id` path traversal in `build/index.js` redirects GitLab API calls using the operator PAT) | [NVD CVE-2026-61462](https://nvd.nist.gov/vuln/detail/CVE-2026-61462) (HIGH, CVSS 8.6) | **Documented, not pinned** — NVD has published no CPE/version data and the description names no fixed version; the "mcp-gitlab" npm name is ambiguous across several GitLab MCP servers. Will pin once the vendor fix version is confirmed (tracked). | 2026-07-16 |
| CVE-2026-15749 (mastergo-design `mastergo-magic-mcp` <= 0.2.0 — `get-c2d.ts` `filePath` path traversal) | [NVD CVE-2026-15749](https://nvd.nist.gov/vuln/detail/CVE-2026-15749) (MEDIUM, CVSS 5.3) | **Documented, not pinned** — no PyPI/npm artifact (GitHub-only TS project) and NVD notes the vendor has not responded / released no fix, so there is no floor to pin. Path-traversal-in-tool-arg class. | 2026-07-16 |
| CVE-2026-15750 (mastergo-design `mastergo-magic-mcp` <= 0.2.0 — `get-component-link.ts` `url` SSRF) | [NVD CVE-2026-15750](https://nvd.nist.gov/vuln/detail/CVE-2026-15750) (MEDIUM, CVSS 6.3) | **Class-covered** by `AAK-MCP-SSRF-001` (unvalidated tool-arg URL → fetch); no pinnable artifact / vendor fix | 2026-07-16 |
| CVE-2026-15751 (mastergo-design `mastergo-magic-mcp` <= 0.2.0 — `component-workflow.md` `rootPath` path traversal) | [NVD CVE-2026-15751](https://nvd.nist.gov/vuln/detail/CVE-2026-15751) (MEDIUM, CVSS 5.3) | **Documented, not pinned** — same package/disposition as CVE-2026-15749 (no artifact, no vendor fix) | 2026-07-16 |
| CVE-2026-15583 (Grafana MCP Server — `X-Grafana-URL` header confused-deputy exfiltrates the service-account token + SSRF to internal/metadata endpoints) | [NVD CVE-2026-15583](https://nvd.nist.gov/vuln/detail/CVE-2026-15583) (HIGH, CVSS 8.6) | **Documented, not pinned** — `mcp-grafana` is a Go module; AAK's pin detector reads PyPI/npm manifests only. SSRF / confused-deputy class. | 2026-07-16 |

## Shipped in v0.3.49 (2026-07-13)

Batch response to the 2026-07-08..12 disclosure wave (13 CVEs). Eight have a
vendor fix + a pinnable PyPI/npm artifact and ship as version-pins
(`mcp_cve_pins_2026_07`); three have no pinnable artifact or a tractable version
scheme and are dispositioned below. Latency exceeds the 48h target for the
earlier CVEs — this backlog accumulated between the v0.3.48 and v0.3.49 releases
and is recorded honestly.

| Incident / Anchor | Reference | AAK rule(s) / disposition | Shipped |
|---|---|---|---|
| CVE-2026-59822 + CVE-2026-59820 (LiteLLM < 1.84.0 — MCP Streamable-HTTP auth bypass via empty `UserAPIKeyAuth()` fallback; skills-archive ZIP path traversal) | [NVD CVE-2026-59822](https://nvd.nist.gov/vuln/detail/CVE-2026-59822) (CVSS n/a) | **AAK-MCP-LITELLM-CVE-2026-59822-001** (NEW: HIGH, SUPPLY_CHAIN — pin `litellm` >= 1.84.0) | 2026-07-13 |
| CVE-2026-59723 (Cline < 3.0.30 — Hub-dashboard `/browser` WebSocket accepts frames without Origin validation → workspace read + settings mutation + command exec) | [NVD CVE-2026-59723](https://nvd.nist.gov/vuln/detail/CVE-2026-59723) (HIGH, CVSS 8.8) | **AAK-MCP-CLINE-CVE-2026-59723-001** (NEW: HIGH, SUPPLY_CHAIN — pin `cline` >= 3.0.30) | 2026-07-13 |
| CVE-2026-15138 (tumf mcp-text-editor — `_validate_file_path` path traversal via `file_path`; NVD affected up to 1.0.2) | [NVD CVE-2026-15138](https://nvd.nist.gov/vuln/detail/CVE-2026-15138) (MEDIUM, CVSS 6.3) | **AAK-MCP-TEXTEDITOR-CVE-2026-15138-001** (NEW: MEDIUM, SUPPLY_CHAIN — pin `mcp-text-editor` past 1.0.2) | 2026-07-13 |
| CVE-2026-59207 (n8n < 2.27.4 / 2.28.1 — AI-Agent MCP tool bypasses credential "Allowed HTTP Request Domains" → shared-credential exfil) | [NVD CVE-2026-59207](https://nvd.nist.gov/vuln/detail/CVE-2026-59207) (MEDIUM, CVSS 6.5) | **AAK-MCP-N8N-CVE-2026-59207-001** (NEW: MEDIUM, SUPPLY_CHAIN — pin `n8n` >= 2.27.4 / 2.28.1) | 2026-07-13 |
| CVE-2026-59726 (ruflo < 3.16.3 — default docker-compose exposes MCP bridge `POST /mcp` unauthenticated → `tools/call` `terminal_execute` RCE, key theft, AgentDB poisoning) | [NVD CVE-2026-59726](https://nvd.nist.gov/vuln/detail/CVE-2026-59726) (CRITICAL, CVSS 10) | **AAK-MCP-RUFLO-CVE-2026-59726-001** (NEW: CRITICAL, SUPPLY_CHAIN — pin `ruflo` >= 3.16.3) | 2026-07-13 |
| CVE-2026-55604 + CVE-2026-55605 (@arikusi/deepseek-mcp-server 1.4.2–<1.8.0 — process-global `SessionStore` accepts unbound `session_id` → session hijack; unauth `POST /mcp` HTTP transport) | [NVD CVE-2026-55604](https://nvd.nist.gov/vuln/detail/CVE-2026-55604) (HIGH, CVSS 8.6) | **AAK-MCP-DEEPSEEK-CVE-2026-55604-001** (NEW: HIGH, SUPPLY_CHAIN — pin `@arikusi/deepseek-mcp-server` >= 1.8.0) | 2026-07-13 |
| CVE-2026-61459 (MCP Server Kubernetes < 3.9.0 — leading-dash `resourceType`/`name` bypass `assertNoDangerousFlags`, inject `--server` to redirect kubectl → bearer-token exfil → cluster compromise) | [NVD CVE-2026-61459](https://nvd.nist.gov/vuln/detail/CVE-2026-61459) (CRITICAL, CVSS 9.8) | **AAK-MCP-K8S-CVE-2026-61459-001** (NEW: CRITICAL, SUPPLY_CHAIN — pin `mcp-server-kubernetes` >= 3.9.0) | 2026-07-13 |
| CVE-2026-15501 (AstrBot ≤ 4.25.2 — `ToolsRoute.test_mcp_connection` fetches caller-supplied `mcp_server_config.url` → SSRF) | [NVD CVE-2026-15501](https://nvd.nist.gov/vuln/detail/CVE-2026-15501) (MEDIUM, CVSS 6.3) | **AAK-MCP-ASTRBOT-CVE-2026-15501-001** (NEW: MEDIUM, SUPPLY_CHAIN — pin `astrbot` past 4.25.2) | 2026-07-13 |
| CVE-2026-15189 (aerostackdev aerostack-mcp — `upload_media` `media_url` SSRF; rolling release, no version, no PyPI/npm artifact) | [NVD CVE-2026-15189](https://nvd.nist.gov/vuln/detail/CVE-2026-15189) (MEDIUM, CVSS 6.3) | **Class-covered** by `AAK-MCP-SSRF-001` (unvalidated tool-arg URL → fetch); no pinnable artifact to add | 2026-07-13 |
| CVE-2026-54149 (MaxKB < 2.10.0-lts — `.tool` import allows stdio transport with malicious commands → `MultiServerMCPClient` executes arbitrary system commands) | [NVD CVE-2026-54149](https://nvd.nist.gov/vuln/detail/CVE-2026-54149) (HIGH, CVSS 8.8) | **Class-covered** by `AAK-MCP-STDIO-CMD-INJ-*` (MCP stdio command-injection); MaxKB is a Docker app, no PyPI/npm artifact to pin | 2026-07-13 |
| CVE-2026-55405 (LangChain4j MariaDB / pgvector embedding stores — metadata-filter SQL injection via string-concatenated filter keys) | [NVD CVE-2026-55405](https://nvd.nist.gov/vuln/detail/CVE-2026-55405) (HIGH, CVSS 7.6) | **Documented, not pinned** — fixed in `langchain4j-mariadb`/`langchain4j-pgvector` 1.2.1-beta8 / 1.5.1-beta11 / 1.11.8-beta19 / 1.16.3-beta26; four parallel beta fix-lines can't be one semver floor and AAK has no Maven pin ecosystem yet (tracked) | 2026-07-13 |

## Shipped in v0.3.48 (2026-07-08)

| Incident / Anchor | Reference | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-49471 (Serena MCP toolkit `serena-agent` < 1.5.2 — unauthenticated Flask dashboard on a fixed port + DNS rebinding writes the agent's persistent memory, chained with `execute_shell_command` `shell=True` to RCE; CWE-306 + CWE-352) | [NVD CVE-2026-49471](https://nvd.nist.gov/vuln/detail/CVE-2026-49471) (HIGH, CVSS 8.3, published 2026-07-07) | **AAK-MCP-SERENA-CVE-2026-49471-001** (NEW: HIGH, MCP_CONFIG — version-pin, fires < 1.5.2 / unpinned / unpinned `oraios/serena` launch ref) | 2026-07-08 | <24h on NVD |
| CVE-2026-14748 (AIAnytime Awesome-MCP-Server `mcp-wiki/wiki-summary` — SSRF: the `url` argument of the tool handler is fetched server-side with no host/scheme allow-list, CWE-918; rolling-release project, no fixed version) | [NVD CVE-2026-14748](https://nvd.nist.gov/vuln/detail/CVE-2026-14748) (MEDIUM, CVSS 6.3, published 2026-07-05) | **AAK-MCP-SSRF-001** (NEW: MEDIUM, MCP_CONFIG — `ast` param→fetch taint / regex fallback, fires on unvalidated tool-arg URL) | 2026-07-08 | ~72h on NVD (past 48h target) |

## Shipped in v0.3.47 (2026-07-07)

| Incident / Anchor | Reference | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-14471 (Amazon mcp-gateway-registry < 1.0.13 — SQL injection: crafted `table_name` interpolated into an SQL identifier in the metrics-service retention policy, CWE-89) | [NVD CVE-2026-14471](https://nvd.nist.gov/vuln/detail/CVE-2026-14471) (HIGH, CVSS 8.1, published 2026-07-06) | **AAK-MCP-GATEWAY-REGISTRY-CVE-2026-14471-001** (NEW: HIGH, SUPPLY_CHAIN — version-pin, fires < 1.0.13 / unpinned) | 2026-07-07 | <24h on NVD |

## Shipped in v0.3.46 (2026-07-06)

| Incident / Anchor | Reference | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-58057 (Flowise < 3.1.3 — case-sensitive NODE_OPTIONS denylist bypass → `node_options` on Windows → `NODE_OPTIONS --require` RCE) | [NVD CVE-2026-58057](https://nvd.nist.gov/vuln/detail/CVE-2026-58057) (CVSS 5.0, published 2026-06-28) | **AAK-FLOWISE-001** (pin floor bumped 3.1.2 → 3.1.3; 3.1.2 configs now flag) | 2026-07-06 | version-pin extension |

## Shipped in v0.3.22 (2026-05-20)

| Incident / Anchor | Reference | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| arXiv:2605.18401 — SkillsVote (Liu et al., Memtensor, 2026-05-18) | Lifecycle governance for Agent Skills — evidence-gated update loop depends on per-execution outcome attribution | **AAK-SKILL-LIFECYCLE-ATTRIBUTION-001** (NEW: MEDIUM, research-grade — Python AST detector for @skill execute() functions that mutate persistent state but emit no outcome-attribution call. **Honest scope**: invented YAML schemas from the prompt — `requires_search`, `depends_on` — were NOT shipped; paper doesn't define them) | 2026-05-20 | <72h on paper anchor |
| arXiv:2605.18747 — Code as Agent Harness (Ning et al., 42 authors, 2026-05-18) | Survey of 110+ papers + 23 systems naming "consistent shared state across multiple agents" as an explicit open challenge | **AAK-AGENT-HARNESS-SHARED-STATE-001** (NEW: MEDIUM, research-grade — Python AST detector for >=2 Agent/Worker/Harness classes mutating a module-level mutable container without a lock primitive visible in scope) | 2026-05-20 | <72h on paper anchor |
| CVE-2026-2611 (MLflow 3.9.0 origin-validation bypass) | NVD CVE-2026-2611 — `/ajax-api` CSRF via cross-origin requests | **No named rule shipped** — class-covered by `AAK-TRUST-001..005` (origin / CORS allowlist) + `AAK-OAUTH-001..005`. Pin-floor `mlflow<3.9.1` named-row queued for v0.3.23+ if a fresh CVE warrants | 2026-05-20 (triage closure) | class-coverage |

## Shipped in v0.3.21 (2026-05-19)

| Incident / Anchor | Reference | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| Anthropic acquires Stainless (2026-05-18) | [anthropic.com/news/anthropic-acquires-stainless](https://www.anthropic.com/news/anthropic-acquires-stainless) — Stainless is the API-spec-to-SDK / CLI / MCP-server generator, now under Anthropic stewardship | **AAK-MCP-LINEAGE-STAINLESS-001** (NEW: provenance / lineage detector, INFO severity — banner-regex + config-as-code detection. **Provenance only**: announcement makes no claim of bifurcated default-posture, AAK doesn't either) | 2026-05-19 | <24h on the acquisition announcement |
| CVE-2026-47090 + CVE-2026-47092 (Claude HUD) | [NVD CVE-2026-47090](https://nvd.nist.gov/vuln/detail/CVE-2026-47090) — OSC 8 hyperlink injection (MEDIUM); [NVD CVE-2026-47092](https://nvd.nist.gov/vuln/detail/CVE-2026-47092) — `COMSPEC` command injection (HIGH) | **No named pin shipped** — Claude HUD has no published npm/PyPI surface; pin-floor SAST rule has no manifest to match. Runtime shapes are already covered by `AAK-LOG-INJECTION-001` (OSC 8 terminal escapes) + `AAK-MCP-STDIO-CMD-INJ-001..004` (env-var-controlled subprocess) | 2026-05-19 (triage closure) | honest triage — class-covered for runtime shape; no pin possible without public package |

## Shipped in v0.3.20 (2026-05-18)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| arXiv:2605.10067 — Metis (ICML 2026) | Inference-time policy optimization within adversarial POMDP — closed-loop reasoning trajectories with refusal-feedback / scoring-string semantic gradient | **AAK-METIS-REFUSAL-REFEED-001** + **AAK-METIS-SCORING-SINK-001** (NEW: two research-grade MEDIUM rules; 3 speculative shapes from the original prompt deferred to v0.3.21+ pending defensive-side follow-up) | 2026-05-18 | Metis paper anchor — non-CVE academic; research-grade tier |
| Issue #163 (internal) — cve-watcher dedup bug | The cve-watcher's `state=open`-only issue lookup caused the same CVE IDs to re-fire as new tickets on each daily cycle (28+ dup closures across 2026-05-13 → 2026-05-18). | **cve-watcher fix** (not a rule — `scripts/cve_watcher.py:_open_issue_cves` renamed to `_all_issue_cves` and now queries `state=all` with pagination; closed-issue regression test added) | 2026-05-18 | 5+ days from first observation to fix |

## Shipped in v0.3.19 (2026-05-17)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-44717 (architectural class) | Source-side generalization of yesterday's `mcp-calculate-server` pin to any MCP server with the same shape | **AAK-MCP-TOOL-UNSAFE-EVAL-001** (NEW: Python AST detector for `eval()`/`exec()` in `@mcp.tool` handlers) | 2026-05-17 | same-day as v0.3.18 named-pin row |
| arXiv:2605.14312 — Hermes (EASE 2026) | OpenAPI-to-MCP migration smell taxonomy (2,450 smells / 600 endpoints) | **AAK-MCP-OPENAPI-LAZY-DESCRIPTION-001** + **AAK-MCP-OPENAPI-BLOATED-PARAMS-001** + **AAK-MCP-OPENAPI-TANGLED-METHODS-001** (NEW: 3-rule smell category + new scanner module + auto-detect of `openapi.{yaml,json}` in project tree) | 2026-05-17 | Hermes paper is the primary incident anchor; non-CVE academic research-driven category |

## Shipped in v0.3.18 (2026-05-17)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-44717 | [NVD 2026-05-15](https://nvd.nist.gov/vuln/detail/CVE-2026-44717) — `mcp-calculate-server` <0.1.1 routes MCP tool input through `eval()` (SymPy-backed, no `local_dict` pinning), CVSS 9.8 CRITICAL; patched in 0.1.1 (latest at ship: 1.0.0) | **AAK-MCPCALC-CVE-2026-44717-PIN-001** (NEW: PyPI pin-floor; broader source-detector for unsafe-eval in any `@mcp.tool` handler queued for v0.3.19) | 2026-05-17 | <48h on NVD disclosure (within SLA) |

## Shipped in v0.3.17 (2026-05-10)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-26030 | [MSRC 2026-05-07](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/) — Microsoft Semantic Kernel **Python SDK** <1.39.4 RCE in `InMemoryVectorStore` filter functionality (CVSS 9.9 CRITICAL); patched in `python-1.39.4` | **AAK-SK-INMEMORY-VECTORSTORE-FILTER-CVE-2026-26030-PIN-001** (NEW: PyPI pin-floor) — companion CVE-2026-25592 (.NET SessionsPythonPlugin file-write) is out of scope, AAK doesn't scan NuGet | 2026-05-10 | <72h on MSRC disclosure (within 48h SLA for the actionable Python SDK arm) |

## Shipped in v0.3.16 (2026-05-09)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-40068 | Anthropic Claude Code 2.1.x folder-trust determination uses git worktree `commondir` without validation; crafted commondir bypasses trust prompt. Vendor patched in 2.1.83 (2026-05-04). Pre-allocated rule-name from v0.3.15 triage of [#181](https://github.com/sattyamjjain/agent-audit-kit/issues/181). | **AAK-CLAUDECODE-CVE-2026-40068-PIN-001** (NEW: pin <2.1.83 on the scoped npm package `@anthropic-ai/claude-code`) — closes the v0.3.15 deferral lane | 2026-05-09 | targeted follow-up: 5 days from v0.3.15 deferral to ship |

## Shipped in v0.3.15 (2026-05-06)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2025-65720 (OX-MCP-2026-05-01 batch, sibling of v0.3.14 DocsGPT row) | [OX Security blog](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/) — `assafelovic/gpt-researcher` MCP STDIO cmd-injection (transport-flip MITM); latest PyPI 0.14.8 (2026-03-13) predates disclosure, no upstream patch as of ship date | **AAK-GPTRESEARCHER-MCP-STDIO-MITM-001** (NEW: PyPI / npm / git pin + `gpt_researcher_transport_flip.py` config detector) — *secondary class coverage* via existing `AAK-MCP-STDIO-CMD-INJ-001` (Python receiver shape) | 2026-05-06 | targeted follow-up: closes Phase 2 row of the OX MCP 2026-05-01 batch (issue [#159](https://github.com/sattyamjjain/agent-audit-kit/issues/159)) |

## Shipped in v0.3.14 (2026-05-05)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| OX-MCP-2026-05-01 (incident class) | [OX Security blog](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/) + [BackBox news](https://news.backbox.org/2026/05/01/200000-mcp-servers-expose-a-command-execution-flaw-that-anthropic-calls-a-feature/) — DocsGPT / GPT-Researcher / Agent-Zero / LettaAI / LiteLLM / LangFlow / Flowise / Bisheng / Langchain-Chatchat MCP-server cluster (transport-flip MITM into stdio cmd-injection class) | **AAK-DOCSGPT-MCP-STDIO-MITM-001** (NEW: product-named pin row + server-config transport-flip detector for DocsGPT) — *secondary class coverage* via existing `AAK-MCP-STDIO-CMD-INJ-001/002/003/004` + `AAK-STDIO-001` (shipped v0.3.6, 2026-04-26) covers GPT-Researcher / Agent-Zero / LettaAI / Flowise / Bisheng / Langchain-Chatchat receiver shapes | 2026-05-05 | <96h on the 2026-05-01 disclosure for the **product-named** row (class coverage was already in place pre-disclosure) |
| CVE-2026-26015 | Same OX writeup — DocsGPT-specific entry in the OX MCP-STDIO family table | **AAK-DOCSGPT-MCP-STDIO-MITM-001** (NEW: pin <0.6.4 on npm/git+https + .mcp.json transport-flip detector) | 2026-05-05 | targeted follow-up: closes the CHANGELOG v0.3.12 carry-list 'OX/BackBox roundup' deferral |

## Shipped in v0.3.13 (2026-05-03)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-7061 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-7061) — Toowiredd/chatgpt-mcp-server <=0.1.0 OS command injection in docker.service.ts (HIGH 7.3); package is GitHub-only, no npm publish, no upstream patch as of ship date | **AAK-CHATGPT-MCP-CVE-2026-7061-PIN-001** (pin-check on git+https / github: shorthand in package.json + companion class detector AAK-MCP-STDIO-CMD-INJ-002) | 2026-05-03 | targeted follow-up: closes the longest-open backlog item |

## Shipped in v0.3.12 (2026-05-03)

> v0.3.11 was tagged but never published — the original tag carried a
> stale `pyproject.toml` so PyPI rejected the duplicate `0.3.10` wheel
> upload. The same content ships as v0.3.12 with a corrected manifest;
> v0.3.11 stays on the tags page as a permanent failed-release marker.

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-7591 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-7591) — TimBroddin/astro-mcp-server <=1.1.1 SQL injection in MCP-tool query construction (no upstream patch as of ship date) | **AAK-ASTROMCP-SQLI-CVE-2026-7591-001** (pin + TS/JS source detector) | 2026-05-03 | <48h on NVD (disclosed 2026-05-01) |
| CVE-2026-30623 | [BerriAI/litellm](https://github.com/BerriAI/litellm/releases) — patched in v1.83.7 (2026-04-30); already class-covered by `AAK-MCP-STDIO-CMD-INJ-001` | **AAK-LITELLM-CVE-2026-30623-PIN-001** (auto-fixable pin floor) | 2026-05-03 | <72h on BerriAI release |

## Shipped in v0.3.8 (2026-04-27)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| Comment-and-Control 2026-04-25 (CVSS 9.4) | [oddguan.com](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/) | **AAK-PRTITLE-IPI-001** | 2026-04-27 | <48h |
| arXiv 2604.20994 (2026-04-23, BFCL FHI) | [arXiv](https://arxiv.org/abs/2604.20994) | **AAK-MCP-FHI-001** | 2026-04-27 | <96h |
| CVE-2026-27825 (CVSS 9.1) | [The Hacker News](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html) | **AAK-MCP-ATLASSIAN-CVE-2026-27825-001** | 2026-04-27 | targeted follow-up 5d |
| CVE-2026-27826 (CVSS 8.2) | The Hacker News (paired with 27825) | **AAK-MCP-ATLASSIAN-CVE-2026-27826-001** | 2026-04-27 | same |
| Wild-IPI corpus 2026-04-24 | [Help Net Security](https://www.helpnetsecurity.com/2026/04/24/indirect-prompt-injection-in-the-wild/) · [Infosec Mag](https://www.infosecurity-magazine.com/news/researchers-10-wild-indirect/) | **AAK-IPI-WILD-CORPUS-001** | 2026-04-27 | <72h |
| CVE-2026-23744 (CVSS 9.8) | [feedly](https://feedly.com/cve/CVE-2026-23744) | **AAK-MCP-INSPECTOR-CVE-2026-23744-001** (vendored fork SAST) | 2026-04-27 | targeted follow-up |

## Shipped in v0.3.7 (2026-04-26)

v0.3.7 was a release-mechanics patch (Dockerfile + global ignore_paths fixes). No new CVE coverage.

## Shipped in v0.3.6 (2026-04-26)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-30615 / 30617 / 30623 / 22252 / 22688 / 33224 / 40933 / 6980 | OX MCP advisory hub (Apr 2026 reframe) | **AAK-MCP-STDIO-CMD-INJ-001/002/003/004** (Python/TS/Java/Rust) | 2026-04-26 | class-coverage release |
| OX-MCP-2026-04-25 + Cloudflare MCP-defender (incidents) | [Cloudflare blog](https://blog.cloudflare.com/), OX MCP hub | **AAK-MCP-MARKETPLACE-CONFIG-FETCH-001** | 2026-04-26 | <24h |
| CVE-2026-32211 (server-side variant) | [DEV — Azure MCP missing-auth](https://dev.to/michael_onyekwere/cve-2026-32211-what-the-azure-mcp-server-flaw-means-for-your-agent-security-14db) | **AAK-AZURE-MCP-NOAUTH-001** | 2026-04-26 | sister to v0.3.5's AAK-AZURE-MCP-001 |
| CVE-2026-33626 | GHSA index — LMDeploy VL SSRF (NVD pending) | **AAK-LMDEPLOY-VL-SSRF-001** | 2026-04-26 | <48h on GHSA |
| CVE-2026-20205 (config variant) | [Splunk SVD-2026-0405](https://advisory.splunk.com/advisories/SVD-2026-0405) | **AAK-SPLUNK-MCP-TOKEN-LEAK-001** | 2026-04-26 | sister to v0.3.4's AAK-SPLUNK-TOKLOG-001 |

## Shipped in v0.3.5 (2026-04-25)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-41481 | [GLAD GHSA-fv5p-p927-qmxr](https://advisories.gitlab.com/pypi/langchain-text-splitters/GHSA-fv5p-p927-qmxr/) — langchain-text-splitters < 1.1.2 SSRF redirect bypass (#61) | **AAK-LANGCHAIN-SSRF-REDIR-001** | 2026-04-25 | <48h |
| CVE-2026-41488 | [GLAD GHSA-r7w7-9xr2-qq2r](https://advisories.gitlab.com/pypi/langchain-openai/GHSA-r7w7-9xr2-qq2r/) — langchain-openai < 1.1.14 TOCTOU / DNS rebinding (#62) | **AAK-SSRF-TOCTOU-001** | 2026-04-25 | <48h |
| CVE-2026-32211 | [DEV — Azure MCP missing-auth](https://dev.to/michael_onyekwere/cve-2026-32211-what-the-azure-mcp-server-flaw-means-for-your-agent-security-14db) — server-side default no-auth | **AAK-AZURE-MCP-001** | 2026-04-25 | targeted follow-up 22d post-disclosure |

## Shipped in v0.3.4 (2026-04-24)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2025-66414 / CVE-2025-66416 | [vulnerablemcp.info](https://vulnerablemcp.info/vuln/cve-2025-66414-66416-dns-rebinding-mcp-sdks.html) — Python MCP SDK DNS-rebinding | **AAK-DNS-REBIND-001** (pattern), **AAK-DNS-REBIND-002** (pin) | 2026-04-24 | <72h (class-level coverage) |
| CVE-2026-35568 | [GitLab advisory](https://advisories.gitlab.com/pkg/maven/io.modelcontextprotocol.sdk/mcp-core/CVE-2026-35568/) — Java `mcp-core` DNS-rebinding | AAK-DNS-REBIND-001 / AAK-DNS-REBIND-002 | 2026-04-24 | <72h |
| CVE-2026-35577 | [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-35577/) — `@apollo/mcp-server < 1.7.0` DNS-rebinding | AAK-DNS-REBIND-001 / AAK-DNS-REBIND-002 | 2026-04-24 | <72h |
| CVE-2026-20205 | [Splunk SVD-2026-0405](https://advisory.splunk.com/advisories/SVD-2026-0405) — splunk-mcp-server token cleartext in `_internal` index | **AAK-SPLUNK-TOKLOG-001** | 2026-04-24 | <72h |
| CVE-2026-40576 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-40576) — excel-mcp-server <= 0.1.7 path traversal (#57) | **AAK-EXCEL-MCP-001** | 2026-04-24 | <72h |
| CVE-2026-40608 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-40608) — next-ai-draw-io < 0.4.15 body-accumulation OOM (#58) | **AAK-NEXT-AI-DRAW-001** | 2026-04-24 | <72h |
| GHA-IMMUTABLE-2026-04 (policy) | [GitHub Blog](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/) | **AAK-GHA-IMMUTABLE-001** | 2026-04-24 | pre-emptive scanner for downstream policy |

Deferred / closed without shipping: CVE-2026-31504 (#59, Linux kernel fanout UAF — out-of-scope for MCP scanner).

## Shipped in v0.3.3 (2026-04-21)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-39313 | [GitLab advisory](https://advisories.gitlab.com/npm/mcp-framework/CVE-2026-39313/) — mcp-framework < 0.2.22 HTTP-body DoS | **AAK-MCPFRAME-001** | 2026-04-21 | 5d (tracking issue → rule) |
| CVE-2025-66335 | [Apache advisory](http://www.mail-archive.com/dev@doris.apache.org/msg11406.html) — apache-doris-mcp-server < 0.6.1 SQL injection | **AAK-DORIS-001** | 2026-04-21 | <48h |
| OX-MCP-2026-04-15 (incident) | [OX Security](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/) · Anthropic declined to CVE | **AAK-ANTHROPIC-SDK-001** (SDK-level), AAK-STDIO-001 (sink-level) | 2026-04-21 | 6d (design-class rule) |

Deferred to v0.3.4 pending NVD resolution (records unresolvable during 2026-04-21 cycle): CVE-2026-6599 (#47), CVE-2026-39861 (#53).

## Shipped in v0.3.2 (2026-04-20)

| CVE / Incident | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-33032 (MCPwn, KEV) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-33032) — nginx-ui, CVSS 9.8 | **AAK-MCPWN-001** (primary) · AAK-MCP-011/012/020 (secondary, retained) | 2026-04-20 | targeted follow-up 4d after PoC |
| CVE-2026-40933 | [GHSA-c9gw-hvqq-f33r](https://github.com/advisories/GHSA-c9gw-hvqq-f33r) — Flowise MCP adapter, CVSS 10.0 | AAK-FLOWISE-001 (primary) · AAK-STDIO-001 (architectural class) | 2026-04-20 | <48h |
| VERCEL-2026-04-19 (incident) | [Vercel bulletin](https://vercel.com/kb/bulletin/vercel-april-2026-security-incident) | AAK-OAUTH-SCOPE-001, AAK-OAUTH-3P-001 | 2026-04-20 | <24h |
| MCPWN-2026-04-16 (incident) | [Rapid7 ETR](https://www.rapid7.com/blog/post/etr-cve-2026-33032-nginx-ui-missing-mcp-authentication/) | AAK-MCPWN-001 | 2026-04-20 | 4d (targeted) |

## Shipped in v0.3.1 (2026-04-19)

| CVE | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2026-30615 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-30615) (Windsurf, CVSS 8.0) | AAK-STDIO-001, AAK-WINDSURF-001 | 2026-04-19 | <48h |
| CVE-2026-35402 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-35402) (mcp-neo4j-cypher, CVSS 2.3) | AAK-NEO4J-001 | 2026-04-19 | <48h |
| CVE-2026-35603 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-35603) (Claude Code Windows, CVSS 5.4) | AAK-CLAUDE-WIN-001 | 2026-04-19 | <48h |
| CVE-2026-6494  | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-6494)  (AAP MCP log injection, CVSS 5.3) | AAK-LOGINJ-001 | 2026-04-19 | <48h |

### Ox Security architectural class (Apr 16 2026 disclosure)

AAK-STDIO-001 closes this whole family with a single AST-based
detection in `scanners/stdio_injection.py`:

| CVE | Product |
|---|---|
| CVE-2025-65720 | GPT Researcher |
| CVE-2026-26015 | DocsGPT |
| CVE-2026-30615 | Windsurf |
| CVE-2026-30617 | Langchain-Chatchat |
| CVE-2026-30618 | Fay Framework |
| CVE-2026-30623 | LiteLLM |
| CVE-2026-30624 | Agent Zero |
| CVE-2026-30625 | Upsonic |
| CVE-2026-33224 | Bisheng / Jaaz |

Source: <https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/>

## Shipped in v0.3.0

| CVE | Advisory | AAK rule(s) | Shipped | Latency |
|---|---|---|---|---|
| CVE-2025-59536 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-59536) | AAK-HOOK-RCE-001, AAK-HOOK-RCE-002, AAK-HOOK-RCE-003 | 2026-04-18 | retroactive |
| CVE-2026-33032 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-33032) | AAK-MCP-011, AAK-MCP-012, AAK-MCP-020 | 2026-04-18 | retroactive |
| CVE-2026-34070 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-34070) | AAK-LANGCHAIN-001, AAK-LANGCHAIN-002 | 2026-04-18 | retroactive |
| CVE-2025-68664 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-68664) | AAK-LANGCHAIN-003 | 2026-04-18 | retroactive |

## Open (48h SLA ticking)

_none — file response-tracking issues get posted here when the SLA fires._
