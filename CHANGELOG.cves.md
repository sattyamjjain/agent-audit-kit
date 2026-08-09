# AAK CVE-to-Rule Ledger

We triage newly disclosed MCP CVEs continuously and ship rule coverage as fast
as we responsibly can — no fixed public deadline (see `ROADMAP_2026.md §2.3`).
This file is the audit trail of what shipped and when.

Format: one line per CVE, `CVE-YYYY-NNNNN` → `AAK-XXX-NNN` with the
shipped-at timestamp. The GitHub Action `.github/workflows/cve-watcher.yml`
diffs NVD's MCP keyword feed against this file and opens a `cve-response`
issue for anything new; the release gate blocks a tag while any such issue is
open.

> **On the "48h" figures below:** AgentAuditKit does not commit to a 48-hour (or
> any fixed) CVE-response SLA — that public commitment was retired in PR #432.
> The `sla-48h` label is likewise retired and should be removed from any open
> issue. The per-CVE latency figures in the tables are **measurements recorded at
> the time**, kept as dated facts, not a standing promise.

## 2026-08-09 (unreleased)

Three `cve-response` issues filed the same day (all MEDIUM CVSS 5.3), adjudicated on
their merits against the npm registry rather than by repeating the prior batch's
disposition. One is in scope and shipped a pin; two are unpinnable. Each was read from
NVD and verified against the registry before deciding.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-19337 (adenot `@adenot/mcp-google-search` <= 0.3.1, SSRF via the `url` argument of `read_webpage` in `src/index.ts`; local) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19337) | **In scope.** Added `AAK-MCP-GOOGLESEARCH-CVE-2026-19337-001` (SUPPLY_CHAIN, MEDIUM). The scoped npm package resolves on the registry (versions 0.1.0 through 0.3.1); the unscoped `mcp-google-search` is a different package and is not pinned. No fixed release exists yet (upstream patch `f071d491` unreleased), so the pin is presence-only and fires on any installed version, with remediation to remove or replace until a patched version ships. Same shape as the astrbot MCP-test-endpoint SSRF pin. (#558) | 2026-08-09 |
| CVE-2026-19329 (andreahaku `codex_mcp`, command injection via `model` in `src/codex-process-simple.ts`; local) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19329) | **Out of scope, unpinnable.** `codex_mcp` and `@andreahaku/codex-mcp` both 404 on npm; the advisory states the project does not use versioning (git-hash artifact only). The only `codex-mcp` on npm is an unrelated author's package, so a name pin would false-positive it. No fix floor and no resolvable artifact to pin. (#556) | 2026-08-09 |
| CVE-2026-19332 (NellyW8 `MCP4EDA` 1.0.0, command injection via `design_name`/`vcd_file` in `run_openlane`/`view_waveform`; local) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19332) | **Out of scope, unpinnable.** `mcp4eda` and `@nellyw8/mcp4eda` both 404 on npm; a GitHub-only project with no registry artifact to pin. (#557) | 2026-08-09 |

## 2026-08-08 (later batch, unreleased)

Four more `cve-response` issues filed the same day, all adjudicated **out of scope**:
each is a rolling-release or unpatched GitHub project with **no fixed version** to pin to
(fix PRs unaccepted or maintainers unresponsive), and three of the four are local-only.
A version pin needs a fix floor to tell users what to upgrade to; there is none here, so
there is nothing for the pin scanner to key on. Each was read from NVD, not the title.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-19263 (INQUIRELAB `mcp-bridge-api` — command injection via `command`/`args` in `mcp-bridge.js`; remote; HIGH CVSS 7.3) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19263) | **Out of scope** — rolling release with no version details for affected or fixed releases, and the fix PR "awaits acceptance", so there is no fix floor to pin. Not distributed under a resolvable pinnable name. Same basis as the ssh-mcp-server / MissionSquad dispositions. (#551) | 2026-08-08 |
| CVE-2026-19268 (abdullah1854 `MCPGateway` — command injection via the `since` arg in `claude-usage.ts`; remote, exploit public; MEDIUM CVSS 6.3) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19268) | **Out of scope** — rolling release, "no version details of affected nor updated releases", maintainer unresponsive; a GitHub project with no fixed version to pin. (#552) | 2026-08-08 |
| CVE-2026-19270 (Hulupeep `mcp-ui-probe` ≤ 0.2.0 — path traversal via `journeyId`/`filename` in `JourneyStorage.ts`; local; MEDIUM CVSS 5.3) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19270) | **Out of scope** — the project was informed but has not responded and has shipped no fix, so there is no fix floor to upgrade to; local-only attack. (#553) | 2026-08-08 |
| CVE-2026-19279 (MIMICLab `mcp-pdf-vision` 1.1.0 — command injection via `pdfPath`/`sessionId` in `src/index.ts`; local; MEDIUM CVSS 5.3) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19279) | **Out of scope** — informed but unpatched (no fixed version to pin), and the attack is local-only. (#554) | 2026-08-08 |

## 2026-08-08 (unreleased)

Three `cve-response` issues filed after the 2026-08-06 batch, adjudicated for the same
(still-unreleased) cut: two new PyPI pins and one out of scope. Each row quotes a
verbatim excerpt of the NVD description; each was read from NVD, not the issue title.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-48039 (`meta-ads-mcp` < 1.0.109 — `AuthInjectionMiddleware` forwards unauthenticated requests without a 401, and a failed Graph API call serialises the request URL, including the `access_token`, into the response → unauthenticated tool invocation + credential leak; CRITICAL CVSS 9.1) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48039) | **Pinned** `AAK-METAADS-CVE-2026-48039-001` — fix floor 1.0.109. A pinnable PyPI artifact (latest 1.0.119) the pin scanner resolves from `requirements.txt`/`pyproject.toml`/`uv.lock`/`.mcp.json`. Tests `test_metaads_below_floor_fires` / `test_metaads_patched_passes`. NVD verbatim: *"AuthInjectionMiddleware.dispatch() at http_auth_integration.py:272 unconditionally forwards unauthenticated Streamable HTTP requests to downstream MCP tool handlers without issuing a 401 response ... when the downstream Meta Graph API call fails, api.py:263-269 serialises the raw httpx request URL—including the operator's access_token as a query parameter—into the JSON-RPC response body, delivering the credential to the unauthenticated caller."* (#549) | 2026-08-08 |
| CVE-2026-71433 (`langgraph-checkpoint-postgres` / `langgraph-checkpoint-sqlite` < 3.1.1 — namespaces stored as a dot-joined string and read by simple prefix match, so a scoped read spills into a sibling namespace → cross-tenant checkpoint leak; MEDIUM CVSS 5.3) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-71433) | **Pinned** `AAK-MCP-LANGGRAPH-CHECKPOINT-CVE-2026-71433-001` — fix floor 3.1.1, matching either PyPI name; the Postgres/SQLite sibling of the langgraph-checkpoint-mongodb leak (CVE-2026-48121). Tests `test_langgraph_checkpoint_postgres_below_floor_fires` / `_sqlite_below_floor_fires` / `_patched_passes`. NVD verbatim: *"persisted hierarchical namespaces as a dot joined string and scoped reads by matching that string as a simple prefix pattern, so a read scoped to one namespace could also match a sibling namespace ... allowing an authenticated caller to retrieve stored items belonging to another tenant or user through an ordinary scoped search or list namespaces call, with no crafted input required."* (#548) | 2026-08-08 |
| CVE-2026-19244 (HKUDS `nanobot` ≤ 0.2.1 — MCP resource/prompt wrappers registered outside the intended `enabledTools` scope → improper access control; MEDIUM CVSS 4.7) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19244) | **Out of scope** — the affected project is HKUDS `nanobot` (a GitHub-hosted MCP agent framework; upgrade to 0.3.0), but the PyPI `nanobot` is an unrelated "minimalist robot navigation framework" with no 0.2.1/0.3.0 releases, so there is no distributable the version-pin scanner can match under a resolvable name. Same basis as the MissionSquad mcp-api dispositions. NVD verbatim: *"MCP resource and prompt wrappers could be registered outside the intended enabledTools scope. The registration boundary was corrected."* (#550) | 2026-08-08 |

## 2026-08-06 (unreleased)

Eleven `cve-response` issues adjudicated: two new pins (`awslabs.documentdb-mcp-server`
and `frontmcp`, both verified as real distributables), six folded into existing pins
(five Langflow CVEs into the `langflow` pin whose 1.11.0 floor already exceeds every
affected version, and one PraisonAI CVE into the `praisonai` pin whose 4.6.78 floor
already exceeds its 4.6.40 fix), and three out of scope. Each row quotes a verbatim
excerpt of the NVD description; each was read from NVD, not the issue title.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-18954 (`awslabs.documentdb-mcp-server` < 1.0.12 — write-capable aggregation-pipeline stages bypass read-only-mode enforcement → unauthorized writes; MEDIUM CVSS 5.5) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-18954) | **Pinned** `AAK-MCP-DOCUMENTDB-CVE-2026-18954-001` — fix floor 1.0.12; the fifth pin in the `awslabs.*-mcp-server` family. A pinnable PyPI artifact (latest 1.0.14) the pin scanner resolves from `requirements.txt`/`pyproject.toml`/`uv.lock`/`.mcp.json`. Tests `test_documentdb_below_floor_fires` / `test_documentdb_patched_passes`. NVD verbatim: *"Incorrect authorization in the aggregation pipeline tool in Amazon AWS Labs DocumentDB MCP Server before 1.0.12 might allow an authenticated MCP client to perform inappropriate write operations on the connected database via write-capable aggregation pipeline stages that bypass the read-only mode enforcement logic."* (#543) | 2026-08-06 |
| CVE-2026-67531 (`frontmcp` < 1.5.7 — the sandboxed `codecall:execute` tool reaches the host Zod schema's Function constructor and runs arbitrary code as the server user; unauthenticated in the default public auth mode; NVD CVSS n/a) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-67531) | **Pinned** `AAK-MCP-FRONTMCP-CVE-2026-67531-001` — fix floor 1.5.7. A pinnable npm artifact (latest 1.6.0) the pin scanner resolves from `package.json`/lockfiles/`.mcp.json`. Tests `test_frontmcp_below_floor_fires` / `test_frontmcp_patched_passes`. NVD verbatim: *"the sandboxed codecall:execute tool exposes live host Zod schema instances to the script via getTool(), and because Zod v4 defines _zod as a non-configurable, non-writable own property, the ECMAScript Proxy invariants force the security membrane to hand back the raw host object, letting a script reach _zod.constr.constructor (the host Function constructor) and execute arbitrary code in the server process."* (#544) | 2026-08-06 |
| CVE-2026-17623 (IBM Langflow OSS 1.0.0–1.10.3 — command-field RCE in MCP server configurations; HIGH 8.8) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-17623) | **Class-covered** by `AAK-MCP-LANGFLOW-CVE-2026-12940-001` — floor already `langflow` 1.11.0, which exceeds the 1.10.3 top of the affected range; CVE added to `cve_references`, no new rule and no floor change. NVD verbatim: *"IBM Langflow OSS 1.0.0 through 1.10.3 could allow a remote authenticated attacker to execute arbitrary commands due to improper validation of the command field in MCP server configurations."* (#537) | 2026-08-06 |
| CVE-2026-17626 (IBM Langflow OSS 1.0.0–1.10.3 — host file read/modify via unfiltered Docker volume-mount / device-mapping args; HIGH 8.8) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-17626) | **Class-covered** by the `langflow` pin (floor 1.11.0 > 1.10.3); CVE added to `cve_references`. NVD verbatim: *"could allow an authenticated attacker to read, modify, or expose sensitive host files via Docker-based MCP servers due to incomplete filtering of dangerous Docker volume-mount and device-mapping arguments."* (#538) | 2026-08-06 |
| CVE-2026-8446 (IBM Langflow OSS 1.0.0–1.10.3 — MCP composer OAuth authentication bypass when `mcp_composer_enabled=true`; HIGH 7.5) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-8446) | **Class-covered** by the `langflow` pin (floor 1.11.0 > 1.10.3); CVE added to `cve_references`. NVD verbatim: *"contain an authentication bypass vulnerability in the Model Context Protocol (MCP) composer endpoint when mcp_composer_enabled=true (default) and projects are configured with auth_type=oauth."* (#540) | 2026-08-06 |
| CVE-2026-9077 (IBM Langflow OSS 1.0.0–1.10.3 — bypass localhost-only restriction to write arbitrary MCP server configs into host IDE config files; HIGH 8.5) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-9077) | **Class-covered** by the `langflow` pin (floor 1.11.0 > 1.10.3); CVE added to `cve_references`. Thematically adjacent to this release's `.vscode/tasks.json` work (writing to IDE config) but the vulnerable component is `langflow` itself, remediated by the version pin. NVD verbatim: *"allows remote authenticated attackers to bypass localhost-only restrictions and write arbitrary MCP server configurations to IDE configuration files on the host system."* (#541) | 2026-08-06 |
| CVE-2026-7646 (IBM Langflow OSS 1.0.0–1.10.3 — `resources/read` path traversal reads the JWT secret, SQLite DB, and process env; MEDIUM 6.5) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-7646) | **Class-covered** by the `langflow` pin (floor 1.11.0 > 1.10.3); CVE added to `cve_references`. NVD verbatim: *"allows users to read arbitrary files from the server filesystem ... by sending a crafted MCP `resources/read` request with a URL-encoded path traversal sequence in the filename."* (#539) | 2026-08-06 |
| CVE-2026-48168 (PraisonAI < 4.6.40 — command injection in the bundled Claude GitHub Actions workflow via an unquoted attacker-controlled PR branch name; any `@claude` comment triggers it; CRITICAL CVSS 10) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48168) | **Class-covered** by `AAK-MCP-PRAISONAI-CVE-2026-61427-001` — floor already `praisonai` 4.6.78, which exceeds the 4.6.40 fix; CVE added to `cve_references`, no floor change. NVD verbatim: *"the bundled Claude GitHub Actions workflow is vulnerable to command injection because it embeds an attacker-controlled pull request branch name into a Bash run: block without quoting or validation. Additionally, the workflow allows any @claude comment to trigger the job regardless of whether the commenter is a trusted collaborator."* (#542) | 2026-08-06 |
| CVE-2026-19039 (Kino-Kafkaesque `ssh-mcp-server` — command injection via host/username in `ssh_exec`; MEDIUM CVSS 5.3) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19039) | **Out of scope** — a rolling-release GitHub project with no pinnable version and no fix version ("version details for affected or updated releases cannot be specified"), the CVE is disputed ("the actual existence of this vulnerability is currently in question"), and the maintainer's stated threat model is a local/trusted tool where the caller already has shell execution. Not resolvable from a client manifest. NVD verbatim: *"The intended threat model is that this MCP server is a local/trusted tool for an agent to execute commands over SSH, so callers already have meaningful execution capability through the exposed shell."* (#545) | 2026-08-06 |
| CVE-2026-19040 (MissionSquad `mcp-api` ≤ 1.11.9 — SSRF in `dcrClients.ts`; MEDIUM CVSS 6.3) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19040) | **Out of scope** — the affected component is a GitHub-hosted project versioned in its own repo (patch commit `f068ab4`), not a PyPI/npm distributable the pin scanner reads; the npm name `mcp-api` is an unrelated 0.0.1 placeholder (no repository, no 1.11.x), and MissionSquad-scoped names do not resolve. No pinnable artifact. Same basis as prior GitHub-release-only dispositions. Upgrade to 1.11.10. (#546) | 2026-08-06 |
| CVE-2026-19041 (MissionSquad `mcp-api` ≤ 1.11.8 — command injection in the NPM package version handler `installPackage`; MEDIUM CVSS 6.3) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19041) | **Out of scope** — same MissionSquad `mcp-api` GitHub project (patch commit `a40f54d`); not distributed on npm/PyPI under a resolvable name, so nothing for the version-pin scanner to match. Upgrade to 1.11.9. (#547) | 2026-08-06 |

## 2026-08-05 (unreleased)

Three `cve-response` issues adjudicated: one new pin (`@langchain/langgraph-checkpoint-mongodb`,
an npm artifact), and two Flowise CVEs folded into the existing `AAK-FLOWISE-001`
rule whose floor was already 3.1.3 — no new rule and no floor change for those two.
Each row quotes a verbatim excerpt of the NVD description; each was read from NVD,
not the issue title.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-48121 (`@langchain/langgraph-checkpoint-mongodb` ≤ 1.3.0 — checkpoint identifiers from `config.configurable` reach `MongoDBSaver.getTuple()` `find()` queries without type enforcement → NoSQL `$gt`/`$ne` operator injection leaks checkpoints across tenants; MEDIUM CVSS 6.7) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48121) | **Pinned** `AAK-MCP-LANGGRAPH-MONGO-CVE-2026-48121-001` — fix floor `@langchain/langgraph-checkpoint-mongodb` 1.3.1. A pinnable npm artifact the pin scanner resolves from `package.json`/`package-lock.json`/`pnpm-lock.yaml`/`.mcp.json`. Regression tests `test_langgraph_mongo_below_floor_fires` / `test_langgraph_mongo_patched_passes`. NVD verbatim: *"Versions 1.3.0 and below are vulnerable to NoSQL injection: checkpoint identifiers (thread_id, checkpoint_ns, checkpoint_id) from config.configurable are passed into MongoDB find() queries in MongoDBSaver.getTuple() without type enforcement. If an attacker supplies an object payload (such as MongoDB operators $gt or $ne) instead of a string, it can be interpreted as a query operator, bypassing thread scoping and leaking checkpoints, including pending writes, across tenants."* (#535) | 2026-08-05 |
| CVE-2026-69263 (Flowise < 3.1.3 — the CVE-2025-8943 mitigation denied `-y`/`--yes` on `npx` and blocked env vars by exact name, but `npm_config_yes=true` reproduces `--yes` via npm's `npm_config_*` config channel, so a Custom MCP server still auto-installs and executes the named package; NVD CVSS n/a) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69263) | **Class-covered** by the existing `AAK-FLOWISE-001` rule — floor already `flowise` 3.1.3 (`_FLOWISE_PATCHED_VERSION`), fixed in the same release, CVE added to the rule's `cve_references`; no separate rule and no floor change. NVD verbatim: *"the mitigation for CVE-2025-8943 blocked -y and --yes flags on npx, but packages/components/nodes/tools/MCP/core.ts denied only PATH, LD_LIBRARY_PATH, DYLD_LIBRARY_PATH, and NODE_OPTIONS by exact environment-variable name. Because npm reads configuration from npm_config_* variables, setting npm_config_yes=true reproduced --yes behavior without using a blocked flag, causing npx to auto-install and execute the named package when a Custom MCP server launched."* (#534) | 2026-08-05 |
| CVE-2026-69257 (Flowise < 3.1.3 — `httpSecurity.ts` does not normalise IPv4-mapped IPv6 (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`) before the deny-list check, so `isDeniedIP()` skips the IPv4 CIDR checks and the MCP-tool / HTTP-Node path can reach loopback, internal services, or cloud-metadata endpoints via a crafted AAAA record; NVD CVSS n/a) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69257) | **Class-covered** by the existing `AAK-FLOWISE-001` rule — floor already `flowise` 3.1.3, fixed in the same release, CVE added to the rule's `cve_references`; no separate rule and no floor change. NVD verbatim: *"Flowise's HTTP security module httpSecurity.ts did not normalize IPv4-mapped IPv6 addresses such as ::ffff:127.0.0.1 and ::ffff:169.254.169.254 before checking them against the deny list. Because ipaddr.js reports these addresses as ipv6 while IPv4 CIDR deny-list entries are ipv4, isDeniedIP() skipped the IPv4 CIDR checks."* (#533) | 2026-08-05 |

## 2026-08-04 (unreleased)

Two `cve-response` issues adjudicated: one pinned (fourth `awslabs.*-mcp-server`
family pin), one out of scope. Each row quotes a verbatim 3-line excerpt of the NVD
description; each was read from NVD, not the issue title.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-18655 (`awslabs.amazon-mq-mcp-server` < 2.0.24 — broker-hostname SSRF exfiltrates broker credentials / OAuth tokens; CVSS 4.0 7.1 HIGH / 3.1 6.5 MEDIUM) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-18655) | **Pinned** `AAK-MCP-AMAZONMQ-CVE-2026-18655-001` — fix floor `awslabs.amazon-mq-mcp-server` 2.0.24; the fourth pin in the existing `awslabs.*-mcp-server` family. A pinnable PyPI artifact (latest 2.0.24) the pin scanner resolves from `requirements.txt`/`pyproject.toml`/`uv.lock`/`.mcp.json`. Regression test `test_amazon_mq_below_floor_fires`. NVD verbatim: *"Improper restriction of intended endpoints in the RabbitMQ broker connection tools of the Amazon MQ MCP Server (awslabs.amazon-mq-mcp-server) before 2.0.24 may allow a remote unauthenticated actor (via prompt injection) to obtain Amazon MQ for RabbitMQ broker credentials or OAuth access tokens sent to a crafted endpoint controlled through a broker hostname introduced in the MCP client context."* (#530) | 2026-08-04 |
| CVE-2026-66065 (Ouroboros AI-agent runtime < 0.42.1 — incomplete dangerous-env-var denylist reaches RCE via an auto-loaded `.env`. The issue title says "CVSS n/a" but NVD scores it CVSS 4.0 8.4 HIGH; trusting NVD.) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-66065) | **Out of scope** — the vulnerable "Ouroboros" runtime is distributed via GitHub releases, not a PyPI/npm artifact the pin detector reads (PyPI `ouroboros` 404s; the npm `ouroboros` is an unrelated pure-Python package at 3.4.0), and the incomplete denylist is a version-specific bug in the runtime's own source. The `.env`-auto-load-to-RCE class is adjacent to `AAK-SKILL-UNTRUSTED-EXEC-PATH` and the langflow env-injection pin, but neither pins Ouroboros. Upgrade to ≥ 0.42.1. NVD verbatim: *"Versions prior to 0.42.1 have an incomplete denylist. Several execution-routing keys of the same RCE class were omitted, so a malicious cloned repo can still reach arbitrary command execution by shipping a .env (auto-loaded at import, with no review step)."* (#531) | 2026-08-04 |

## 2026-08-03 (v0.3.67)

Two `cve-response` issues adjudicated for the v0.3.67 cut — both the same upstream
(ArcadeDB < 26.7.3, vendor ArcadeData), both out of scope. No new rule. Each was
verified against the NVD record (not the issue title) before a verdict.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-68578 (ArcadeDB < 26.7.3 — the MCP HTTP transport fails to bind the authenticated principal, so all engine permission checks silently pass as no-ops → authorization bypass; HIGH 7.5) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-68578) | **Out of scope** — ArcadeDB is a Java multi-model database distributed as a JAR / Docker image, not a PyPI/npm artifact the pin detector reads (no Maven/Gradle/`go.mod` in its candidate set), and the auth-principal-binding failure is a server-side runtime property with no config-detectable signature. Same basis as SiYuan CVE-2026-66012 (#499). Upgrade to ≥ 26.7.3; the reachable exposed / unauthenticated remote MCP endpoint posture is flagged by `AAK-MCP-001`. (#528) | 2026-08-03 |
| CVE-2026-67357 (ArcadeDB < 26.7.3 — the MCP `get_server_settings` tool leaks `arcadedb.ha.clusterToken` in cleartext → information disclosure; HIGH 7.5) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-67357) | **Out of scope** — same Java/Docker ecosystem the pin detector does not read, and a server-side information disclosure through an MCP tool response, not a version pinned in a client config. Upgrade to ≥ 26.7.3. (#527) | 2026-08-03 |

## 2026-08-02 (v0.3.66)

Three `cve-response` issues adjudicated for the v0.3.66 cut — one out of scope, and
two `better-auth` CVEs folded into the existing `better-auth` pin (its floor raised
1.6.11 → 1.6.13). No new rule. Each was verified against the NVD record (not the
issue title) before a verdict.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-15988 (AI Engine – The Chatbot, AI Framework & MCP for WordPress plugin ≤ 3.6.5 — CSRF via missing/incorrect nonce validation on `reauth_for_authorize`; HIGH 8.8) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-15988) | **Out of scope** — a WordPress/PHP plugin, an ecosystem the pin detector does not read (no PyPI/npm artifact, no version in a client `.mcp.json`/manifest), and a server-side CSRF on a web endpoint with no config-detectable signature. Same basis as the prior WordPress-plugin dispositions (CVE-2026-15015 #490, CVE-2026-9810). Upgrade the plugin to ≥ 3.6.6. (#523) | 2026-08-02 |
| CVE-2026-67333 (`better-auth` < 1.6.13 — the deprecated `oidc-provider` and `mcp` plugins do not validate the scheme of registered `redirect_uris`, so a `javascript:` redirect URI executes in the authorization-server origin → session theft / account takeover; HIGH 7.2 / CVSS 4.0 5.1) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-67333) | **Pinned** — folded into the existing `AAK-MCP-BETTERAUTH-CVE-2026-53512-001` pin, whose floor is **raised 1.6.11 → 1.6.13** (1.6.11/1.6.12 fixed the earlier flaws but are still exposed to this one) and CVE added to `cve_references`; regression test `test_betterauth_1612_fires_for_67333`. The 1.7.0-beta.0–beta.3 pre-release gap (fixed 1.7.0-beta.4) is outside the stable version-tuple pin's scope. (#524) | 2026-08-02 |
| CVE-2026-67336 (`better-auth` < 1.6.11 — insecure cryptographic defaults in the `oidcProvider` and `mcp` plugins advertise the `none` algorithm and accept plain PKCE by default; CRITICAL CVSS 4.0 9.4 / HIGH 8.7) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-67336) | **Class-covered** by the existing `AAK-MCP-BETTERAUTH-CVE-2026-53512-001` pin — fixed 1.6.11, already ⊆ the raised 1.6.13 floor; CVE added to the rule's `cve_references`. No separate rule. (#525) | 2026-08-02 |

## 2026-08-01 (v0.3.65)

One `cve-response` issue adjudicated for the v0.3.65 cut — filed by the NVD watcher
while the release was being tagged, and pinned (not deferred) so the release gate
stayed honest. Verified against the NVD record before a verdict.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-54785 (gemini-bridge `1.0.0`–`1.3.0` — `consult_gemini_with_files` inline mode reads any file path in the `files` argument without confining it to the working directory, then forwards the contents to the Gemini CLI → path-traversal file exfiltration; MEDIUM 6.2) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-54785) | **Pinned** `AAK-MCP-GEMINIBRIDGE-CVE-2026-54785-001` — fix floor `gemini-bridge` 1.3.1, `introduced` 1.0.0. The PyPI `gemini-bridge` (versions 1.0.0–1.3.1) is the artifact the CVE range matches and is resolvable from `requirements.txt`/`pyproject.toml`/`uv.lock`; the npm `gemini-bridge` (0.1.x) is an unrelated package below the affected range. (#519) | 2026-08-01 |

## 2026-07-31 (v0.3.64)

Six `cve-response` issues adjudicated for the v0.3.64 cut — one new pin
(`langflow`, a PyPI artifact) and five dispositioned out of scope. The five disposed
CVEs are one upstream: Google `mcp-toolbox` (`googleapis/genai-toolbox`), a **Go
binary** the client-config / dependency-manifest pin scanner does not read (its
candidate set is PyPI/npm manifests, lockfiles, and MCP config files; no `go.mod`),
plus server-side runtime flaws invisible to a static client scan — the same basis on
which CVE-2026-15829 (also `mcp-toolbox`) was dispositioned. Each CVE was verified
against the NVD record (not the issue title) before a verdict.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-12940 (IBM Langflow OSS `langflow` 1.0.0–1.10.1 — the MCP stdio launcher's `DANGEROUS_ENV_VARS` blocklist (`src/lfx/base/mcp/util.py`) omits `SHELLOPTS`/`BASHOPTS`/`PS4` → unauthenticated env-var-injection RCE; CRITICAL 9.8) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-12940) · GHSA-gx45-8jc3-gqqr | **Pinned** `AAK-MCP-LANGFLOW-CVE-2026-12940-001` — fix floor `langflow` 1.11.0, `introduced` 1.0.0 (1.11.0 is the first PyPI release after the affected 1.10.1; there is no 1.10.2, and pre-1.0.0 predates the MCP stdio launcher). A pinnable PyPI artifact the pin scanner resolves from `requirements.txt`/`pyproject.toml`/`uv.lock`. (#513) | 2026-07-31 |
| CVE-2026-14537 (Google `mcp-toolbox` v1.3.0/v1.4.0 — incorrect authorization on the direct HTTP API tool-invocation endpoint when `--enable-api` is active → an unauthenticated attacker invokes `scopeRequired`-protected tools via legacy HTTP endpoints; HIGH CVSS 4.0 8.1) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-14537) | **Out of scope** — `mcp-toolbox` is a Go binary (`googleapis/genai-toolbox`), not a PyPI/npm artifact the pin scanner keys on (no `go.mod` in its candidate set), and the authz bypass is a server-side runtime property; same basis as CVE-2026-15829. The reachable posture — an exposed MCP HTTP endpoint — is flagged by `AAK-MCP-001`. Upgrade past the affected releases. (#514) | 2026-07-31 |
| CVE-2026-14538 (Google `mcp-toolbox` 0.16.1–1.4.0 — a fail-open logic error in the `bigquery-execute-sql` dry-run enforcement lets an authenticated user bypass `allowedDatasets` validation and read excluded/federated schemas; MEDIUM CVSS 4.0 5.7) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-14538) | **Out of scope** — Go binary (`googleapis/genai-toolbox`), not pinnable, and a server-side data-authorization bug invisible to a static client-config scan. Upgrade past the affected range. (#515) | 2026-07-31 |
| CVE-2026-14539 (Google `mcp-toolbox` ≤ 1.4.0 — the `/mcp` HTTP handler reads request bodies into memory with no size limit → unauthenticated memory-exhaustion DoS; MEDIUM CVSS 4.0 6.6) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-14539) | **Out of scope** — Go binary, not pinnable (no `go.mod` surface), and a transport-internal resource-exhaustion DoS with no client-config signal. Reachable posture at most is the exposed endpoint (`AAK-MCP-001`). Upgrade past 1.4.0. (#516) | 2026-07-31 |
| CVE-2026-14540 (Google `mcp-toolbox` 0.3.0–1.4.0 — the generic HTTP source/tool client lacks redirect validation and private-IP checks → SSRF via open redirect; HIGH CVSS 4.0 8.0) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-14540) | **Out of scope** — Go binary (`googleapis/genai-toolbox`), not pinnable. The caller-URL→fetch-without-allow-list SSRF class is what `AAK-MCP-SSRF-001` covers on AAK's client-scan side. Upgrade past the affected range. (#517) | 2026-07-31 |
| CVE-2026-14541 (Google `mcp-toolbox` 1.4.0 — the Google OAuth provider skips audience validation for opaque tokens when `mcpEnabled: true` but no audience/clientId is configured → auth bypass / audience confusion; HIGH CVSS 4.0 8.0) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-14541) | **Out of scope** — Go binary, not pinnable, and a server-side OAuth-validation flaw. The audience-confusion / missing-resource-binding class is `AAK-OAUTH-007`'s territory (RFC 8707 resource indicators) on the client side. Upgrade past 1.4.0. (#518) | 2026-07-31 |

## 2026-07-30 (v0.3.63)

Six `cve-response` issues adjudicated for the v0.3.63 cut — one new pin
(`flyto-core`, a PyPI artifact) and five dispositioned out of scope. The five
disposed CVEs are one upstream: the official MCP Ruby SDK (`mcp` gem, vendor
`modelcontextprotocol`) before 0.23.0 — a RubyGems ecosystem the client-config /
dependency-manifest pin scanner does not read (its candidate set is PyPI/npm
manifests, lockfiles, and MCP config files; no `Gemfile`/`Gemfile.lock`), plus
server-side transport internals invisible to a static client scan. Their shared
remediation: upgrade the `mcp` gem to ≥ 0.23.0. Each CVE was verified against the
NVD record (not the issue title) before a verdict.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-67425 (Flyto2 Core `flyto-core` < 2.26.6 — `llm.chat` reads provider keys (`OPENAI_API_KEY`/`ANTHROPIC_API_KEY`) from the environment and forwards them in the `Authorization: Bearer` header to a caller-controlled `base_url` that clears the SSRF guard → operator provider-key exfiltration; HIGH 8.6) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-67425) | **Pinned** `AAK-MCP-FLYTO-CVE-2026-67425-001` — fix floor `flyto-core` 2.26.6 (all prior versions affected; no `introduced` bound). `flyto-core` is a pinnable PyPI artifact the pin scanner resolves from `pyproject.toml`/`requirements.txt`/`uv.lock` (same basis as the `awslabs.aws-api-mcp-server` PyPI pin). The env-var-key exfil-to-caller-controlled-`base_url` class is adjacent to the config-side env-secret exfil surface `AAK-MCP-ENV-PLACEHOLDER-EXFIL-001` (`tests/test_mcp_env_placeholder_exfil.py`). (#507) | 2026-07-30 |
| CVE-2026-67432 (MCP Ruby SDK / `mcp` gem < 0.23.0 — `StreamableHTTPTransport` parses an unbounded JSON-RPC POST body → unauthenticated remote memory-exhaustion DoS; HIGH 7.5) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-67432) | **Out of scope** — RubyGems artifact + server-side transport-internal resource exhaustion; a gem version is invisible to the pin scanner (no `Gemfile`/`Gemfile.lock` in its candidate set) and an unbounded-body DoS leaves no client-config signal. Upgrade the `mcp` gem to ≥ 0.23.0; the reachable posture at most is the exposed remote endpoint (`AAK-MCP-001`). (#512) | 2026-07-30 |
| CVE-2026-67431 (MCP Ruby SDK / `mcp` gem < 0.23.0 — `StreamableHTTPTransport` does not bind a session ID to a session owner → an attacker with a stolen session ID runs `tools/call` in the victim's session; HIGH CVSS 4.0 8.3) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-67431) | **Out of scope** — RubyGems + server-side session-authorization internals, invisible to a static client-config/manifest scan (no `Gemfile` in the pin surface). Upgrade to ≥ 0.23.0. The reachable posture — an unauthenticated/hijackable remote MCP endpoint — is flagged by `AAK-MCP-001`. (#511) | 2026-07-30 |
| CVE-2026-63118 (MCP Ruby SDK / `mcp` gem < 0.23.0 — `StreamableHTTPTransport` does not validate the HTTP `Host`/`Origin` headers → a malicious browser page uses DNS rebinding to reach a locally running MCP server and invoke tools; MEDIUM CVSS 4.0 6.9) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-63118) | **Out of scope** — RubyGems + server-side transport internals not visible to a static client scan (no `Gemfile` in the pin surface). Upgrade to ≥ 0.23.0. The DNS-rebinding / missing-`Host`-validation class is covered on AAK's side by the transport-security rule `AAK-DNS-REBIND-001` (browser DNS-rebind → loopback MCP server). (#508) | 2026-07-30 |
| CVE-2026-67430 (MCP Ruby SDK / `mcp` gem < 0.23.0 — `StreamableHTTPTransport` does not expire sessions → repeated `initialize` requests retain unbounded `ServerSession` objects → memory-exhaustion DoS; MEDIUM 5.3) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-67430) | **Out of scope** — RubyGems + server-side session-lifecycle internals; no client-config signal and no `Gemfile` in the pin surface. Upgrade to ≥ 0.23.0. Reachable posture at most is the exposed remote endpoint (`AAK-MCP-001`). (#510) | 2026-07-30 |
| CVE-2026-63119 (MCP Ruby SDK / `mcp` gem < 0.23.0 — `StdioTransport` / `Client::Stdio` use `IO#gets` with no byte limit → a peer sending data without a newline exhausts process memory; MEDIUM 6.2) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-63119) | **Out of scope** — RubyGems + a local stdio-transport resource exhaustion in the gem's Ruby source; not visible in any client config and no `Gemfile` in the pin surface. Being a local stdio DoS, the remote-endpoint `AAK-MCP-001` posture does not apply. Upgrade to ≥ 0.23.0. (#509) | 2026-07-30 |

## 2026-07-28 (v0.3.62)

Three `cve-response` issues adjudicated for the v0.3.62 cut — all dispositioned
out of scope with rationale (no new rule). Each was verified against the NVD
record (not the issue title) before a verdict.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-16496 (terraform-mcp-server 0.3.0–<1.1.0 — authorization bypass in the streamable-HTTP stateful transport: a user who obtains another user's MCP session ID executes tool calls with that user's Terraform credentials; HIGH 8.9) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-16496) | **Out of scope** — HashiCorp `terraform-mcp-server` is a Go project/binary, not a PyPI/npm artifact the pin scanner keys on (same basis as prior Go-server CVEs), and the session-ID authz bypass is a server-side runtime property invisible to a static client-config scan. Upgrade to ≥ 1.1.0; the reachable no-auth/hijackable-endpoint posture is flagged by `AAK-MCP-001`. (#505) | 2026-07-28 |
| CVE-2026-47427 (GitHub MCP Server <1.1.0 — `CompletionsHandler` in `pkg/github/server.go` dereferences a nil `params.Ref` on a completion/complete request with a missing ref → pre-auth Go panic → DoS; HIGH 7.5) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-47427) | **Out of scope** — `github-mcp-server` is a Go binary (not PyPI/npm), and a nil-deref crash in the server's Go source is not detectable from a client config. Upgrade to ≥ 1.1.0. (#504) | 2026-07-28 |
| CVE-2026-9680 (alibabacloud-rds-openapi-mcp-server 1.8.0–3.1.2 — the MCP endpoint listens on all interfaces (`0.0.0.0`) by default → remote unauthenticated tool invocation; MEDIUM 5.8) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-9680) | **Out of scope** — no published fix version (no floor to pin against) and a default-bind exposure is a server/deployment condition, not visible in a client `.mcp.json`. Bind to loopback + require auth; the no-auth-remote-endpoint class is flagged by `AAK-MCP-001`. (#503) | 2026-07-28 |

## 2026-07-27 (v0.3.60)

Seven `cve-response` issues adjudicated for the v0.3.60 cut — one new pin, one
class-covered by an existing pin, five dispositioned out of scope with rationale.
Each was verified against the NVD record (not the issue title) before a verdict.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-16584 (AWS API MCP Server 0.2.13–1.3.46 — when security-policy enforcement data fails to initialize at startup, the policy check is skipped for the process lifetime → actor executes AWS API operations the policy was set to deny/gate; fixed 1.3.47; HIGH 7.0) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-16584) | **Pinned** `AAK-MCP-AWSAPIMCP-CVE-2026-16584-001` — fix floor `awslabs.aws-api-mcp-server` 1.3.47, `introduced` 0.2.13 (pre-0.2.13 and ≥1.3.47 clear). Pinnable `uvx`/PyPI artifact referenced with a version in `.mcp.json`. (#491) | 2026-07-27 |
| CVE-2026-63732 (9router 0.4.59 — hardcoded default password `123456` + spoofed-Host LOCAL_ONLY bypass + unvalidated `child_process.spawn()` MCP-plugin registration → RCE; fixed 0.4.60; CRITICAL 9.9) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-63732) | **Class-covered** by the existing `AAK-MCP-9ROUTER-CVE-2026-46339-001` pin (floor `9router` 0.5.2 ⊇ the affected 0.4.59); CVE added to the rule's `cve_references`. (#496) | 2026-07-27 |
| CVE-2026-66012 (SiYuan < v3.7.2 — missing authorization on the `POST /mcp` kernel endpoint + anonymous Publish reverse-proxy → remote unauthenticated MCP access → admin takeover; CRITICAL 10.0) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-66012) | **Out of scope** — server-side authz flaw in a desktop app referenced by URL, not a pinned `npx`/`uvx` artifact; a static config scan can't see SiYuan's version or internal auth gating. The reachable posture (no-auth remote MCP endpoint) is flagged by `AAK-MCP-001`. Upgrade to ≥3.7.2 + disable anonymous Publish. (#499) | 2026-07-27 |
| CVE-2026-15015 (MountDev AI MCP Connector for WordPress ≤ 1.6.1 — public Dynamic Client Registration + unprotected authorization endpoint → unauthenticated attacker mints admin-bound OAuth bearer token; CRITICAL 9.8) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-15015) | **Out of scope** — server-side WordPress plugin authz bypass; the plugin version is not present in a client config, and open-DCR is a server property AAK can't observe from the client side. Upgrade the plugin > 1.6.1 + require admin approval for OAuth client registration. (#490) | 2026-07-27 |
| CVE-2026-66005 (Jan ≤ 0.8.4 — local API server replaces user-configured trusted hosts with a wildcard reflecting arbitrary origins with credentials → network-adjacent / DNS-rebinding access to the unauthenticated OpenAI-compatible API + MCP tools; MEDIUM 6.3) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-66005) | **Out of scope** — runtime CORS misconfiguration in a desktop app's local server; not a pinned MCP package and not visible in any file a static scanner reads. Fix is a commit (3e1c1e7), no version floor. Upgrade Jan + bind the local API to loopback. (#498) | 2026-07-27 |
| CVE-2026-17433 (NanoClaw ≤ 2.0.64 — improper authorization in `createChatSdkBridge.setup` / "MCP Server Approval"; local; CVSS 3.1 5.3) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-17433) | **Out of scope** — local, source-level authz flaw in NanoClaw's own TypeScript, invisible to a client-config scan, and **no vendor fix exists** (project unresponsive) so there is no floor to pin against. Revisit if a fixed version ships. (#500) | 2026-07-27 |
| CVE-2026-47769 (APIFold before commit 7f19b52 — `/webhooks/:serverSlug/:eventName` accepts unauthenticated JSON with the signature check unconditionally skipped → attacker-controlled data served as trusted MCP resource state; MEDIUM 5.3) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-47769) | **Out of scope** — server-side trust-boundary flaw fixed by a git commit (no PyPI/npm version floor), and the APIFold-generated endpoint is referenced by URL, exposing neither its version nor the missing validators map. Update APIFold past 7f19b52 + require webhook signature validation. (#492) | 2026-07-27 |

## 2026-07-23 (v0.3.58)

Two `cve-response` issues triaged for the v0.3.58 cut — one new pin, one
dispositioned.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-65594 (n8n MCP Server Trigger — the OAuth 2.1 consent/token flow does not verify the authenticated user's access to the referenced workflow → member-level user self-approves consent for another user's workflow and runs it in the owner's project with the owner's credentials; affected 2.27.0–<2.29.8 and 2.30.0–<2.30.1) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-65594) | **Pinned** `AAK-MCP-N8N-CVE-2026-65594-001` — two arms (mainline floor 2.29.8 introduced 2.27.0; 2.30.x floor 2.30.1 introduced 2.30.0). A distinct fix line from CVE-2026-59207 (2.27.4/2.28.1), so its own rule rather than a floor bump — the old pin must not false-positive the 2.28.x line, and this one must not miss it. | 2026-07-23 |
| CVE-2026-44192 (Ansible Lightspeed MCP server — path traversal via indirect prompt injection → writes files to unauthorized locations; MEDIUM 6.6) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-44192) | **Not pinnable** — a Red Hat product component (Ansible Lightspeed), not a standalone npm/PyPI dependency a scanned project pins, and no fixed version is published (a floorless pin would false-positive after any future fix). Path-traversal / indirect-prompt-injection class. No rule. | 2026-07-23 |

## 2026-07-22 (v0.3.57)

Five `cve-response` issues triaged for the v0.3.57 cut — one new pin, one
class-covered by an existing pin, three dispositioned with rationale.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-47708 (MCP-for-Stata < 1.17.3 — `log_file_name` interpolated into a Stata command string with no sanitization → arbitrary Stata `shell`/`python`/`erase` command injection) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-47708) | **Pinned** `AAK-MCP-STATA-CVE-2026-47708-001` (fix floor `mcp-for-stata` 1.17.3) | 2026-07-22 |
| CVE-2026-47394 (PraisonAI < 4.6.40 — incomplete fix of CVE-2026-44336; `workflow.show` + unvalidated `tools/call` kwargs → arbitrary file read) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-47394) | **Class-covered** by the existing `AAK-MCP-PRAISONAI-CVE-2026-61427-001` pin (floor 4.6.78 ⊇ every < 4.6.40 affected version); CVE added to the rule's `cve_references`. | 2026-07-22 |
| CVE-2026-50758 (next-ai-draw-io 0.4.13 — XSS via the `mcp` parameter) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-50758) | **Class-covered** by the existing `AAK-NEXT-AI-DRAW-001` pin, which fires on `next-ai-draw-io < 0.4.15` and so catches the affected 0.4.13. No separate rule (a DoS-titled pin should not carry an unrelated XSS CVE); no vendor fix version for the XSS is published. | 2026-07-22 |
| CVE-2026-15829 (googleapis/mcp-toolbox — `bigquery-forecast` SQL injection / `allowedDatasets` bypass) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-15829) | **Not pinnable** — mcp-toolbox is a Go binary (`googleapis/genai-toolbox`), not an npm/PyPI dependency a scanned project pins, and no fixed version is published. SQLi class; outside AAK's pin/config surface. No rule. | 2026-07-22 |
| CVE-2026-65056 (mcp-webresearch 0.1.7 — SSRF: `visit_page` validates URL scheme only, not private/reserved IP ranges → cloud-metadata/internal reach; HIGH 8.2) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-65056) | **Class-covered, not pinned** — the caller-URL→fetch-without-allow-list pattern is exactly `AAK-MCP-SSRF-001` (CVE-2026-14748 anchor). No published fix version, so a version pin would false-positive after any future fix; tracked here instead. | 2026-07-22 |

## 2026-07-21 (v0.3.56)

Five `cve-response` issues triaged for the v0.3.56 cut — two pinned, three
dispositioned with rationale.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-46555 (whatsapp-mcp < 0.2.1 — `whatsapp-bridge` unauthenticated loopback HTTP API + no Host validation + absolute `media_path` → arbitrary file exfil as WhatsApp attachments, DNS-rebinding; CVSS 7.7) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-46555) | **Pinned** `AAK-MCP-WHATSAPP-CVE-2026-46555-001` (fix floor 0.2.1; fires on manifest/lockfile references below 0.2.1) | 2026-07-21 |
| CVE-2026-57495 (AgenticMail bridge-wake indirect prompt injection — external mail resumes the operator's Claude Code session with `permissionMode: bypassPermissions`, embedding attacker-controlled `from`/`subject`/`preview` into a fully-privileged agent) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-57495) | **Pinned** `AAK-MCP-AGENTICMAIL-CVE-2026-57495-001` — one rule, per-package fix floors: `@agenticmail/claudecode` ≥ 0.2.39, `@agenticmail/codex` ≥ 0.1.33, `@agenticmail/core` ≥ 0.9.43, `@agenticmail/openclaw` ≥ 0.5.71 | 2026-07-21 |
| CVE-2026-53378 (Linux kernel `drm/colorop` blob-property reference leak) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-53378) | **Out of scope** — a Linux-kernel DRM reference-counting memory leak, not an MCP/agent artifact. Surfaced only because the NVD keyword feed matched; there is no AAK config/dependency surface. No rule. | 2026-07-21 |
| CVE-2026-55544 (NextCRM 0.12.1 — MCP campaign tools ignore the authenticated user ID → BOLA/IDOR across campaigns; fixed 0.12.2; CVSS 7.6) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-55544) | **Not pinnable** — server-side broken-object-level-authorization in a self-hosted Next.js app (`nextcrm-app`), which is not an npm/PyPI dependency a scanned project pins, and the flaw has no client `.mcp.json` or dependency-manifest signal. Outside AAK's detection surface; no rule. | 2026-07-21 |
| CVE-2026-55550 (NextCRM 0.12.1 — MCP product tools skip role checks → any low-priv user mutates the shared catalog; fixed 0.12.3; CVSS 7.1) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-55550) | **Not pinnable** — same class and app as CVE-2026-55544 (self-hosted server-side authorization logic). Outside AAK's detection surface; no rule. | 2026-07-21 |

## Dispositioned 2026-07-19 (v0.3.52)

| Incident / Anchor | Reference | AAK rule(s) / disposition | Dispositioned |
|---|---|---|---|
| CVE-2026-16133 (LiuMengxuan04 MiniCode 0.1.0 — `child_process.spawn` command injection in `mcp.ts`) | [NVD CVE-2026-16133](https://nvd.nist.gov/vuln/detail/CVE-2026-16133) (MEDIUM, CVSS 5) | **Class-covered** by `AAK-MCP-STDIO-CMD-INJ-*` (TS/JS MCP stdio `child_process.spawn` command injection). Not pinned — GitHub-only project (0.1.0), no released fix (upstream PR pending), no matching npm/PyPI artifact. | 2026-07-19 |

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
scheme and are dispositioned below. Latency ran past 48 hours for the earlier
CVEs — this backlog accumulated between the v0.3.48 and v0.3.49 releases
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

## Open (best-effort — no committed SLA)

_none — newly-filed `cve-response` issues are tracked here until triaged._
