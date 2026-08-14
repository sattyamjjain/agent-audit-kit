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

## 2026-08-14 (v0.3.75)

Two `cve-response` issues. One pinnable on PyPI; one distributed as a git checkout, so it ships as a detection rule instead of a pin — the disposition the pin scanner's docstring already reserves for non-pinnable CVEs.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-73296 (Microsoft UFO < 3.0.8 — `create_mobile_data_collection_server` and `create_mobile_action_server` in `ufo/client/mcp/http_servers/mobile_mcp_server.py` publish Streamable-HTTP MCP services on TCP 8020 and 8021 with no inbound authentication; an unauthenticated remote caller invokes `capture_screenshot`, `get_ui_tree`, `tap`, `swipe`, `type_text`, `launch_app`, `press_key` and `click_control` against the ADB-connected Android device, reading screen and device data and changing device state; CRITICAL, CVSS 9.4) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73296) | **In scope, detection rule (not pinned)** `AAK-MCP-UFO-CVE-2026-73296-001` (MCP_CONFIG, CRITICAL). UFO ships as a git checkout, not a PyPI or npm artifact — `ufo` on PyPI 404s and `ufo` on npm is unjs's unrelated URL library, so a pin row would either never resolve or fire on the wrong package. New scanner `ufo_mobile_mcp` instead, over three paths: vendored server source that builds either mobile server without auth, an MCP config wired to 8020/8021, and a UFO git dependency unpinned or below 3.0.8. (#573) | 2026-08-14 |
| CVE-2026-73498 (MCP Atlassian < 0.22.0 — `confluence_upload_attachment` passes its client-supplied `file_path` straight to `open(file_path, "rb")` in `_upload_attachment_direct()` in `src/mcp_atlassian/confluence/attachments.py` without calling `validate_safe_path`; an authenticated MCP client, or an agent induced by untrusted content, reads any file the server process can reach and exfiltrates it to Confluence as an attachment, including whatever holds `CONFLUENCE_API_TOKEN`; HIGH, CVSS 7.7) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73498) | **In scope, pinned** `AAK-MCP-ATLASSIAN-CVE-2026-73498-001` (SUPPLY_CHAIN, HIGH): floor `mcp-atlassian >= 0.22.0`, carried by the `mcp_cve_pins_2026_07` pin table. Resolves on PyPI (0.22.0 published; 0.23.0 latest). A second detector in `mcp_atlassian` catches a vendored or reimplemented copy of the handler, where there is no pin to read. Distinct from the 2026-04 Atlassian RCE chain (CVE-2026-27825/27826) already carried by that scanner. (#574) | 2026-08-14 |

## 2026-08-12 (v0.3.74)

Two `cve-response` issues, both adjudicated in scope and pinned after an npm registry check.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-72768 (n8n < 2.32.1 — server-side-request-forgery-protection bypass in the MCP Client node: an authenticated workflow author can send requests to internal / blocked hosts without routing through n8n's SSRF protection, exposing internal services and reading the responses back through the workflow; CVSS n/a) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-72768) | **In scope, pinned** `AAK-MCP-N8N-CVE-2026-72768-001` (SUPPLY_CHAIN, MEDIUM): floor `n8n >= 2.32.1`. `n8n` resolves on npm (fix 2.32.1 published; latest 2.34.5). A third distinct n8n arm — separate from CVE-2026-59207 (credential-domain bypass) and CVE-2026-65594 (two-branch OAuth fix) — carried by the same `mcp_cve_pins_2026_07` pin table. (#568) | 2026-08-12 |
| CVE-2026-73222 (claude-code-templates < 1.29.4 — the `--studio` option launches the Claude Code Studio server on 0.0.0.0:3444 with CORS open and no authentication; `POST /api/execute` (`prompt`) and `POST /api/install-agent` (`agentName`), plus the agent path reachable from `/api/execute` via `checkAndInstallAgent()`, reach `child_process.spawn()` with shell execution enabled → unauthenticated OS command execution with the developer's privileges; HIGH, CVSS 8.8) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73222) | **In scope, pinned** `AAK-MCP-CCTEMPLATES-CVE-2026-73222-001` (SUPPLY_CHAIN, HIGH): floor `claude-code-templates >= 1.29.4`. Resolves on npm (fix 1.29.4 is latest; the release before it is 1.29.2 — no 1.29.3 was published). (#569) | 2026-08-12 |

## 2026-08-11 (v0.3.73)

One `cve-response` issue, adjudicated in scope and pinned.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-19516 (Grafana `mcp-grafana` <= 1.0.0 — a caller-controlled `X-Grafana-URL` header sets the outbound destination and `grafana_api_request` picks the method/path/body, so the destination is not restricted to the configured instance, giving SSRF to internal / loopback / metadata endpoints; CRITICAL, CVSS 9.1) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19516) | **Pinned** `AAK-MCP-GRAFANA-CVE-2026-19516-001` (SUPPLY_CHAIN, CRITICAL): `mcp-grafana >= 1.1.0`, which restricts the destination. The incomplete-fix follow-up to CVE-2026-15583 (that fix stopped the service-account token leak but not the destination), so the control is destination restriction, not token handling. mcp-grafana is a Go server but ships a resolvable PyPI wrapper (`uvx mcp-grafana`, versions through 1.1.0), so it is pinnable after all — superseding the 2026-07-16 "documented, not pinned" note. (#566) | 2026-08-11 |

## 2026-08-10 (v0.3.72)

One `cve-response` issue, adjudicated out of scope after a registry check.

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-19338 (automateyournetwork `MCPyATS` <= 0.1.4, path traversal via `folder`/`name` in `mcp_servers/mermaid/index.ts`; local) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19338) | **Out of scope, unpinnable.** `mcpyats`, `@automateyournetwork/mcpyats`, and `pyats-mcp` all 404 on npm, and `mcpyats` 404 on PyPI. A GitHub-only project with no versioned registry artifact to pin. (#565) | 2026-08-10 |

## 2026-08-09 (v0.3.71)

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

## Older CVE ledger

Ledger sections for the **v0.3.58 cut and earlier** (down to v0.3.0) are archived in [docs/changelog/archive/CHANGELOG.cves.md](docs/changelog/archive/CHANGELOG.cves.md).
