<p align="center">
  <h1 align="center">AgentAuditKit</h1>
  <p align="center"><strong>The missing <code>npm audit</code> for AI agents.</strong></p>
</p>

<p align="center">
  <a href="https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml"><img src="https://github.com/sattyamjjain/agent-audit-kit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agent-audit-kit/"><img src="https://img.shields.io/pypi/v/agent-audit-kit.svg" alt="PyPI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="benchmarks/determinism/RESULTS.md"><img src="https://img.shields.io/badge/determinism-0%25%20variance%20(20%2F20)-brightgreen.svg" alt="Determinism: 0% variance across 20/20 runs"></a>
  <!-- fp-badge --><a href="benchmarks/false_positive/RESULTS.md"><img src="https://img.shields.io/badge/benign--slice%20536%20configs-HIGH%2FCRIT%20FP%200%2F1-brightgreen.svg" alt="Benign-slice false-positive measurement: 536 configs scanned, 0 of 1 HIGH/CRITICAL findings were false positives (0.0%)"></a><!-- /fp-badge -->
  <a href="docs/benchmarks/third-party-grading.md"><img src="https://img.shields.io/badge/third--party%20grade-see%20notes-lightgrey.svg" alt="Third-party grading notes"></a>
  <a href="#what-it-scans"><img src="https://img.shields.io/badge/rules-332-blue.svg" alt="Rules: 332"></a>
  <a href="#frameworks--standards"><img src="https://img.shields.io/badge/OWASP_Agentic-10%2F10-green.svg" alt="OWASP Agentic: 10/10"></a>
  <a href="#frameworks--standards"><img src="https://img.shields.io/badge/OWASP_MCP-10%2F10-green.svg" alt="OWASP MCP: 10/10"></a>
  <a href="https://sattyamjjain.github.io/agent-audit-kit/"><img src="https://img.shields.io/badge/MCP_Security_Index-live-blue.svg" alt="MCP Security Index"></a>
  <a href="research/state-of-mcp-2026/REPORT.md#how-to-cite-this-report"><img src="https://img.shields.io/badge/cite-State_of_MCP_Security_2026_v1.0-informational.svg" alt="Cite the State of MCP Security 2026 report, version 1.0"></a>
</p>

---

<p align="center">
  <a href="https://asciinema.org/a/9X7N1ztuuIYi9T2P" target="_blank"><img src="https://asciinema.org/a/9X7N1ztuuIYi9T2P.svg" alt="AgentAuditKit Demo" width="700"/></a>
</p>

Security scanner for MCP-connected AI agent pipelines. Finds misconfigurations, hardcoded secrets, tool poisoning, rug pulls, trust boundary violations, and tainted data flows across **10 agent platforms**.

**What we measured across the public MCP ecosystem** ([State of MCP Security 2026, v1.0](research/state-of-mcp-2026/REPORT.md) — [how to cite](research/state-of-mcp-2026/REPORT.md#how-to-cite-this-report)):

- **<!-- report:corpus -->2,303<!-- /report --> distinct public MCP configs scanned**, of which **<!-- report:rfc9728-n -->0<!-- /report --> serve RFC 9728** Protected-Resource-Metadata discovery.
- **<!-- report:noauth-pct -->52.1<!-- /report -->% (<!-- report:noauth-n -->1,200<!-- /report -->)** declare a remote server with **no authentication**.
- **<!-- report:inline-auth-pct -->100<!-- /report -->% (<!-- report:inline-auth-n -->424<!-- /report -->/<!-- report:inline-auth-d -->424<!-- /report -->)** of inline-auth remote configs **hardcode a static credential**.

These are regenerated from `research/state-of-mcp-2026/results.json` by `scripts/sync_rule_count.py` and asserted by `tests/test_report_headline_numbers.py`, so they cannot drift from the report.

**Two things it does that hosted scanners can't:**

1. **Runs fully offline and deterministically.** Your code, configs, and secrets never leave the machine; the default scan path makes zero network calls, and the same input always yields the same finding (no model in the loop). This is measured, not just claimed: [20/20 identical runs → one shared SHA-256 finding-set digest, 0% variance](benchmarks/determinism/RESULTS.md). Scanners that route findings through an LLM judge can't guarantee a byte-identical re-run — so CI diffs, audit re-runs, and regression baselines stay stable here. No account, no telemetry. Precision is measured the same way, not asserted: we publish a reproducible, hand-adjudicated [benign-slice HIGH/CRITICAL false-positive rate](benchmarks/false_positive/RESULTS.md) — with a Wilson confidence interval and any offending rule filed as an issue.
2. **Produces auditor-ready compliance-evidence packs.** SARIF for the GitHub Security tab plus PDF evidence reports mapped to 12 frameworks (EU AI Act, SOC 2, ISO 27001/42001, HIPAA, NIST AI RMF, and regional regimes) — what you hand an auditor, not just a list of findings.

- **<!-- rule-count:total -->332<!-- /rule-count --> rules** across 14 security categories, covering the 2026 CVE wave
  - Rule count is computed from the registry and verified in CI (`test_rule_count_is_canonical`).
- **<!-- scanner-count:total -->98<!-- /scanner-count --> scanner modules** including AST-based Python taint analysis and regex pattern scanners for TypeScript/JavaScript and Rust
- **Remediation guidance: all <!-- rule-count:total -->332<!-- /rule-count --> of <!-- rule-count:total -->332<!-- /rule-count --> rules.** Every finding tells you what to change and why — that is the product, and it has no gap.
- **Mechanical fix recipes: <!-- fix-recipe-coverage:count -->11<!-- /fix-recipe-coverage --> of <!-- rule-count:total -->332<!-- /rule-count --> rules (<!-- fix-recipe-coverage:pct -->3.3<!-- /fix-recipe-coverage -->%).** This is a scope decision, not coverage: **a recipe ships only where the remediation is deterministic and one-line** — exactly one correct edit, confirmable from the diff. Everything else stays advisory on purpose, because a fix that needs judgement is a fix that can be wrong silently. `agent-audit-kit fix` applies these; the narrower `suggest --auto-pr` allow-list is the subset AAK will open a PR for.
  <br>The rules with the most findings are the ones that fail that bar hardest, and the reasons are written down per fix shape in [`autopr.py`](agent_audit_kit/autopr.py): splitting a shell string into argv needs the shell's own parse; flipping a transport needs to know the server speaks the replacement; declaring RFC 9728 metadata needs an endpoint stood up on a different machine than the one being scanned. [`AAK-OAUTH-008` is the worked example](agent_audit_kit/autopr.py): the only edit that silences it leaves the credential in place, and a test performs that edit to prove it.
  - Coverage is computed from the registry and verified in CI (`test_fix_recipe_coverage_is_canonical`), which also asserts every rule marked `auto_fixable` has a recipe that actually runs.
- **26 CLI commands**: `scan`, `discover`, `pin`, `verify`, `fix`, `score`, `update`, `proxy`, `kill`, `diff`, `suggest`, `watch`, `watch-cve`, `notify`, `install-precommit`, `export-rules`, `verify-bundle`, `sbom`, `report`, `coverage`, `inspect-ide`, `parity`, `corpus`, `pipelock`, `rule`, `scanners`
- **OWASP coverage**: Agentic Top 10 (10/10), MCP Top 10 (10/10), Adversa AI Top 25
- **Compliance mapping** (12 frameworks): EU AI Act Art. 15 + 55, SOC 2, ISO 27001, ISO/IEC 42001, HIPAA, NIST AI RMF, **NSA MCP Security CSI (U/OO/6030316-26, May 2026)**, Singapore Agentic AI, India DPDP 2023, **Alabama Personal Data Protection Act (HB 351, 2026)**, **Tennessee SB 1580 Health Care AI (PRA)** — PDF reports via `agent-audit-kit report --format pdf --framework <name>`; plus `agent-audit-kit scan . --compliance mcp-2026-roadmap` for **MCP 2026 Roadmap (May 2026)** conformance (a scan-time mapping, not a PDF evidence pack)
- **Supply chain**: deterministic rule bundle (`export-rules`), Sigstore-signed releases, CycloneDX + SPDX SBOM (`sbom`)
- **MCP Security Index**: public leaderboard at [sattyamjjain.github.io/agent-audit-kit](https://sattyamjjain.github.io/agent-audit-kit/) ([snapshot dates](#mcp-security-index)) — per-server grade cards (A–F), 90-day [disclosure policy](docs/disclosure-policy.md)
- **CVE coverage**: newly disclosed MCP CVEs are triaged and turned into rules as they land — surfaced automatically by the NVD watcher ([`cve-watcher.yml`](.github/workflows/cve-watcher.yml)) and logged in [CHANGELOG.cves.md](CHANGELOG.cves.md). Per-severity triage budgets and the current queue depth are published in [docs/cve-triage.md](docs/cve-triage.md)
- **OAuth / spec coverage**: the **2026-07-28 final auth profile** as a one-command check — `agent-audit-kit scan . --profile mcp-2026-07-28` runs RFC 9207 `iss` validation (`AAK-OAUTH-006`), RFC 8707 resource indicators (`AAK-OAUTH-007`), and RFC 9728 Protected-Resource-Metadata discovery (`AAK-OAUTH-008`). We scanned 2,303 distinct public MCP configs: **0 use RFC 9728 discovery; <!-- report:noauth-pct -->52.1<!-- /report -->% (<!-- report:noauth-n -->1,200<!-- /report -->) declare a remote server with no authentication; 100% (421/421) of inline-auth remote configs hardcode a static credential** — see the [State of MCP Security 2026](research/state-of-mcp-2026/REPORT.md) report, v1.0, [citable](research/state-of-mcp-2026/REPORT.md#how-to-cite-this-report) (the earlier dated [2026-07-18 748-config readiness scan](docs/reports/mcp-2026-07-28-readiness.md) is a separate point-in-time artifact). The July 2026-07-28 deprecation/stateless pack stays labelled **release candidate** (the spec ratifies 2026-07-28); every cited SEP was re-verified in the [ratification reconciliation](CHANGELOG.cves.md)
- **Spec-ahead coverage + standards crosswalk**: the two wedges a free hosted scanner can't match are **offline determinism** and **standards-provenance compliance evidence** — and AAK ships coverage for the **2026-07-28 MCP spec surface before it ratifies**. The spec-ahead pack (all static, deterministic, no LLM): `Mcp-Method`/`Mcp-Name` routable-header ↔ body desync (`AAK-MCP-ROUTING-DESYNC-001`, **SEP-2243**), MCP Apps UI iframe rendered without sandbox / sanitization (`AAK-MCP-APPS-001/002`, **SEP-1865**), and unbounded MCP Tasks with no quota/concurrency bound → task-flood DoS (`AAK-TASKS-004`, **SEP-2663**). Every rule is mapped, rule by rule, to the **NSA MCP Security CSI** control it evidences and its **OWASP Agentic Top-10 (2026)** item in the [standards crosswalk](docs/crosswalk/nsa-csi-owasp-agentic.md) — regenerate it any time with `agent-audit-kit report --framework standards-crosswalk`.
- **Zero cloud dependencies** — runs fully offline, zero network calls in the default scan path

### Why This Exists

In early 2026, [30 MCP CVEs dropped in 60 days](https://www.heyuan110.com/posts/ai/2026-03-10-mcp-security-2026/). [CVE-2026-33032](https://nvd.nist.gov/vuln/detail/CVE-2026-33032) (Nginx-UI MCP auth bypass, CVSS 9.8) exposed a shared-handler pattern that several other servers have. [CVE-2025-59536](https://nvd.nist.gov/vuln/detail/CVE-2025-59536) turned a project-local Claude Code hook into RCE. [CVE-2026-34070](https://nvd.nist.gov/vuln/detail/CVE-2026-34070) hit LangChain's `load_prompt()` with absolute-path and `..` traversal. [CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852) demonstrated source-code exfiltration via a single Claude Code config flag. A 2,614-server survey found **82% of public MCP servers** had path-traversal issues. On 2026-05-01, [OX Security disclosed 10+ CVEs](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/) across DocsGPT, GPT-Researcher, Agent-Zero, LettaAI, LiteLLM, LangFlow, Flowise, Bisheng, and Langchain-Chatchat — all rooted in the same MCP STDIO command-injection class `AAK-MCP-STDIO-CMD-INJ-*` covers. Meanwhile, every AI coding assistant adopted MCP with sparse security tooling.

AgentAuditKit is the deterministic, auditor-ready OSS scanner that closes the gap.

> **Architectural note:** AAK rules are multi-arm adjudicators (pin arm + source/config arm + explicit-reject short-circuit + adjudicator log), not single-shot regex matchers. See [docs/notes/adjudicator-pattern.md](docs/notes/adjudicator-pattern.md) for the four-arm structure and the Mozilla / arXiv precedents.

---

## Quick Start

### GitHub Action (Recommended)

```yaml
# .github/workflows/agent-security.yml
name: Agent Security Scan
on: [push, pull_request]

permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sattyamjjain/agent-audit-kit@v0.3.94
        id: scan
        with:
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()   # upload even if the scan failed the build
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

The scan step emits SARIF; the `upload-sarif` step publishes it, so findings
appear as **inline PR annotations** and in the **Security tab**. See
[SARIF Integration](#sarif-integration).

### CLI

```bash
pip install agent-audit-kit
agent-audit-kit scan .

# `aak` is installed as a shorthand for the same command
aak scan .
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/sattyamjjain/agent-audit-kit
    rev: v0.3.94
    hooks:
      - id: agent-audit-kit
```

### Try It Now

Scan a deliberately vulnerable config to see AgentAuditKit in action:

```bash
git clone https://github.com/sattyamjjain/agent-audit-kit
cd agent-audit-kit
pip install -e .
agent-audit-kit scan examples/vulnerable-configs/04-hook-exfiltration/
```

11 vulnerability examples covering all security categories in the [examples/](examples/) directory. See also the [damn-vulnerable-MCP-server case study](examples/case-studies/damn-vulnerable-mcp/).

---

## What It Scans

| Category | Rules | What It Detects |
|----------|:-----:|-----------------|
| **MCP Configuration** | <!-- category-count:MCP_CONFIG -->66<!-- /category-count --> | Missing auth middleware (CVE-2026-33032 class), empty IP allowlists, wildcard CORS, path traversal in resource handlers, SSRF (CWE-918), OAuth 2.1 misconfig (PKCE/S256/DPoP), Tasks primitive leakage (SEP-1686), shell injection, MCPwn middleware-asymmetry, Azure MCP no-auth (CVE-2026-32211), MCP Inspector vendored fork (CVE-2026-23744), 2026-07-28 stateless-MCP migration (`Mcp-Session-Id` reliance, removed `tasks/list`, sticky-session deployment, un-cached client `tools/list`), deny-by-default attested admission (signed clearance / `/.well-known/mcp-clearance` / pinned trust root — arXiv:2605.24248), Anthropic MCP Tunnels gateway (SSRF defense disabled / `upstream.disable_ip_validation`, HTTPS upstream missing `upstream.tls.ca_file` trust anchor, tunnel token + TLS private keys hardcoded in CI / committed Kubernetes Secrets — research preview 2026-05-19), stdio launcher injection (`npx`/`node`/`bash`/`sh`/`python` with `-c`/`-e`/`--eval`, or non-pinned interpolated argv — CVE-2026-40933), tool-gate enforcement asymmetry (allowlist / read-only / non-destructive check applied in `tools/list` but not `tools/call` — CVE-2026-46519), unauthenticated MCP HTTP/SSE server on `0.0.0.0` / wildcard CORS (GitLab/Nocturne/AgenticMail no-auth class — CVE-2026-44895/44830/50287), plus the non-loopback no-auth **launch surface** — `mcp.json`/`claude_desktop_config.json`/`*.mcp.yaml` `command`/`args`, Docker `--host 0.0.0.0`/`-p 0.0.0.0:`, and MCP Inspector / FastMCP startup binding `0.0.0.0`/`::`/a routable IP with no token or `DANGEROUSLY_OMIT_AUTH` set (CWE-306; MCP Inspector exemplar CVE-2026-23744; mcp-pinot `0.0.0.0:8080` no-auth CVE-2026-49257; Windows-MCP wildcard-CORS no-auth CVE-2026-48989; ~12,520 exposed services per Censys), argv-rebuild-after-allowlist command-injection TOCTOU (a command/argv approved against an allow/deny list is re-split / re-joined / extended before `subprocess`/`os.exec*` / Node `child_process.spawn`/`execa` with no re-check — `AAK-MCP-ARGV-TOCTOU-001`, **CWE-77 + CWE-367 / CVE-2026-53822**), MCP server unauthenticated-by-default / fail-open auth (an auth function returning truthy on an empty/unset secret, a placeholder/empty secret literal — `""`/`changeme`/`os.environ.get(...,"")` — or a warning-only secret gate on a `0.0.0.0` bind — `AAK-MCP-NOAUTH-DEFAULT`, **CWE-306 + CWE-862 / CVE-2026-48814** (incomplete fix of CVE-2026-46701)), bearer-token → session-file path traversal (an untrusted token / `Authorization` header joined into a session file path used for an existence/read check with no separator-reject or resolve-and-contain guard — `AAK-MCP-AUTH-PATHTRAVERSAL-001`, **CWE-22 / CVE-2026-52830**, fast-mcp-telegram < 0.19.1), MCP tool-argument URL SSRF (an MCP tool handler passing a caller-supplied `url`/`endpoint`/`target` argument straight into an outbound `requests`/`httpx`/`urllib`/`aiohttp` fetch with no host/scheme allow-list — `ast` parameter→fetch taint for Python, regex fallback for TS/JS/Rust — `AAK-MCP-SSRF-001`, **CWE-918 / CVE-2026-14748**, AIAnytime Awesome-MCP-Server `mcp-wiki/wiki-summary`), Serena MCP toolkit unauthenticated-dashboard RCE (`serena-agent` < 1.5.2 — an unauthenticated Flask dashboard on a fixed port reachable via DNS rebinding writes the agent's persistent memory, chained with `execute_shell_command` `shell=True` to remote code execution — `AAK-MCP-SERENA-CVE-2026-49471-001`, **CWE-306 + CWE-352 / CVE-2026-49471**, HIGH 8.3), MCP 2026-07-28 deprecated features (the `roots` / `sampling` / `logging` capabilities annotation-deprecated under the RC's new 12-month deprecation policy — flagged across config + server source so authors migrate before removal — `AAK-MCP-DEPRECATED-001..003`, **SEP-2577 / SEP-2596**), OAuth `iss`-validation gap (an authorization-code client that handles the auth response but never validates the RFC 9207 `iss` parameter, the RC's actual new OAuth requirement — `AAK-OAUTH-006`, **RFC 9207 / SEP-2468**), RFC 8707 Resource-Indicator absence (an OAuth 2.1 flow / MCP client config that never sets the `resource` parameter, so issued tokens aren't audience-bound and a token minted for one MCP server can be replayed at another — the confused-deputy / audience-confusion class; mandatory in the **ratified** MCP 2025-11-25 auth spec, independent of the 2026-07-28 RC — `AAK-OAUTH-007`, **RFC 8707 / RFC 9728 §7.4**), RFC 9728 Protected-Resource-Metadata discovery gap (a remote MCP server config that embeds a static `Authorization`/`Bearer`/`auth` credential with no `/.well-known/oauth-protected-resource` discovery path, or server source enforcing bearer auth without serving PRM — the resource-discovery arm of the 2026-07-28 auth profile — `AAK-OAUTH-008`, **RFC 9728**) |
| **Supply Chain** | <!-- category-count:SUPPLY_CHAIN -->103<!-- /category-count --> | Vulnerable LangChain / langchain-text-splitters versions, named pin rules for `astro-mcp-server` / `chatgpt-mcp-server` / `docsgpt` / `gpt-researcher` / `litellm` / `mcp-calculate-server` / `semantic-kernel` / `@anthropic-ai/claude-code` / `apache-doris-mcp-server` / `excel-mcp-server`, OX MCP-STDIO command-injection (Python/TS/Java/Rust) — `AAK-MCP-STDIO-CMD-INJ-001..004` — Stainless-generator lineage, marketplace.json signatures / typosquat / mutable refs, unpinned packages, dangerous install scripts, untrusted-search-path executable override in skill/install flows (`.env`-sourced binary, workspace-prepended `PATH`, `shutil.which` over a tainted PATH, Homebrew env override — `AAK-SKILL-UNTRUSTED-EXEC-PATH`, **CWE-426 / CVE-2026-53819**), and the **2026-07 MCP/agent CVE disclosure wave** — verified PyPI/npm version-pins for `litellm` < 1.84.0 (MCP auth bypass + skills-archive traversal, **CVE-2026-59822/59820**), `cline` < 3.0.30 (Hub-dashboard WS origin bypass → RCE, **CVE-2026-59723**), `mcp-text-editor` ≤ 1.0.2 (path traversal, **CVE-2026-15138**), `n8n` < 2.27.4/2.28.1 (MCP tool credential-domain bypass, **CVE-2026-59207**), `ruflo` < 3.16.3 (unauth MCP bridge RCE, **CVE-2026-59726**, CVSS 10), `@arikusi/deepseek-mcp-server` < 1.8.0 (unbound session IDs + unauth HTTP transport, **CVE-2026-55604/55605**), `mcp-server-kubernetes` < 3.9.0 (kubectl `--server` argument injection, **CVE-2026-61459**, CVSS 9.8), and `astrbot` ≤ 4.25.2 (MCP-test-endpoint SSRF, **CVE-2026-15501**) |
| **Tool Poisoning** | <!-- category-count:TOOL_POISONING -->30<!-- /category-count --> | Invisible Unicode / bidi, skill frontmatter injection, SKILL.md post-install commands, data-exfil primitives, skill name hijacking, cross-tool references, rug-pull (SHA-256 pinning), `@mcp.tool` unsafe-eval (CVE-2026-44717 generalization), OpenAPI smells (Hermes paper LAZY/BLOATED/TANGLED), Metis POMDP refusal-refeed + scoring-sink, SkillsVote lifecycle attribution, MCP Calculate Server pin, Kong Konnect MCP server < 1.0.0 indirect prompt injection → unintended Konnect/Admin API requests (`AAK-MCP-KONG-CVE-2026-13341-001`, **CVE-2026-13341**, HIGH 7.4). Indirect-prompt-injection detection (`AAK-POISON-001..006`) runs against tool descriptions **and** every per-parameter `inputSchema.properties.*.description` (recursive — nested objects, array items, `anyOf`/`allOf`/`oneOf`), so instruction text hidden in a single argument's docstring is caught |
| **Secret Exposure** | <!-- category-count:SECRET_EXPOSURE -->18<!-- /category-count --> | Anthropic/OpenAI/AWS/GitHub/GitLab/GCP keys, Shannon-entropy detection, `.env` leaks, private-key files, hardcoded credential surface, token-leak via log sinks (CVE-2026-20205), `${VAR}`/process.env placeholder resolution on user-supplied MCP URLs → secret exfiltration (CVE-2026-32625) |
| **Agent Config** | <!-- category-count:AGENT_CONFIG -->18<!-- /category-count --> | Routines permission escalation + schedule injection + audit-log gaps, AGENTS.md/CLAUDE.md/.cursorrules hijacking, hidden Unicode, encoded payloads, internal scanner-fail signal, Project Deal economic-drift detection |
| **A2A Protocol** | <!-- category-count:A2A_PROTOCOL -->13<!-- /category-count --> | Missing mutual auth, unbounded delegation, transitive trust, replay protection, schema confusion, HTTP endpoints, JWT lifetime/validation, impersonation, multi-agent shared-state without lock (Code-as-Harness) |
| **Hook Injection** | <!-- category-count:HOOK_INJECTION -->17<!-- /category-count --> | Hook RCE (CVE-2025-59536 class), `shell=True` + interpolation, pre-trust execution, network-capable hooks, credential exfiltration, VS Code `.vscode/tasks.json` `runOn: folderOpen` auto-execution (the keyv-worm vector — code runs before the workspace-trust prompt) with `command`/`args` shell-reach and `launch.json` `preLaunchTask` chaining (`AAK-IDE-TASK-001..003`) |
| **Taint Analysis** | <!-- category-count:TAINT_ANALYSIS -->14<!-- /category-count --> | `@tool` param flows to shell/eval/SQL/SSRF/file/deserialization sinks (Python AST), `load_prompt()` user-path reachability, transport-flip MITM (DocsGPT + GPT-Researcher). SQL-injection sinks (`AAK-TAINT-005`) now detected in TypeScript/JS MCP servers too — interpolated/concatenated `.query()`/`.execute()`, `knex.raw`, Prisma `$queryRawUnsafe` — matching the Python + Rust scanners (OX MCP-SDK disclosure class). LLM-generated SQL executed on an RCE-capable DB role (`AAK-LLM-SQL-RCE-001`, **CVE-2026-25879**) — model output reaching `cursor.execute`/`text(...)`/`.query()` as the query itself with no allow-list, plus superuser/`COPY ... FROM PROGRAM`/`xp_cmdshell`/`FILE`-privilege connection roles that turn SQL injection into shell |
| **Transport Security** | <!-- category-count:TRANSPORT_SECURITY -->15<!-- /category-count --> | HTTP endpoints, TLS disabled, deprecated SSE, tokens in URL query strings, transport body-size limits (CVE-2026-39313), SSRF redirect bypass (CVE-2026-41481), DNS-rebinding (CVE-2025-66414/66416, CVE-2026-35568/35577) |
| **Legal Compliance** | <!-- category-count:LEGAL_COMPLIANCE -->12<!-- /category-count --> | Copyleft licenses (AGPL/SSPL), missing licenses, DMCA-flagged packages, India PII surface, US-state consumer privacy (Alabama HB 351, Tennessee SB 1580), Singapore Agentic AI, healthcare AI triggers, EU AI Act Article 15 multilingual-eval coverage advisory (Annex III high-risk binding 2027-12-02, Annex I 2028-08-02 — AI Omnibus) |
| **Trust Boundaries** | <!-- category-count:TRUST_BOUNDARY -->16<!-- /category-count --> | `enableAllProjectMcpServers`, API URL redirects, wildcard permissions, missing deny rules, missing allowlists, Claude Code folder-trust bypass (CVE-2026-40068) |
| **MCP Server Card** | <!-- category-count:MCP_SERVER_CARD -->4<!-- /category-count --> | Static audit of SEP-1649 discovery cards (`/.well-known/mcp/server-card.json`): tool-description poisoning in `tools[].description` (`AAK-MCP-CARD-001`, reuses the AAK-POISON detectors), declared-transport vs advertised-capability mismatch — remote transport with `authentication.required: false`, or `stdio` advertising a remote endpoint (`AAK-MCP-CARD-002`), missing / placeholder signature / provenance (`AAK-MCP-CARD-003`), and over-broad capability / wildcard-scope claims (`AAK-MCP-CARD-004`) |
| **Composition** | <!-- category-count:COMPOSITION -->3<!-- /category-count --> | Risk that exists only between components, where each one passes on its own. An ordered 2- or 3-component path carrying untrusted input to network egress through something that reads secrets or local state, while no single component spans it (`AAK-COMPOSE-001`, CompoSkill **arXiv:2608.16246**); two or more skills sharing a writable path neither declares, which is the collusion channel a declared-capability union cannot see by construction (`AAK-COMPOSE-002`, ColluSkill **arXiv:2608.09732**); and a skill whose body or adjacent scripts exercise a wider capability than its manifest declares, which makes every chain through it look narrower than it is (`AAK-COMPOSE-003`). Paths are capped at three components, where CompoSkill's own attack-success numbers concentrate. Distinct from `AAK-AGENT-COMPOSE-001`, which is an unordered capability union over one container of skills; a composition finding stands down when any component is already reported at the same severity, so a chain is never reported twice |
| **Agentic Skills (AST10)** | <!-- category-count:AGENTIC_SKILL -->3<!-- /category-count --> | The statically decidable subset of the [OWASP Agentic Skills Top 10](#owasp-agentic-skills-top-10-ast10). A skill bundle pulling an external resource that nothing pins, so what it runs is whatever the source serves at the time (`AAK-AST02-001`, **AST02** + the pinning half of **AST07**); a deserialization tag in skill frontmatter that constructs an object while parsing, before any field is read and before the skill is invoked (`AAK-AST04-001`, **AST04** parsing layer, distinct from `AAK-SKILL-005` which reads frontmatter *values*); and a bundle whose platform manifests disagree about security metadata, so the platform loading the weaker one runs without a control the other declares (`AAK-AST10-001`, **AST10**). Three rules, not ten: AST06, AST08 and AST09 need runtime or organisational evidence a static scan cannot supply |

**<!-- rule-count:total -->332<!-- /rule-count --> rules total.** Every finding includes severity, evidence, remediation, OWASP references, Adversa references, and CVE links where applicable.

### MCP Server Card scanning (SEP-1649)

The MCP discovery track ([SEP-1649](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1649), superseded-in-draft by SEP-2127) has servers publish a **server card** at `/.well-known/mcp/server-card.json` — a JSON document (`serverInfo`, `transport`, `capabilities`, `authentication`, `tools[]`) that a client fetches and **trusts before it connects**, ahead of the [2026-07-28 MCP spec finalization](https://modelcontextprotocol.io/). That makes the card an attack surface in its own right.

`agent-audit-kit` statically audits a server card — from a committed file, or an **opt-in** fetch — with four deterministic rules (`AAK-MCP-CARD-001..004`, category **MCP Server Card**): tool-description poisoning, transport/capability mismatch, missing/placeholder provenance, and over-broad capability claims. It stays **offline and deterministic** — the default scan path makes zero network calls; card fetching only happens behind an explicit flag (`AAK_FETCH_SERVER_CARD_URL`, or the crawler's `--server-cards` network pass), and the same card always yields the same findings.

```bash
# audit a committed / saved server card, fully offline
agent-audit-kit scan path/to/server-card.json

# opt-in prevalence sweep of discoverable cards (network; writes results-<date>.json)
python benchmarks/crawler.py --server-cards --limit 200
```

### Agent Platforms Scanned

Claude Code, Cursor, VS Code Copilot, Windsurf, Amazon Q, Gemini CLI, Goose, Continue, Roo Code, Kiro + user-level global configs.

The **VS Code Copilot** config set now includes `.vscode/tasks.json` and `.vscode/launch.json` alongside `.vscode/mcp.json`, so the folder-open task-execution surface is covered: `agent-audit-kit scan` flags a `runOn: folderOpen` auto-run task (`AAK-IDE-TASK-001..004`), and project-level discovery lists these files. (`agent-audit-kit discover` reports machine/user-level agent installs; project configs like these surface in a `scan`.)

### Language Support

| Language | Scanning Method | What It Finds |
|----------|----------------|---------------|
| **Python** | AST analysis (stdlib `ast`) | `@tool` param flows to dangerous sinks (eval, subprocess, SQL, file I/O, HTTP); LangChain `load_prompt()` user-path reachability |
| **TypeScript / JS** | Regex pattern scan | `eval()`, `child_process.exec`, `fs.writeFileSync`, SSRF patterns, OAuth token passthrough in MCP server files |
| **Rust** | Regex pattern scan | `Command::new(format!())`, `unsafe` blocks, SQL macros without parameterization |

_Note: Phase 2 scanners (`ssrf_patterns`, `oauth_misconfig`, `mcp_auth_patterns`, `hook_rce`, `skill_poisoning`, `mcp_tasks`) are regex-based; a tree-sitter AST migration is tracked in [issue #22](https://github.com/sattyamjjain/agent-audit-kit/issues/22)._

---

## CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `agent-audit-kit scan .` | Full security scan |
| `agent-audit-kit scan . --ci` | CI mode: SARIF + `--fail-on high` |
| `agent-audit-kit discover` | Find all AI agent configs on the machine |
| `agent-audit-kit pin .` | Pin tool definitions (SHA-256 hashes) |
| `agent-audit-kit verify .` | Check tools against pins (detect rug pulls) |
| `agent-audit-kit fix . --dry-run` | Auto-fix common misconfigurations |
| `agent-audit-kit suggest run.sarif --pr` | Markdown remediation body for `gh pr create --body-file -` |
| `agent-audit-kit suggest run.sarif --auto-pr` | Apply allow-listed mechanical fixes on a branch and open a **draft** PR |
| `agent-audit-kit score .` | Security grade (A-F) + SVG badge |
| `agent-audit-kit update` | Update vulnerability database |
| `agent-audit-kit proxy --port 8765 --target URL` | Start MCP interception proxy |
| `agent-audit-kit kill` | Terminate running proxy |
| `agent-audit-kit export-rules --out rules.json` | Write deterministic rule bundle + SHA-256 (Sigstore-signable) |
| `agent-audit-kit verify-bundle rules.json [--signature sig]` | Verify bundle digest or Sigstore signature |
| `agent-audit-kit sbom . --format {cyclonedx,spdx}` | Emit CycloneDX 1.5 / SPDX 2.3 SBOM for MCP deps |
| `agent-audit-kit report . --framework FRAMEWORK --format pdf` | Auditor-ready compliance report (EU AI Act / SOC 2 / ISO 27001 / HIPAA / NIST AI RMF) |
| `agent-audit-kit install-precommit` | Add the hook to `.pre-commit-config.yaml` |

### Scan Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `console` | Output: `console`, `json`, `sarif` |
| `--severity` | `low` | Minimum severity to report |
| `--fail-on` | `none` | Exit 1 at this severity: `critical`, `high`, `medium`, `low`, `none` |
| `--output` / `-o` | stdout | Write output to file |
| `--ci` | | Shorthand: `--format sarif --fail-on high -o agent-audit-results.sarif` |
| `--config` | | Path to `.agent-audit-kit.yml` |
| `--rules` | all | Comma-separated rule IDs to include |
| `--exclude-rules` | | Comma-separated rule IDs to skip |
| `--ignore-paths` | | Comma-separated paths to exclude |
| `--include-user-config` | | Also scan `~/.claude/`, `~/.cursor/`, etc. |
| `--score` | | Show security score and grade |
| `--owasp-report` | | Generate OWASP coverage matrix |
| `--compliance FRAMEWORK` | | Compliance report: `eu-ai-act`, `soc2`, `iso27001`, `hipaa`, `nist-ai-rmf`, `mcp-2026-roadmap` |
| `--verify-secrets` | | Probe APIs to check if leaked keys are live (opt-in) |
| `--diff BASE_REF` | | Only report findings in files changed since BASE_REF |
| `--llm-scan` | | Local LLM semantic analysis via Ollama (opt-in) |
| `--sessions PATH` | | Run the session-scoped rules over agent transcripts — OpenAI Agents SDK traces, LangGraph checkpoints, JSONL. See [Session transcripts](docs/session-transcripts.md) |
| `--strict-loading` | | Fail loudly if any optional scanner module can't be imported (default: silently skip) |
| `--verbose` / `-v` | | Detailed scan progress |

### Exit Codes

| Code | Meaning |
|:----:|---------|
| 0 | Scan passed — no findings exceed `--fail-on` threshold |
| 1 | Scan failed — findings meet or exceed `--fail-on` severity |
| 2 | Error — invalid path, malformed config, etc. |

---

## Configuration

Create `.agent-audit-kit.yml` in your project root:

```yaml
severity: medium
fail-on: high
ignore-paths:
  - vendor/
  - third_party/
exclude-rules:
  - AAK-MCP-007    # We intentionally don't pin npx versions
include-user-config: false
```

CLI flags always take precedence over config file values.

---

## GitHub Action Reference

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `severity` | `low` | Minimum severity to report |
| `fail-on` | `high` | Fail at this severity or above (`none` = never fail) |
| `format` | `sarif` | Output format: `sarif`, `json`, `console` |
| `upload-sarif` | `true` | Upload SARIF to GitHub Security tab |
| `include-user-config` | `false` | Scan user-level agent configs |
| `rules` | | Comma-separated rule IDs to include |
| `exclude-rules` | | Comma-separated rule IDs to skip |
| `ignore-paths` | | Comma-separated paths to exclude |
| `config` | | Path to `.agent-audit-kit.yml` |

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings |
| `critical-count` | Count of CRITICAL findings |
| `high-count` | Count of HIGH findings |
| `sarif-file` | Path to SARIF output file |
| `exit-code` | 0 = pass, 1 = findings exceed threshold |

---

## SARIF Integration

This action **emits** SARIF (the `sarif-file` output); it does **not** upload to
Code Scanning itself. Add the canonical `github/codeql-action/upload-sarif` step
so findings appear in the **Security tab** and as **inline PR annotations**:

```yaml
permissions:
  security-events: write   # required for the upload
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: sattyamjjain/agent-audit-kit@v0.3.94
    id: scan
    with:
      fail-on: high
  - uses: github/codeql-action/upload-sarif@v3
    if: always()           # upload even when the scan step failed the build
    with:
      sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

SARIF output conforms to [SARIF 2.1.0](https://json.schemastore.org/sarif-2.1.0.json)
with `fingerprints`, `partialFingerprints`, `security-severity` scores, and
`%SRCROOT%` relative paths. Each finding carries **OWASP references** and **CVE
links** via the rule-level `help`; per-finding remediation is in result
`properties`. (No SARIF `fixes[]` — those require machine-applicable
`artifactChanges`, so emitting prose there would make Code Scanning reject the
upload.)

---

## Security Scoring

```bash
agent-audit-kit score .
# Security Score: 85/100  Grade: B
```

| Grade | Score | Meaning |
|:-----:|:-----:|---------|
| A | 90-100 | Excellent — minimal risk |
| B | 75-89 | Good — minor issues |
| C | 60-74 | Fair — needs attention |
| D | 40-59 | Poor — significant risk |
| F | 0-39 | Critical — immediate action required |

Generate an SVG badge for your README: `agent-audit-kit score . --badge`

---

## Frameworks & Standards

| Framework | Coverage |
|-----------|----------|
| **OWASP Agentic Top 10** (ASI01-ASI10) | 10/10 (100%) — density by slot below |
| **OWASP MCP Top 10** (MCP01-MCP10) | 10/10 (100%) |
| **OWASP Agentic Skills Top 10** (AST01-AST10) | 6/10 (60%) — partial by design, [see below](#owasp-agentic-skills-top-10-ast10) |

### Public OWASP coverage leaderboard

Category-by-category coverage tables — every OWASP slot mapped to the exact AAK
rule IDs that cover it — are generated from the live rule registry so they
cannot drift (CI regenerates and fails on staleness, `scripts/gen_coverage.py`):

- **[OWASP Agentic Top 10 → AAK rules](docs/coverage/owasp-agentic-top10.md)**
- **[OWASP MCP Top 10 → AAK rules](docs/coverage/owasp-mcp-top10.md)**

### OWASP Agentic Skills Top 10 (AST10)

[AST10](https://owasp.org/www-project-agentic-skills-top-10/) is an OWASP
**incubator** project whose v1 is in public review — a different maturity from the
two tables above, and worth knowing before you cite it. It covers the *skill*
layer: in the project's own words, "MCP = how the model talks to tools; AST10 =
what those tools actually do."

**Coverage is partial on purpose.** A rule ships here only where a static check
over a skill bundle gives a deterministic answer. Three of the ten need runtime
evidence, and no rule that guesses is worth the finding it produces.

| AST10 category | Covered | By |
|---|---|---|
| **AST01** Malicious Skills | Yes | `AAK-SKILL-001/002/003/004`, `AAK-POISON-001..006` |
| **AST02** Supply Chain Compromise | Yes | `AAK-AST02-001` — an external resource nothing pins |
| **AST03** Over-Privileged Skills | Yes | `AAK-COMPOSE-003` — manifest narrower than the code it ships |
| **AST04** Insecure Metadata | Yes | `AAK-AST04-001` (parsing layer: a deserialization tag that runs before any field is read) + `AAK-SKILL-005` (semantic layer) |
| **AST05** Untrusted External Instructions | Yes | `AAK-SKILL-005`, `AAK-POISON-002`, `AAK-COMPOSE-001` |
| **AST06** Weak Isolation | **No** | Whether a skill is sandboxed is a property of the runtime that loads it, not of anything in the bundle. A static scan cannot see the container, the seccomp profile, or the process the agent actually spawned. |
| **AST07** Update Drift | **Partial** | `AAK-AST02-001` covers the pinning half — a bundle pinned to a moving ref. Detecting that a *deployed* skill has drifted from its known-good version needs the deployed copy and a baseline, which a repository scan does not have. |
| **AST08** Poor Scanning | **No** | This is a risk about the registry's process, not about the skill. There is nothing in a bundle that reports whether the marketplace scanned it. |
| **AST09** No Governance | **No** | Organisational: approval workflows, ownership, review policy. Not a property of any file. |
| **AST10** Cross-Platform Reuse | Yes | `AAK-AST10-001` — security metadata present in one platform manifest and lost or weakened in another |

So: **6 of 10 fully, 1 partially, 3 not at all.** The three are not a backlog —
they are outside what a static scanner can answer, and a rule claiming them would
be reporting a guess.

Every rule in the family carries a `limitations` field stating what it cannot see;
`agent-audit-kit rule AAK-AST02-001` prints it.

### Coverage, mapped to frameworks

One command emits the full per-rule crosswalk — every rule's `id`, `title`,
`severity`, the **CVE(s)** it covers, and its **OWASP MCP Top-10**, **OWASP
Agentic Top-10 (2026)**, **NSA MCP Security CSI** (U/OO/6030316-26), and **EU AI
Act** article — grouped and counted by framework, straight from the rule
registry (no hand-typed numbers):

```bash
agent-audit-kit --emit-coverage --format json   # machine-readable (== docs/coverage.json)
agent-audit-kit --emit-coverage --format md      # human table
```

- **Machine-readable:** [`docs/coverage.json`](docs/coverage.json) — per-rule rows
  + framework roll-ups + reserved slots for the 2026-07-28 MCP-final surfaces.
- **Human report seed:** [`docs/STATE-OF-MCP-SECURITY-2026.md`](docs/STATE-OF-MCP-SECURITY-2026.md)
  — the coverage table plus the "we scanned N public MCP servers, here's what
  breaks" corpus section.

Coverage labels use a published threshold (**Full** = ≥3 rules, **Partial** =
1–2, **None** = 0) — reproducible from the registry, not a self-scored grade.
The [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
(2026-04-02) states 10/10 Agentic coverage as a *runtime* enforcer; AAK reports
its honest per-category **static** rule counts next to it — a coverage
cross-reference, not a head-to-head benchmark.

<details>
<summary>OWASP Agentic Top 10 — density by slot</summary>

<!-- owasp-coverage:start -->
| ASI | Title | # rules |
| --- | --- | --- |
| **ASI01** | Goal Hijack | 14 |
| **ASI02** | Tool Misuse | 48 |
| **ASI03** | Memory Poisoning | 73 |
| **ASI04** | Identity & Privilege Abuse | 68 |
| **ASI05** | Cascading Failures | 54 |
| **ASI06** | Unauthorized Capability Acquisition | 47 |
| **ASI07** | Plan Injection | 9 |
| **ASI08** | Agent Communication Poisoning | 5 |
| **ASI09** | Resource Abuse | 18 |
| **ASI10** | Supply-Chain | 21 |
<!-- owasp-coverage:end -->

</details>

| **Adversa AI MCP Security Top 25** | Fully mapped |
| **EU AI Act** | `--compliance eu-ai-act` |
| **SOC 2 Type II** | `--compliance soc2` |
| **ISO 27001:2022** | `--compliance iso27001` |
| **HIPAA Security Rule** | `--compliance hipaa` |
| **NIST AI RMF 1.0** | `--compliance nist-ai-rmf` |
| **MCP 2026 Roadmap (May 2026)** | `--compliance mcp-2026-roadmap` |

---

## Tool Pinning & Rug Pull Detection

MCP servers can silently change tool definitions after you approve them. AgentAuditKit detects this:

```bash
# Create initial pins (commit tool-pins.json to git)
agent-audit-kit pin .

# In CI, verify nothing changed
agent-audit-kit verify .
```

Detects: tool definitions changed (AAK-RUGPULL-001), new tools added (AAK-RUGPULL-002), tools removed (AAK-RUGPULL-003).

---

## Auto-PR for mechanical fixes

```bash
agent-audit-kit scan . --format sarif -o run.sarif
agent-audit-kit suggest run.sarif --auto-pr --dry-run   # see the plan
agent-audit-kit suggest run.sarif --auto-pr             # open a draft PR
```

Off by default, and deliberately narrow:

- **Allow-listed rules only.** If any pending fix is for a rule outside `AUTO_PR_ALLOWLIST`, the whole run refuses rather than opening a partial PR. The allow-list is an explicit literal, not `auto_fixable` — marking a new rule auto-fixable does not, on its own, make AAK push it.
- **Draft, never merged.** A mechanical edit nobody reviewed is a diff, not a decision.
- **No credentials.** Delivery runs through your existing `gh auth`. AAK never asks for, stores, or reads a token, so it cannot exceed the access you already granted `gh`.
- **Refuses on a dirty tree**, so your uncommitted work is never swept into its branch.

Fixes whose correct form depends on how the project is deployed or wired — adding an auth dependency to a route, rewriting a quoted shell string as a parameterised call, flipping a bind address off `0.0.0.0` — are reported but never auto-edited. The PR body says so too.

---

## Comparison

See [`docs/comparisons.md`](docs/comparisons.md) for a fully-sourced version. Verifiable claims only.

| Feature | AgentAuditKit | Microsoft AGT | Snyk Agent Scan | Semgrep Multimodal |
|---------|:---:|:---:|:---:|:---:|
| Scope | Static scanner + compliance PDFs | Runtime governance | Static + runtime | Multimodal SAST |
| Detection rules (static) | **<!-- rule-count:total -->332<!-- /rule-count -->** | Runtime policies, not rules | ~30 | LLM-assisted |
| OWASP Agentic 10/10 | **Yes** | Yes | Partial | Partial |
| OWASP MCP 10/10 | **Yes** | No (runtime-focused) | No | No |
| Auditor-ready PDF compliance | **12 frameworks** | No | 0 | 0 |
| Regional frameworks (IN/SG/AL/TN) | **Yes** | No | No | No |
| Sigstore-signed rule bundle | **Yes** | SLSA provenance | No | No |
| CycloneDX + SPDX SBOM output | **Yes** | No | No | No |
| Public CVE-response ledger | **Yes** | No | No | No |
| Public grade leaderboard | **Yes** (MCP Security Index) | No | No | No |
| Pin + drift verification | **Yes** | Yes (runtime rings) | No | No |
| Auto-fix CVE dependency bumps | **Yes** (`fix --cve`) | No | No | No |
| GitHub Security Advisories | **Yes** (`--advisories`) | No | No | No |
| Secret verification | **Yes** | No | No | No |
| A2A protocol scanning | **<!-- category-count:A2A_PROTOCOL -->13<!-- /category-count --> rules** | Agent Mesh | No | No |
| Reproducible finding set (same input → same digest) | **[Yes — 20/20 runs, 0% variance](benchmarks/determinism/RESULTS.md)** | Runtime governance | LLM-judge in path | LLM-assisted |
| Healthcare-AI legal triggers | **Yes** (TN SB 1580, KS/WA/UT) | No | No | No |
| Offline / zero cloud | **Yes** | Yes | No | Optional |
| License | **MIT** | MIT | Proprietary | Proprietary |

**Microsoft AGT is an ally, not a competitor.** It governs agents at
runtime; agent-audit-kit audits them at CI time and produces the PDF an
auditor needs. Use both — the overlap is small, the reinforcement is
high. See [docs/comparisons.md](docs/comparisons.md) for the full
positioning write-up.

---

## VS Code Extension

A VS Code/Cursor extension is available in `vscode-extension/`:

```bash
cd vscode-extension && npm install && npm run compile
```

Provides inline diagnostics on file save with quick-fix suggestions.

---

## MCP Security Index

Public leaderboard of MCP servers, published at
**[sattyamjjain.github.io/agent-audit-kit](https://sattyamjjain.github.io/agent-audit-kit/)**.

<!-- index-cadence -->Last published snapshot: **2026-08-31** (4 snapshots in [`history.json`](https://sattyamjjain.github.io/agent-audit-kit/data/history.json)). The build fails if this date falls more than 10 days behind, so a stalled index reports itself.<!-- /index-cadence -->

> **On the schedule.** The Monday crawl was dying on `HTTP 429` — the status the
> GitHub Search API returns for a secondary rate limit, and the one its retry path
> did not handle — so every scheduled run from 2026-06-15 failed except 2026-07-20.
> Two months passed unnoticed because a failing scheduled run notified nobody.
> Fixed in v0.3.86: it backs off on 429, keeps a partial crawl under a wall-clock
> budget rather than being killed with nothing, records `partial` and the reason in
> the artifact, and files an issue when a scheduled run fails. The trend chart was
> a second, separate fault — the site build removed its output directory before
> reading the previous `history.json`, so every published history in this project's
> life had held exactly one snapshot and "need >= 2" was unsatisfiable by
> construction.
>
> Both are now verified by real runs rather than by manual dispatch: the scheduled
> run on **2026-08-24** landed and published, and the history holds enough
> snapshots for the chart to render. That is one scheduled success since the fix,
> not a demonstrated cadence, so this page states the last snapshot date above
> rather than promising a frequency — and `scripts/index_cadence.py --check` fails
> the build if that date falls more than 10 days behind, which is one tolerated
> miss and no more.

- Per-server grade cards (A–F)
- Snapshots at [`history.json`](https://sattyamjjain.github.io/agent-audit-kit/data/history.json) on the published index site (generated by `benchmarks/index_builder.py`; not a path in this repository). A snapshot cut short by the API budget is recorded with `partial: true` and the reason, so a short week is never read as a full one
- **90-day coordinated disclosure** before anything lands on a public card — see [`docs/disclosure-policy.md`](docs/disclosure-policy.md)
- Maintainer-fix earlier gets published the day the fix lands, with credit

## State of MCP Security 2026

A reproducible data report over **2,303 distinct public MCP server configs** — a
GitHub crawl plus **1,641 official MCP Registry latest-version servers** (up 2.3×
from 710 in July as the registry grew), deduped by content and scanned offline and
deterministically (scan date **2026-07-26**). Headline: **<!-- report:noauth-pct -->52.1<!-- /report -->% (<!-- report:noauth-n -->1,200<!-- /report -->/2,303) declare
a remote server with no authentication, 0% use RFC 9728 Protected-Resource-Metadata
discovery, 100% (421/421) of inline-auth configs hardcode a static credential, and
19.5% `npx`/`uvx`-fetch-and-execute unpinned remote packages** (the Shai-Hulud
supply-chain blast radius, one `.mcp.json` away). 52.8% carry a critical finding.

Full method, per-metric findings (each with n + denominator), the two defensible
wedges (offline/deterministic scanning + a NSA-MCP-CSI / OWASP-Agentic
compliance-evidence crosswalk), market backdrop, and limitations:
**[`research/state-of-mcp-2026/REPORT.md`](research/state-of-mcp-2026/REPORT.md)**
(+ [PDF](research/state-of-mcp-2026/state-of-mcp-security-2026.pdf)) — raw aggregate
[`results.json`](research/state-of-mcp-2026/results.json), corpus provenance
[`registry-manifest.json`](research/state-of-mcp-2026/corpus/registry-manifest.json).

**Citing it.** The report is **version 1.0** (published 2026-08-17, scan date
2026-07-26) and has a stable identity so a number in it can be referenced:
[how to cite](research/state-of-mcp-2026/REPORT.md#how-to-cite-this-report) gives a
plain-text and a BibTeX form, and [`CITATION.cff`](CITATION.cff) carries the same
identity for GitHub's "Cite this repository" widget. The
[NSA-CSI / OWASP-Agentic crosswalk](docs/crosswalk/nsa-csi-owasp-agentic.md) links to
it too: the crosswalk says what the controls are, the report says how often they are
met.

The harness contains no scanner — it reuses `agent_audit_kit.engine.run_scan` +
`scoring.compute_score`, so every number is reproducible offline and cannot drift
from the code (`make report` regenerates `results.json` from the committed
manifest; the corpus refresh is the one network step, `fetch_registry.py`):

```bash
make report   # regenerate the report numbers, offline + deterministic
```

### Frozen baseline (pre-2026-07-28-spec)

The same measurement, **frozen and citable** as
**[`docs/research/mcp-security-baseline-v1.0.md`](docs/research/mcp-security-baseline-v1.0.md)**:
an immutable, byte-deterministic snapshot
([`mcp-security-baseline-v1.0-2026-07-27.json`](research/state-of-mcp-2026/baseline/mcp-security-baseline-v1.0-2026-07-27.json))
recording, per config and in aggregate, the corpus size + collection window, the
auth-posture distribution (no-auth / bearer / OAuth 2.1 / unknown), the transport
distribution, the per-rule HIGH/CRITICAL hit counts, and the benign-slice
false-positive rate with its denominator — tamper-evident under
**SHA-256 `320b43072d930edbc18f050795939dbee3831e4da2f88b3483ea12ec7bb6551f`**. It
is the **pre-2026-07-28-spec** reference. It is a fixed point to compare against,
not a promise of a next edition: the comparison is one command, runs offline
against the current corpus, and is the reason no re-measure date is advertised
here — a date would expire, this does not. Last run 2026-08-24, and it reports
real movement on every axis, corpus size and `AAK-MCP-001` hit count included:

```bash
python research/state-of-mcp-2026/baseline.py \
    --compare research/state-of-mcp-2026/baseline/mcp-security-baseline-v1.0-2026-07-27.json
```

Scan your own in 30s, fully offline: `pip install agent-audit-kit && agent-audit-kit scan .`
See which AAK rules cover each OWASP MCP slot in the
[public coverage leaderboard](docs/coverage/owasp-mcp-top10.md).

## CVE Response

AgentAuditKit tracks newly disclosed MCP CVEs and ships rule coverage on a best-effort basis, recorded in a public ledger ([`CHANGELOG.cves.md`](CHANGELOG.cves.md)). A [GitHub Action](.github/workflows/cve-watcher.yml) watches NVD's MCP keyword feed every 6 hours and files a tracking issue for each new disclosure.

> **`aak watch-cve` is experimental — exactly one live feed.** The CLI poller ships one live feed, `nvd` (the NVD 2.0 API); its network call is opt-in behind `--online`, so a default run reads an on-disk cache and never touches the network. The other four feeds (`ox`, `cert-cc`, `thaicert`, `ironplate`) are unimplemented stubs that print `feed <id>: not implemented`; the command exits 0 when at least one requested feed polls cleanly and non-zero when every requested feed is a stub. The automated CVE tracking above runs through the `cve-watcher.yml` GitHub Action, not that command. (`aak watch`, the pinned-tool drift monitor, is a separate, functional command.)

## Supply chain

Every `v*` release publishes:

- **Wheel + sdist** on PyPI via OIDC Trusted Publisher
- **Docker image** on GHCR (`ghcr.io/sattyamjjain/agent-audit-kit:<tag>`) with SLSA provenance attestation. Provenance is attached by the release flow, so it covers **version tags**; the nightly rebuild that refreshes `:latest` and `:nightly` scans the image with Trivy but attaches no attestation, so pin a version tag if you need provenance
- **Sigstore keyless-signed rule bundle** (`rules.json` + `rules.json.sha256`)
- **CycloneDX + SPDX SBOM** (`sbom.cdx.json`, `sbom.spdx.json`)

Verify a bundle:

```bash
agent-audit-kit verify-bundle rules.json --signature rules.json.sigstore
```

---

## Contributing

```bash
git clone https://github.com/sattyamjjain/agent-audit-kit
cd agent-audit-kit
pip install -e ".[dev]"
pytest -v                          # <!-- test-count:total -->2,135<!-- /test-count --> test functions
ruff check .                       # Lint
mypy agent_audit_kit/              # Type check
agent-audit-kit scan .             # Self-scan
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development guide.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/sattyamjjain/agent-audit-kit/security/advisories) or see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
