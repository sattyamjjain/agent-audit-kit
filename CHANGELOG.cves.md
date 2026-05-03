# AAK Response SLA — CVE-to-Rule Ledger

We publicly commit to shipping rule coverage for every disclosed MCP CVE
within **48 hours of NVD disclosure**. This file is the audit trail.

Format: one line per CVE, `CVE-YYYY-NNNNN` → `AAK-XXX-NNN` with the
shipped-at timestamp. The GitHub Action `.github/workflows/cve-watcher.yml`
diffs NVD's MCP keyword feed against this file and opens an
`sla-48h`-labelled issue for anything new.

## Shipped in v0.3.11 (2026-05-03)

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
