# We Scanned 47 Public MCP Server Configs on GitHub. Here's What We Found.

> **TL;DR**: We used AgentAuditKit to scan 47 real `.mcp.json` files from public GitHub repositories. We found **258 security findings** across them — 13 critical, 87 high severity. The #1 issue? **Every single config using npx/uvx had unpinned packages** — a supply chain attack waiting to happen.

---

## Why We Did This

In early 2026, [30 MCP-related CVEs dropped in 60 days](https://www.heyuan110.com/posts/ai/2026-03-10-mcp-security-2026/). CVE-2026-21852 demonstrated source code exfiltration via a single config flag. CVE-2026-32211 (CVSS 9.1) hit Azure MCP servers.

MCP is now the default protocol for AI coding assistants — Claude Code, Cursor, VS Code Copilot, Windsurf, Amazon Q, and Gemini CLI all support it. But there's been zero standard tooling for auditing MCP configurations.

We built [AgentAuditKit](https://github.com/sattyamjjain/agent-audit-kit) to fill that gap. To validate it works on real configs, we crawled GitHub for public `.mcp.json` files and scanned them.

## Methodology

We used AgentAuditKit's built-in benchmark crawler (`benchmarks/crawler.py`) to:

1. Search the GitHub API for public `.mcp.json` files containing `mcpServers`
2. Download 47 valid JSON configs from distinct repositories (3 were non-JSON templates)
3. Run all 77 rules across 13 scanner modules against each config
4. Aggregate the findings by severity and category

The scan ran fully offline — zero network calls during analysis.

```bash
# Reproduce this yourself
git clone https://github.com/sattyamjjain/agent-audit-kit
cd agent-audit-kit
pip install -e .
GITHUB_TOKEN=$(gh auth token) python benchmarks/crawler.py --limit 50 --output benchmarks/results.json --verbose
```

## Top-Level Results

| Metric | Value |
|--------|-------|
| Configs scanned | **47** |
| Total findings | **258** |
| Critical findings | **13** (5.0%) |
| High findings | **87** (33.7%) |
| Medium findings | **87** (33.7%) |
| Low findings | **71** (27.5%) |
| Configs with hardcoded secrets | **0%** (good news!) |
| Configs with `enableAllProjectMcpServers` | **2.1%** (1 config) |
| Configs with remote servers lacking auth | **23.4%** (11 configs) |
| Average findings per config | **5.5** |

## Top 10 Most Common Violations

| # | Rule | Title | Count | Severity |
|---|------|-------|------:|----------|
| 1 | AAK-SUPPLY-001 | MCP server package not pinned to exact version | **71** | HIGH |
| 2 | AAK-MCP-005 | MCP server uses npx/uvx to fetch and execute remote packages | **71** | MEDIUM |
| 3 | AAK-MCP-007 | MCP server lacks version pinning in args | **71** | LOW |
| 4 | AAK-MCP-006 | MCP server command uses relative path | **15** | MEDIUM |
| 5 | AAK-MCP-001 | Remote MCP server without authentication | **11** | CRITICAL |
| 6 | AAK-MCP-003 | MCP server environment exposes secrets | **8** | HIGH |
| 7 | AAK-MCP-009 | MCP server URL points to localhost/internal network | **7** | HIGH |
| 8 | AAK-MCP-002 | MCP server command runs with shell expansion | **2** | CRITICAL |
| 9 | AAK-MCP-010 | MCP server config allows arbitrary filesystem root access | **1** | HIGH |
| 10 | AAK-TRANSPORT-003 | Deprecated SSE transport in use | **1** | MEDIUM |

## Deep Dives

### Finding 1: The Supply Chain Epidemic (71 violations)

The most pervasive issue by far. **Every single config that uses `npx` or `uvx` to run MCP servers had unpinned packages.** This means:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "/home/user/project"]
    }
  }
}
```

Without a version pin (`@1.2.3`), every time this runs, it fetches *whatever version is current on npm*. If an attacker compromises the package or publishes a typosquatted version, your MCP server silently becomes malicious. This is exactly how the `postmark-mcp` typosquat attack worked — it built trust over 15 versions before injecting malware.

**Fix**: Always pin versions: `"@modelcontextprotocol/server-filesystem@1.2.3"`

### Finding 2: Remote Servers Without Authentication (11 configs)

23.4% of configs had remote MCP servers (URLs) without any authentication headers. Anyone who can reach these servers can invoke their tools.

```json
{
  "mcpServers": {
    "api": {
      "url": "http://mcp-server.example.com:3000/sse"
    }
  }
}
```

No `Authorization` header, no API key, no auth at all. This mirrors the exact pattern behind CVE-2026-32211, where the Azure MCP Server's unauthenticated access exposed API keys, tokens, and DevOps data.

**Fix**: Always require authentication headers on remote MCP servers.

### Finding 3: Secrets in Environment Blocks (8 configs)

8 configs had secret-like values hardcoded in their MCP server environment blocks — database URLs with passwords, API tokens, and credential strings.

```json
{
  "env": {
    "DATABASE_URL": "postgresql://admin:p4ssw0rd@db.prod.internal:5432/main"
  }
}
```

**Fix**: Use environment variable references: `"DATABASE_URL": "${DATABASE_URL}"`

### Finding 4: enableAllProjectMcpServers (1 config)

One config had the flag that made CVE-2026-21852 possible. When `enableAllProjectMcpServers: true`, any `.mcp.json` in a cloned repository can silently register MCP servers — meaning a malicious repo can inject attacker-controlled tools into your AI assistant.

The good news: only 2.1% of configs had this enabled. The bad news: it only takes one.

## What You Should Do

1. **Scan your MCP configs now**: `pip install agent-audit-kit && agent-audit-kit scan .`
2. **Add it to CI/CD**: Use our [GitHub Action](https://github.com/sattyamjjain/agent-audit-kit) to catch misconfigurations before they merge
3. **Pin your MCP packages**: Add `@version` to every npx/uvx package reference
4. **Use `agent-audit-kit pin`**: Creates SHA-256 hashes of tool definitions; `agent-audit-kit verify` detects rug pulls in CI
5. **Never commit API keys**: Use environment variable references (`${VAR}`) in MCP configs
6. **Set `enableAllProjectMcpServers: false`**: Always.

## Methodology Notes

- All repos were public at the time of crawling (April 12, 2026)
- No credentials or sensitive data from the scanned repos is disclosed in this post
- Repository names are included as they are public
- The crawler respects GitHub API rate limits
- Results are fully reproducible using the open-source crawler

## Try It Yourself

```bash
pip install agent-audit-kit
agent-audit-kit scan .
```

GitHub: [sattyamjjain/agent-audit-kit](https://github.com/sattyamjjain/agent-audit-kit)

---

*AgentAuditKit is MIT licensed, runs fully offline, and the only runtime dependencies are click and pyyaml. 77 rules, 13 scanners, 452 tests at 90% coverage.*
