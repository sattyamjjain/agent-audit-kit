# r/netsec Post

**Title:** I built an open-source scanner that finds security misconfigurations across 13 AI agent platforms — here's what 77 rules catch

**Body:**

I've been digging into the security surface of MCP (Model Context Protocol) — the standard that Claude Code, Cursor, VS Code Copilot, Windsurf, and most AI coding assistants use to connect to external tools.

The short version: it's a mess. 30 CVEs in 60 days. `enableAllProjectMcpServers: true` was enough for full source code exfiltration (CVE-2026-21852). Most MCP servers ship with zero authentication. Tool descriptions can contain invisible Unicode that hijacks agent behavior without anyone noticing.

So I built AgentAuditKit — a static security scanner specifically for MCP agent configurations.

**What it actually detects (77 rules across 13 scanners):**

- Remote MCP servers without auth headers
- Shell injection in server commands (`sh -c`, pipes, backticks)
- Hardcoded API keys with real Shannon entropy detection (not just regex)
- Tool poisoning via invisible Unicode in tool descriptions (zero-width joiners, RTL override)
- "Rug pull" attacks — servers silently changing tool definitions after approval (SHA-256 pinning)
- Trust boundary violations (`enableAllProjectMcpServers`, wildcard permissions, missing deny rules)
- Taint analysis via Python AST — tracks `@tool` function parameters to dangerous sinks (eval, subprocess, SQL, file I/O)
- A2A (Agent-to-Agent) protocol issues — Agent Card auth, JWT validation, impersonation risk

**OWASP coverage:**
- Agentic Top 10: 10/10
- MCP Top 10: 10/10
- Adversa AI Top 25: fully mapped

Runs fully offline, zero network calls in the scan path. SARIF 2.1.0 output for GitHub Code Scanning integration.

GitHub: https://github.com/sattyamjjain/agent-audit-kit

`pip install agent-audit-kit && agent-audit-kit scan .`

Happy to discuss the threat model or specific attack vectors if anyone's interested.
