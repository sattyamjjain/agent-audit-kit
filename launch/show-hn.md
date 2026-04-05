# Show HN Post

## Title
Show HN: AgentAuditKit – 77-rule security scanner for MCP agent pipelines (OSS)

## URL
https://github.com/sattyamjjain/agent-audit-kit

---

## First Comment (post immediately after submission)

I built AgentAuditKit because 30 MCP-related CVEs dropped in 60 days earlier this year and there was no equivalent of `npm audit` or `trivy scan` for AI agent configurations.

MCP (Model Context Protocol) is the standard that Claude Code, Cursor, VS Code Copilot, Windsurf, and most AI coding assistants use to connect to external tools. A single misconfigured `enableAllProjectMcpServers: true` flag (CVE-2026-21852) was enough to exfiltrate your entire source code to an attacker-controlled server.

AgentAuditKit scans project-level configs for:

- Hardcoded API keys (Anthropic, OpenAI, AWS, GitHub, GCP) with real Shannon entropy detection
- Shell injection in MCP server commands
- Tool poisoning via invisible Unicode characters in tool descriptions
- "Rug pull" detection — MCP servers silently changing tool definitions after approval (SHA-256 pinning)
- Trust boundary violations (wildcard permissions, missing deny rules)
- Tainted data flows in Python @tool functions via AST analysis (not regex)

Technical details that might interest HN:

- The taint analysis walks the Python AST to track parameter flow from @tool-decorated functions to dangerous sinks (eval, subprocess, SQL, file I/O). This catches real injection paths, not just pattern matches.
- Tool pinning hashes tool definitions (name + description + input schema) with SHA-256. Pin once, verify in CI — detects if a server changes behavior after your initial review.
- SARIF 2.1.0 output with fingerprints for GitHub Code Scanning integration — findings show as inline PR annotations.
- Maps every rule to OWASP Agentic Top 10 (10/10) and OWASP MCP Top 10 (10/10).

It's MIT licensed, runs fully offline (zero network calls in the scan path), and the only runtime dependencies are click and pyyaml. 441 tests at 90% coverage.

Install: `pip install agent-audit-kit && agent-audit-kit scan .`

GitHub Action: `uses: sattyamjjain/agent-audit-kit@v0.2.0`

Happy to answer questions about the threat model, the taint analysis approach, or MCP security in general.
