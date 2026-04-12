# OWASP Working Group Outreach

## Email 1: OWASP Agentic Top 10 Working Group

**To:** agentic-top10@owasp.org (or via https://genai.owasp.org/ contact form)
**Subject:** Open-source scanner implementing all 10 OWASP Agentic Top 10 risks

Hi,

I built AgentAuditKit — an open-source security scanner (MIT licensed) that maps detection rules to all 10 risks in the OWASP Agentic Top 10.

77 rules across 13 scanners cover:
- ASI01 (Goal Hijack) → AGENTS.md/.cursorrules/.CLAUDE.md scanning for prompt injection
- ASI02 (Tool Misuse) → Python AST taint analysis tracking @tool params to dangerous sinks
- ASI03 (Identity & Privilege Abuse) → Trust boundary violations, credential exposure
- ASI04 (Supply Chain) → Unpinned packages, known vulnerable deps, rug pull detection
- ASI05 (Unexpected Code Execution) → Shell injection in MCP commands, hook injection
- ASI06 (Memory & Context Poisoning) → Tool description poisoning via invisible Unicode
- ASI07 (Inter-Agent Communication) → A2A protocol scanning, JWT validation
- ASI08 (Cascading Failures) → Excessive server count, dependency chain analysis
- ASI09 (Human-Agent Trust) → Trust boundary overrides, missing deny rules
- ASI10 (Rogue Agents) → enableAllProjectMcpServers, ANTHROPIC_BASE_URL redirect

It runs as a GitHub Action, CLI, or pre-commit hook. SARIF output integrates with GitHub Code Scanning.

GitHub: https://github.com/sattyamjjain/agent-audit-kit
Marketplace: https://github.com/marketplace/actions/agentauditkit-mcp-security-scan

Would the working group be interested in listing this as an implementation tool? Happy to contribute documentation mapping each rule to specific Agentic Top 10 risks.

Best,
Sattyam Jain
https://github.com/sattyamjjain

---

## Email 2: OWASP MCP Top 10 Working Group

**To:** Via https://owasp.org/www-project-mcp-top-10/ contact or GitHub issues
**Subject:** Open-source scanner with full MCP01-MCP10 rule coverage

Hi,

I built AgentAuditKit, an open-source (MIT) security scanner for MCP-connected AI agent pipelines. It maps 77 detection rules to all 10 risks in the OWASP MCP Top 10:

- MCP01 (Token Mismanagement) → 16 rules detecting hardcoded secrets across Anthropic/OpenAI/AWS/GitHub/GCP keys
- MCP02 (Context Over-Sharing) → Excessive server count, overly broad permissions
- MCP03 (Supply Chain) → 11 rules for unpinned packages, known vulns, dangerous install scripts
- MCP04 (Command Injection) → 15 rules for shell expansion, hook injection, headersHelper abuse
- MCP05 (Tool Poisoning) → 17 rules including invisible Unicode, prompt injection, rug pull detection (SHA-256 pinning)
- MCP06 (Privilege Escalation) → Sudo in hooks, filesystem root access, trust boundary violations
- MCP07 (Insufficient Auth) → Remote MCP servers without authentication headers
- MCP08 (Audit Logging) → Missing deny rules, excessive unaudited hooks
- MCP09 (Protocol Vulnerabilities) → HTTP endpoints, disabled TLS, deprecated SSE, tokens in URLs
- MCP10 (Insecure Plugin/Extension) → npx/uvx runtime fetch, known vulnerable MCP packages

It scans 13 agent platforms (Claude Code, Cursor, VS Code Copilot, Windsurf, Amazon Q, Gemini CLI, Goose, Continue, Roo Code, Kiro) and outputs SARIF 2.1.0 for GitHub Code Scanning integration.

GitHub: https://github.com/sattyamjjain/agent-audit-kit

Would the project be interested in referencing this as an implementation tool? I'm also happy to contribute to the MCP Top 10 documentation.

Best,
Sattyam Jain
https://github.com/sattyamjjain

---

## Discord Messages

### LangChain Discord (#general or #showcase)

Hey everyone — I built an open-source security scanner for MCP agent configs. 77 rules that catch hardcoded secrets, shell injection, tool poisoning (invisible Unicode in tool descriptions), and rug pull attacks.

If you're using MCP tools with LangChain/LangGraph, it also does Python AST taint analysis on `@tool` functions — tracks parameter flow to dangerous sinks like eval, subprocess, SQL.

One-line GitHub Action: `uses: sattyamjjain/agent-audit-kit@v0.2.0`
CLI: `pip install agent-audit-kit && agent-audit-kit scan .`

GitHub: https://github.com/sattyamjjain/agent-audit-kit

### CrewAI Discord (#showcase or #tools)

Built an open-source security scanner for AI agent pipelines — specifically catches misconfigurations in MCP server configs, tool poisoning via invisible Unicode, and tainted data flows in `@tool` decorated functions.

If you're building CrewAI tools that use MCP, this scans your configs for hardcoded keys, shell injection, and supply chain risks before deployment.

`pip install agent-audit-kit && agent-audit-kit scan .`

GitHub: https://github.com/sattyamjjain/agent-audit-kit
