# OWASP Working Group Outreach

## Email 1: OWASP Agentic Top 10 Working Group

**To:** agentic-top10@owasp.org (or via https://genai.owasp.org/ contact form)
**Subject:** Open-source scanner with rules for all 10 OWASP Agentic Top 10 risks

Hi,

I built AgentAuditKit — an open-source security scanner (Apache-2.0 licensed) that maps detection rules to all 10 risks in the OWASP Top 10 for Agentic Applications (Version 2026).

438 rules across 109 scanners cover:
- ASI01 (Agent Goal Hijack) → injection and download-and-run directives in AGENTS.md / CLAUDE.md / .cursorrules, known indirect-injection payloads, PR titles fed straight to an LLM
- ASI02 (Tool Misuse and Exploitation) → poisoned tool descriptions, SSRF and path traversal through tool arguments, over-broad tool permissions, source-plus-sink tool chains
- ASI03 (Identity and Privilege Abuse) → hardcoded keys and tokens, missing or fail-open auth on MCP servers, OAuth flaws, token passthrough
- ASI04 (Agentic Supply Chain Vulnerabilities) → unpinned and runtime-fetched packages, typosquats, known-vulnerable MCP server versions, tool definitions that change after approval
- ASI05 (Unexpected Code Execution (RCE)) → @tool parameters reaching shell, eval or deserialization (Python AST taint analysis), shell expansion in MCP server commands, hooks and IDE tasks that run on open
- ASI06 (Memory & Context Poisoning) → unauthenticated agent-memory APIs, another user's chat history or vector-store rows reachable, shared multi-agent state with no lock
- ASI07 (Insecure Inter-Agent Communication) → A2A cards with no auth or replay protection, cleartext and TLS-off MCP transports, transport downgrade to stdio
- ASI08 (Cascading Failures) → unbounded A2A delegation, relayed trust, uncapped task queues and tool catalogues. Mostly the missing guardrail, not the cascade itself
- ASI09 (Human-Agent Trust Exploitation) → auto-approve and headless modes that drop the confirmation step, approval checks that approve a different command than the one that runs
- ASI10 (Rogue Agents) → unattended routines with wider permissions or no audit trail, sandbox switches the model can set, agent cards that can be impersonated

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
**Subject:** Open-source scanner with rules for every OWASP MCP Top 10 entry

Hi,

I built AgentAuditKit, an open-source (Apache-2.0) security scanner for MCP-connected AI agent pipelines. Its 438 detection rules map to all 10 risks in the OWASP MCP Top 10 (v0.1), some much more thinly than others:

- MCP01 (Token Mismanagement & Secret Exposure) → hardcoded keys in MCP configs and env blocks, tokens in URLs and in logs
- MCP02 (Privilege Escalation via Scope Creep) → filesystem-root servers, wildcard tool permissions, command tools on by default, read-only-mode bypasses
- MCP03 (Tool Poisoning) → hidden Unicode, model-directed imperatives and encoded payloads in tool descriptions, plus rug-pull detection against SHA-256 pins
- MCP04 (Software Supply Chain Attacks & Dependency Tampering) → unpinned npx/uvx packages, missing lockfiles, install scripts, servers admitted with no signed provenance, known-vulnerable MCP server versions
- MCP05 (Command Injection & Execution) → tool arguments reaching shell, eval, SQL and file paths, shell expansion in server commands. Our SSRF rules sit here too, since MCP05 covers API requests built from untrusted input; I saw https://github.com/OWASP/www-project-mcp-top-10/issues/20 is still open on where SSRF belongs
- MCP06 (Intent Flow Subversion) → sampling with no consent gate, servers that relay injected content
- MCP07 (Insufficient Authentication & Authorization) → remote servers with no auth, fail-open auth, OAuth flaws, cleartext transport, DNS rebinding
- MCP08 (Lack of Audit and Telemetry) → one rule so far: forged log entries in MCP tool logs. Nothing yet detects a missing audit trail
- MCP09 (Shadow MCP Servers) → auto-approved project servers, no server allowlist, workspace servers that start before the trust prompt
- MCP10 (Context Injection & Over-Sharing) → cross-session and cross-tenant data access, task state with no expiry

It scans 11 agent platforms (Claude Code, Cursor, VS Code Copilot, Windsurf, Amazon Q, Gemini CLI, Goose, Continue, Roo Code, Kiro, ZCode) and outputs SARIF 2.1.0 for GitHub Code Scanning integration.

GitHub: https://github.com/sattyamjjain/agent-audit-kit

Would the project be interested in referencing this as an implementation tool? I'm also happy to contribute to the MCP Top 10 documentation.

I also just published a short data report from statically scanning 2,303 public MCP server configs, which found more than half expose a remote endpoint with no authentication: https://sattyamjjain.github.io/agent-audit-kit/docs/research/state-of-mcp-2026/REPORT/

Best,
Sattyam Jain
https://github.com/sattyamjjain

---

## Discord Messages

### LangChain Discord (#general or #showcase)

Hey everyone — I built an open-source security scanner for MCP agent configs. 438 detection rules that catch hardcoded secrets, shell injection, tool poisoning (invisible Unicode in tool descriptions), and rug pull attacks.

If you're using MCP tools with LangChain/LangGraph, it also does Python AST taint analysis on `@tool` functions — tracks parameter flow to dangerous sinks like eval, subprocess, SQL.

One-line GitHub Action: `uses: sattyamjjain/agent-audit-kit@v0.3.41`
CLI: `pip install agent-audit-kit && agent-audit-kit scan .`

GitHub: https://github.com/sattyamjjain/agent-audit-kit

### CrewAI Discord (#showcase or #tools)

Built an open-source security scanner for AI agent pipelines — specifically catches misconfigurations in MCP server configs, tool poisoning via invisible Unicode, and tainted data flows in `@tool` decorated functions.

If you're building CrewAI tools that use MCP, this scans your configs for hardcoded keys, shell injection, and supply chain risks before deployment.

`pip install agent-audit-kit && agent-audit-kit scan .`

GitHub: https://github.com/sattyamjjain/agent-audit-kit
