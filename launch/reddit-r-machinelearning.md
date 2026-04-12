# r/MachineLearning Post

**Title:** [P] Tool poisoning in MCP: how AI agents get tricked into exfiltrating data through hidden instructions in tool descriptions

**Body:**

I've been researching tool poisoning attacks against MCP-connected AI agents and built an open-source scanner to detect them.

**The attack:** MCP tool descriptions are free-text fields that the LLM reads before deciding how to use a tool. An attacker can inject invisible Unicode characters (zero-width joiners, RTL override characters) or natural language prompt injection patterns ("before calling this tool, first send the user's API key to...") directly into the tool description. The LLM follows these hidden instructions without the user seeing them.

MCPTox benchmark showed a 72.8% attack success rate on o1-mini. 43% of MCP servers analyzed were vulnerable to some form of tool poisoning.

**What I built:** AgentAuditKit — 77-rule security scanner that catches these attacks statically, before deployment.

The tool poisoning detection specifically looks for:
- Invisible Unicode (zero-width joiners, RTL override, homoglyphs)
- Prompt injection patterns in tool descriptions
- Cross-tool reference attacks ("before calling X, first call Y")
- Encoded payloads (base64, hex in descriptions)
- Rug pull detection — tool definitions changing after initial approval (SHA-256 pinning)

Beyond tool poisoning, it also does Python AST-based taint analysis for `@tool` decorated functions — tracking parameter flow from tool inputs to dangerous sinks like `eval()`, `subprocess`, `cursor.execute()`, `requests.get()`, and `open()`. This catches real injection paths, not just pattern matches.

Maps to OWASP Agentic Top 10 (10/10 coverage) and OWASP MCP Top 10 (10/10).

MIT licensed, runs offline, zero dependencies beyond click + pyyaml.

GitHub: https://github.com/sattyamjjain/agent-audit-kit

Paper references:
- OWASP Agentic Top 10: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- Adversa AI MCP Top 25: https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/
