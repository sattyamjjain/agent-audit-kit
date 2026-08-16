# AgentAuditKit standards crosswalk

Every AgentAuditKit rule (308 total; 281 mapped) against two agentic-security standards. Static and deterministic — generated from the committed rule registry and compliance mappings, no scan required.

**Standards**

- **NSA MCP Security CSI** — Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation (U/OO/6030316-26 | PP-26-1834, NSA Artificial Intelligence Security Center (AISC), May 2026 Ver. 1.0).
- **OWASP Agentic Top-10 (2026)** — ASI01–ASI10.

| AAK rule | Severity | Category | NSA MCP CSI control(s) | OWASP Agentic Top-10 (2026) |
|----------|----------|----------|------------------------|------------------------------|
| `AAK-A2A-001` | high | a2a-protocol | Design for boundaries | ASI07 Insecure Inter-Agent Communication |
| `AAK-A2A-002` | high | a2a-protocol | Design for boundaries | ASI07 Insecure Inter-Agent Communication |
| `AAK-A2A-003` | medium | a2a-protocol | Validate parameters; Instrument for logging and detection | ASI07 Insecure Inter-Agent Communication; ASI08 Cascading Failures |
| `AAK-A2A-004` | medium | a2a-protocol | Sign and verify MCP messages | ASI07 Insecure Inter-Agent Communication |
| `AAK-A2A-005` | high | a2a-protocol | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-A2A-006` | high | a2a-protocol | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-A2A-007` | medium | a2a-protocol | Instrument for logging and detection | ASI10 Rogue Agents |
| `AAK-A2A-008` | high | a2a-protocol | Design for boundaries | ASI07 Insecure Inter-Agent Communication |
| `AAK-A2A-009` | high | a2a-protocol | Design for boundaries | ASI07 Insecure Inter-Agent Communication |
| `AAK-A2A-010` | high | a2a-protocol | Design for boundaries | ASI07 Insecure Inter-Agent Communication |
| `AAK-A2A-011` | medium | a2a-protocol | Sign and verify MCP messages; Instrument for logging and detection | ASI07 Insecure Inter-Agent Communication; ASI08 Cascading Failures |
| `AAK-A2A-012` | medium | a2a-protocol | Instrument for logging and detection | ASI07 Insecure Inter-Agent Communication; ASI08 Cascading Failures |
| `AAK-AGENT-001` | critical | agent-config | Instrument for logging and detection | ASI01 Agent Goal Hijacking |
| `AAK-AGENT-002` | high | agent-config | Instrument for logging and detection | ASI01 Agent Goal Hijacking |
| `AAK-AGENT-003` | high | agent-config | Instrument for logging and detection | ASI01 Agent Goal Hijacking |
| `AAK-AGENT-004` | medium | agent-config | Instrument for logging and detection | ASI01 Agent Goal Hijacking |
| `AAK-AGENT-005` | medium | agent-config | Filter and monitor output pipelines and chained execution | ASI01 Agent Goal Hijacking |
| `AAK-AGENT-COMPOSE-001` | high | trust-boundary | — | ASI06 Memory & Context Poisoning |
| `AAK-AGENT-COMPOSE-002` | medium | trust-boundary | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI06 Memory & Context Poisoning; ASI03 Identity & Privilege Abuse |
| `AAK-AGENT-HARNESS-SHARED-STATE-001` | medium | a2a-protocol | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities; ASI06 Memory & Context Poisoning |
| `AAK-AGENT-SHARED-RES-AUTHZ-001` | high | trust-boundary | Choose supported MCP projects when possible; Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities; ASI02 Tool Misuse |
| `AAK-AGENT-TRUST-001` | high | hook-injection | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-AGENT-TRUST-002` | critical | hook-injection | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Sign and verify MCP messages; Filter and monitor output pipelines and chained execution; Scan local network for open or vulnerable MCP servers | ASI05 Unexpected Code Execution; ASI03 Identity & Privilege Abuse |
| `AAK-AGENT-TRUST-003` | high | agent-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-AGENT-TRUST-004` | medium | agent-config | — | ASI06 Memory & Context Poisoning |
| `AAK-ANTHROPIC-SDK-001` | high | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Instrument for logging and detection | ASI02 Tool Misuse; ASI10 Rogue Agents |
| `AAK-ASTROMCP-SQLI-CVE-2026-7591-001` | high | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Instrument for logging and detection; Track and patch MCP related vulnerabilities | ASI02 Tool Misuse; ASI10 Rogue Agents |
| `AAK-AZURE-MCP-001` | high | mcp-config | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-AZURE-MCP-NOAUTH-001` | high | mcp-config | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-CHATGPT-MCP-CVE-2026-7061-PIN-001` | high | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Instrument for logging and detection; Track and patch MCP related vulnerabilities | ASI02 Tool Misuse; ASI10 Rogue Agents |
| `AAK-CLAUDE-WIN-001` | high | agent-config | Track and patch MCP related vulnerabilities | ASI06 Memory & Context Poisoning |
| `AAK-CLAUDECODE-CVE-2026-40068-PIN-001` | high | supply-chain | Design for boundaries; Sign and verify MCP messages; Instrument for logging and detection; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse; ASI10 Rogue Agents |
| `AAK-CREWAI-CHAIN-2026-04-001` | critical | agent-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI01 Agent Goal Hijacking; ASI05 Unexpected Code Execution; ASI09 Human-Agent Trust Exploitation |
| `AAK-CREWAI-CVE-2026-2275-001` | critical | agent-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution; Track and patch MCP related vulnerabilities | ASI05 Unexpected Code Execution |
| `AAK-CREWAI-CVE-2026-2285-001` | high | tool-poisoning | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Track and patch MCP related vulnerabilities | ASI02 Tool Misuse |
| `AAK-CREWAI-CVE-2026-2286-001` | critical | transport-security | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-CREWAI-CVE-2026-2287-001` | critical | agent-config | Track and patch MCP related vulnerabilities | ASI09 Human-Agent Trust Exploitation |
| `AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001` | high | tool-poisoning | Validate parameters | ASI01 Agent Goal Hijacking |
| `AAK-DNS-REBIND-001` | critical | transport-security | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-DNS-REBIND-002` | high | supply-chain | Choose supported MCP projects when possible; Instrument for logging and detection | ASI10 Rogue Agents |
| `AAK-DOCSGPT-MCP-STDIO-MITM-001` | high | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Instrument for logging and detection; Track and patch MCP related vulnerabilities | ASI02 Tool Misuse; ASI10 Rogue Agents |
| `AAK-DORIS-001` | high | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Track and patch MCP related vulnerabilities | ASI02 Tool Misuse |
| `AAK-EU-AI-ACT-ART15-LOCALE-001` | info | legal-compliance | — | — |
| `AAK-EXCEL-MCP-001` | critical | supply-chain | Choose supported MCP projects when possible; Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI02 Tool Misuse; ASI04 Supply Chain Vulnerabilities |
| `AAK-FLOWISE-001` | critical | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Track and patch MCP related vulnerabilities | ASI02 Tool Misuse |
| `AAK-GHA-IMMUTABLE-001` | medium | supply-chain | Instrument for logging and detection | ASI10 Rogue Agents |
| `AAK-GPTRESEARCHER-MCP-STDIO-MITM-001` | high | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Instrument for logging and detection; Track and patch MCP related vulnerabilities | ASI02 Tool Misuse; ASI10 Rogue Agents |
| `AAK-HEALTHCARE-AI-001` | critical | legal-compliance | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-HEALTHCARE-AI-002` | high | legal-compliance | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-HEALTHCARE-AI-003` | high | legal-compliance | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-HEALTHCARE-AI-004` | medium | legal-compliance | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-HEALTHCARE-AI-005` | high | legal-compliance | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-HOOK-001` | critical | hook-injection | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-HOOK-002` | critical | hook-injection | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-HOOK-003` | high | hook-injection | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-HOOK-004` | high | hook-injection | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-HOOK-005` | high | hook-injection | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-HOOK-006` | medium | hook-injection | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-HOOK-007` | medium | hook-injection | Design for boundaries; Validate parameters; Constrain and sandbox tool execution | ASI02 Tool Misuse |
| `AAK-HOOK-008` | critical | hook-injection | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-HOOK-009` | medium | hook-injection | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-HOOK-RCE-001` | critical | hook-injection | Constrain and sandbox tool execution | ASI09 Human-Agent Trust Exploitation |
| `AAK-HOOK-RCE-002` | critical | hook-injection | Constrain and sandbox tool execution | ASI09 Human-Agent Trust Exploitation |
| `AAK-HOOK-RCE-003` | high | hook-injection | Constrain and sandbox tool execution | ASI09 Human-Agent Trust Exploitation |
| `AAK-IDE-TASK-001` | high | hook-injection | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-IDE-TASK-002` | high | hook-injection | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-IDE-TASK-003` | high | hook-injection | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-IDE-TASK-004` | low | agent-config | — | — |
| `AAK-INDIA-PII-001` | critical | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-INDIA-PII-002` | high | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-INDIA-PII-003` | high | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-INDIA-PII-004` | medium | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-INDIA-PII-005` | medium | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-INDIA-PII-006` | low | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-INTERNAL-SCANNER-FAIL` | info | agent-config | — | — |
| `AAK-IPI-WILD-CORPUS-001` | high | taint-analysis | Design for boundaries; Validate parameters; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-LANGCHAIN-001` | high | supply-chain | Validate parameters | ASI06 Memory & Context Poisoning |
| `AAK-LANGCHAIN-002` | medium | taint-analysis | Validate parameters | ASI06 Memory & Context Poisoning |
| `AAK-LANGCHAIN-003` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-LANGCHAIN-PROMPT-LOADER-PATH-001` | high | tool-poisoning | Design for boundaries; Validate parameters; Constrain and sandbox tool execution | ASI02 Tool Misuse |
| `AAK-LANGCHAIN-SSRF-REDIR-001` | high | transport-security | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities; ASI09 Human-Agent Trust Exploitation |
| `AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001` | medium | agent-config | — | ASI09 Human-Agent Trust Exploitation |
| `AAK-LEGAL-001` | high | legal-compliance | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-LEGAL-002` | medium | legal-compliance | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-LEGAL-003` | critical | legal-compliance | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-LITELLM-CVE-2026-30623-PIN-001` | high | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Instrument for logging and detection; Track and patch MCP related vulnerabilities | ASI02 Tool Misuse; ASI10 Rogue Agents |
| `AAK-LLM-SQL-RCE-001` | critical | taint-analysis | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI02 Tool Misuse; ASI05 Unexpected Code Execution |
| `AAK-LMDEPLOY-VL-SSRF-001` | high | transport-security | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities; ASI09 Human-Agent Trust Exploitation |
| `AAK-LOGINJ-001` | medium | taint-analysis | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution; Instrument for logging and detection | ASI05 Unexpected Code Execution |
| `AAK-MARKETPLACE-001` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MARKETPLACE-002` | medium | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MARKETPLACE-003` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MARKETPLACE-004` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-001` | critical | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-002` | critical | mcp-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-MCP-003` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-004` | high | mcp-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution | ASI02 Tool Misuse |
| `AAK-MCP-005` | medium | mcp-config | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-006` | medium | mcp-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-MCP-007` | low | mcp-config | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-008` | critical | mcp-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-MCP-009` | high | mcp-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Scan local network for open or vulnerable MCP servers | ASI02 Tool Misuse |
| `AAK-MCP-010` | high | mcp-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution | ASI02 Tool Misuse |
| `AAK-MCP-011` | critical | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-012` | critical | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-013` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-014` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-015` | critical | mcp-config | Validate parameters | ASI06 Memory & Context Poisoning |
| `AAK-MCP-016` | medium | mcp-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-MCP-017` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-018` | medium | mcp-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-MCP-019` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-020` | critical | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-9ROUTER-CVE-2026-46339-001` | critical | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-AGENTICFLOW-CVE-2026-58195-001` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-AGENTICMAIL-CVE-2026-57495-001` | high | supply-chain | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-AMAZONMQ-CVE-2026-18655-001` | medium | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-APIFY-CVE-2026-46341-001` | medium | supply-chain | — | ASI06 Memory & Context Poisoning |
| `AAK-MCP-APPIUM-CVE-2026-58500-001` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-APPS-001` | high | tool-poisoning | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-MCP-APPS-002` | high | tool-poisoning | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-MCP-ARGV-TOCTOU-001` | high | mcp-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution | ASI02 Tool Misuse |
| `AAK-MCP-ASTRBOT-CVE-2026-15501-001` | medium | supply-chain | — | ASI06 Memory & Context Poisoning |
| `AAK-MCP-ATLASSIAN-CVE-2026-27825-001` | critical | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Track and patch MCP related vulnerabilities | ASI02 Tool Misuse |
| `AAK-MCP-ATLASSIAN-CVE-2026-27826-001` | high | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Track and patch MCP related vulnerabilities | ASI02 Tool Misuse |
| `AAK-MCP-ATTEST-001` | medium | mcp-config | Choose supported MCP projects when possible; Design for boundaries; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse; ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-AUTH-PATHTRAVERSAL-001` | critical | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-AWSAPIMCP-CVE-2026-16584-001` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-BETTERAUTH-CVE-2026-53512-001` | high | supply-chain | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-CARD-001` | critical | mcp-server-card | — | ASI06 Memory & Context Poisoning |
| `AAK-MCP-CARD-002` | high | mcp-server-card | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-CARD-003` | high | mcp-server-card | — | ASI06 Memory & Context Poisoning |
| `AAK-MCP-CARD-004` | medium | mcp-server-card | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-CCTEMPLATES-CVE-2026-73222-001` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-CLINE-CVE-2026-59723-001` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-DBTMCP-CVE-2026-44968-001` | medium | supply-chain | — | ASI09 Human-Agent Trust Exploitation |
| `AAK-MCP-DEEPSEEK-CVE-2026-55604-001` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-DEPRECATED-001` | medium | mcp-config | — | — |
| `AAK-MCP-DEPRECATED-002` | medium | mcp-config | — | — |
| `AAK-MCP-DEPRECATED-003` | medium | mcp-config | — | — |
| `AAK-MCP-DOCUMENTDB-CVE-2026-18954-001` | medium | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-ENV-PLACEHOLDER-EXFIL-001` | critical | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-FHI-001` | high | tool-poisoning | Choose supported MCP projects when possible; Validate parameters; Sign and verify MCP messages; Filter and monitor output pipelines and chained execution; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-FLYTO-CVE-2026-67425-001` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-FRONTMCP-CVE-2026-67531-001` | high | supply-chain | Choose supported MCP projects when possible; Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Sign and verify MCP messages; Filter and monitor output pipelines and chained execution; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI05 Unexpected Code Execution; ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-GATEWAY-REGISTRY-CVE-2026-14471-001` | high | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution | ASI02 Tool Misuse |
| `AAK-MCP-GEMINIBRIDGE-CVE-2026-54785-001` | medium | supply-chain | — | ASI09 Human-Agent Trust Exploitation |
| `AAK-MCP-GOOGLESEARCH-CVE-2026-19337-001` | medium | supply-chain | — | ASI06 Memory & Context Poisoning |
| `AAK-MCP-GRAFANA-CVE-2026-19516-001` | critical | supply-chain | — | ASI06 Memory & Context Poisoning |
| `AAK-MCP-HEALTHLAKE-CVE-2026-15643-001` | high | supply-chain | — | ASI06 Memory & Context Poisoning |
| `AAK-MCP-HEALTHOMICS-CVE-2026-15415-001` | medium | supply-chain | — | ASI09 Human-Agent Trust Exploitation |
| `AAK-MCP-HTTP-NOAUTH-SERVER-001` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-INSPECTOR-CVE-2026-23744-001` | critical | supply-chain | Choose supported MCP projects when possible; Instrument for logging and detection; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI10 Rogue Agents |
| `AAK-MCP-K8S-CVE-2026-61459-001` | critical | supply-chain | — | ASI01 Agent Goal Hijacking |
| `AAK-MCP-KONG-CVE-2026-13341-001` | high | tool-poisoning | — | ASI01 Agent Goal Hijacking |
| `AAK-MCP-LANGFLOW-CVE-2026-12940-001` | critical | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-LANGGRAPH-CHECKPOINT-CVE-2026-71433-001` | medium | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-LANGGRAPH-MONGO-CVE-2026-48121-001` | medium | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-LINEAGE-STAINLESS-001` | info | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages | — |
| `AAK-MCP-LITELLM-CVE-2026-59822-001` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-MARKETPLACE-CONFIG-FETCH-001` | critical | supply-chain | Instrument for logging and detection | ASI10 Rogue Agents |
| `AAK-MCP-N8N-CVE-2026-59207-001` | medium | supply-chain | — | ASI06 Memory & Context Poisoning |
| `AAK-MCP-N8N-CVE-2026-65594-001` | high | supply-chain | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-N8N-CVE-2026-72768-001` | medium | supply-chain | — | ASI06 Memory & Context Poisoning |
| `AAK-MCP-N8NMCP-CVE-2026-54052-001` | critical | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-NOAUTH-DEFAULT` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-OPENAPI-BLOATED-PARAMS-001` | low | tool-poisoning | Filter and monitor output pipelines and chained execution | — |
| `AAK-MCP-OPENAPI-LAZY-DESCRIPTION-001` | medium | tool-poisoning | Filter and monitor output pipelines and chained execution | — |
| `AAK-MCP-OPENAPI-TANGLED-METHODS-001` | medium | tool-poisoning | Filter and monitor output pipelines and chained execution | — |
| `AAK-MCP-OPENCLAW-CVE-2026-62195-001` | high | supply-chain | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-PENPOT-CVE-2026-45805-001` | critical | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-PRAISONAI-CVE-2026-61427-001` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-REPOMIX-CVE-2026-49988-001` | medium | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-ROUTING-DESYNC-001` | high | transport-security | Design for boundaries; Validate parameters; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-RUFLO-CVE-2026-59726-001` | critical | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-SAMPLING-001` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-SANDBOX-SELFDISABLE-001` | critical | trust-boundary | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI06 Memory & Context Poisoning; ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-SDK-CVE-2026-52869-001` | high | supply-chain | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-SERENA-CVE-2026-49471-001` | high | mcp-config | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-SSRF-001` | medium | mcp-config | — | ASI06 Memory & Context Poisoning |
| `AAK-MCP-STATA-CVE-2026-47708-001` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCP-STATELESS-001` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-STATELESS-002` | high | mcp-config | Track and patch MCP related vulnerabilities | — |
| `AAK-MCP-STATELESS-003` | medium | mcp-config | — | — |
| `AAK-MCP-STATELESS-004` | low | mcp-config | — | — |
| `AAK-MCP-STDIO-CMD-INJ-001` | critical | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Instrument for logging and detection | ASI02 Tool Misuse; ASI10 Rogue Agents |
| `AAK-MCP-STDIO-CMD-INJ-002` | critical | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Instrument for logging and detection | ASI02 Tool Misuse; ASI10 Rogue Agents |
| `AAK-MCP-STDIO-CMD-INJ-003` | critical | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Instrument for logging and detection | ASI02 Tool Misuse; ASI10 Rogue Agents |
| `AAK-MCP-STDIO-CMD-INJ-004` | critical | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Instrument for logging and detection | ASI02 Tool Misuse; ASI10 Rogue Agents |
| `AAK-MCP-STDIO-LAUNCHER-INJECT-001` | high | mcp-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution; ASI02 Tool Misuse |
| `AAK-MCP-TEXTEDITOR-CVE-2026-15138-001` | medium | supply-chain | — | ASI09 Human-Agent Trust Exploitation |
| `AAK-MCP-TOOL-UNSAFE-EVAL-001` | critical | tool-poisoning | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI02 Tool Misuse; ASI05 Unexpected Code Execution |
| `AAK-MCP-TOOLGATE-ASYMMETRY-001` | high | mcp-config | Choose supported MCP projects when possible; Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities; ASI02 Tool Misuse |
| `AAK-MCP-TUNNEL-001` | critical | mcp-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI02 Tool Misuse; ASI05 Unexpected Code Execution |
| `AAK-MCP-TUNNEL-002` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-MCP-TUNNEL-003` | critical | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse; ASI06 Memory & Context Poisoning |
| `AAK-MCP-WHATSAPP-CVE-2026-46555-001` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-MCPCALC-CVE-2026-44717-PIN-001` | critical | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI02 Tool Misuse; ASI05 Unexpected Code Execution |
| `AAK-MCPFRAME-001` | medium | transport-security | Track and patch MCP related vulnerabilities | ASI09 Human-Agent Trust Exploitation |
| `AAK-MCPWN-001` | critical | mcp-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Scan local network for open or vulnerable MCP servers | ASI01 Agent Goal Hijacking; ASI02 Tool Misuse |
| `AAK-METAADS-CVE-2026-48039-001` | critical | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-METIS-REFUSAL-REFEED-001` | medium | tool-poisoning | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI01 Agent Goal Hijacking; ASI02 Tool Misuse |
| `AAK-METIS-SCORING-SINK-001` | medium | tool-poisoning | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI01 Agent Goal Hijacking; ASI02 Tool Misuse |
| `AAK-NEO4J-001` | medium | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-NEXT-AI-DRAW-001` | medium | transport-security | — | ASI09 Human-Agent Trust Exploitation |
| `AAK-OAUTH-001` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-OAUTH-002` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-OAUTH-003` | critical | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-OAUTH-004` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-OAUTH-005` | medium | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-OAUTH-006` | medium | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-OAUTH-007` | medium | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-OAUTH-008` | low | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-OAUTH-3P-001` | medium | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-OAUTH-SCOPE-001` | high | trust-boundary | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-OPENCLAW-PRIVESC-001` | high | trust-boundary | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-OX-COVERAGE-MANIFEST-001` | info | supply-chain | — | — |
| `AAK-POISON-001` | critical | tool-poisoning | Filter and monitor output pipelines and chained execution | ASI06 Memory & Context Poisoning |
| `AAK-POISON-002` | critical | tool-poisoning | Validate parameters; Filter and monitor output pipelines and chained execution | ASI06 Memory & Context Poisoning |
| `AAK-POISON-003` | high | tool-poisoning | Filter and monitor output pipelines and chained execution | ASI06 Memory & Context Poisoning |
| `AAK-POISON-004` | high | tool-poisoning | Filter and monitor output pipelines and chained execution | ASI06 Memory & Context Poisoning |
| `AAK-POISON-005` | medium | tool-poisoning | Filter and monitor output pipelines and chained execution | ASI06 Memory & Context Poisoning |
| `AAK-POISON-006` | medium | tool-poisoning | Filter and monitor output pipelines and chained execution | ASI06 Memory & Context Poisoning |
| `AAK-PRISMA-AIRS-COVERAGE-001` | info | supply-chain | — | — |
| `AAK-PROJECT-DEAL-DRIFT-001` | high | agent-config | — | ASI06 Memory & Context Poisoning |
| `AAK-PRTITLE-IPI-001` | high | taint-analysis | Design for boundaries; Validate parameters; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-ROUTINE-001` | high | agent-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-ROUTINE-002` | medium | agent-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-ROUTINE-003` | medium | agent-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-RUGPULL-001` | critical | tool-poisoning | Choose supported MCP projects when possible; Filter and monitor output pipelines and chained execution | ASI06 Memory & Context Poisoning |
| `AAK-RUGPULL-002` | high | tool-poisoning | Choose supported MCP projects when possible; Filter and monitor output pipelines and chained execution | ASI06 Memory & Context Poisoning |
| `AAK-RUGPULL-003` | medium | tool-poisoning | Choose supported MCP projects when possible; Filter and monitor output pipelines and chained execution | ASI06 Memory & Context Poisoning |
| `AAK-SEC-MD-001` | low | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-SECRET-001` | critical | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-SECRET-002` | critical | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-SECRET-003` | critical | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-SECRET-004` | high | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-SECRET-005` | high | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-SECRET-006` | medium | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-SECRET-007` | medium | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-SECRET-008` | critical | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-SECRET-009` | high | secret-exposure | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-SK-INMEMORY-VECTORSTORE-FILTER-CVE-2026-26030-PIN-001` | critical | supply-chain | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution; Instrument for logging and detection | ASI02 Tool Misuse; ASI05 Unexpected Code Execution; ASI10 Rogue Agents |
| `AAK-SKILL-001` | critical | tool-poisoning | Filter and monitor output pipelines and chained execution | ASI06 Memory & Context Poisoning |
| `AAK-SKILL-002` | high | tool-poisoning | Filter and monitor output pipelines and chained execution | ASI06 Memory & Context Poisoning |
| `AAK-SKILL-003` | critical | tool-poisoning | Filter and monitor output pipelines and chained execution | ASI06 Memory & Context Poisoning |
| `AAK-SKILL-004` | high | tool-poisoning | Filter and monitor output pipelines and chained execution | ASI06 Memory & Context Poisoning |
| `AAK-SKILL-005` | high | tool-poisoning | Filter and monitor output pipelines and chained execution | ASI01 Agent Goal Hijacking |
| `AAK-SKILL-LIFECYCLE-ATTRIBUTION-001` | medium | tool-poisoning | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities; ASI09 Human-Agent Trust Exploitation |
| `AAK-SKILL-UNTRUSTED-EXEC-PATH` | high | supply-chain | — | ASI06 Memory & Context Poisoning |
| `AAK-SPLUNK-MCP-TOKEN-LEAK-001` | high | secret-exposure | Choose supported MCP projects when possible; Sign and verify MCP messages; Instrument for logging and detection; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-SPLUNK-TOKLOG-001` | high | secret-exposure | Choose supported MCP projects when possible; Sign and verify MCP messages; Instrument for logging and detection; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-SSRF-001` | critical | mcp-config | Constrain and sandbox tool execution | ASI06 Memory & Context Poisoning |
| `AAK-SSRF-002` | high | mcp-config | Scan local network for open or vulnerable MCP servers | ASI06 Memory & Context Poisoning |
| `AAK-SSRF-003` | critical | mcp-config | Scan local network for open or vulnerable MCP servers | ASI06 Memory & Context Poisoning |
| `AAK-SSRF-004` | high | mcp-config | Constrain and sandbox tool execution | ASI06 Memory & Context Poisoning |
| `AAK-SSRF-005` | high | mcp-config | Constrain and sandbox tool execution | ASI06 Memory & Context Poisoning |
| `AAK-SSRF-TOCTOU-001` | medium | transport-security | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-STATE-PRIVACY-001` | medium | legal-compliance | — | — |
| `AAK-STATE-PRIVACY-002` | medium | legal-compliance | — | — |
| `AAK-STATE-PRIVACY-003` | low | legal-compliance | — | — |
| `AAK-STDIO-001` | critical | mcp-config | Design for boundaries; Validate parameters; Constrain and sandbox tool execution | ASI02 Tool Misuse |
| `AAK-SUPPLY-001` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-SUPPLY-002` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-SUPPLY-003` | medium | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-SUPPLY-004` | medium | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-SUPPLY-005` | low | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-SUPPLY-006` | high | supply-chain | Choose supported MCP projects when possible; Sign and verify MCP messages; Track and patch MCP related vulnerabilities; Scan local network for open or vulnerable MCP servers | ASI04 Supply Chain Vulnerabilities |
| `AAK-TAINT-001` | critical | taint-analysis | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-TAINT-002` | critical | taint-analysis | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-TAINT-003` | high | taint-analysis | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-TAINT-004` | high | taint-analysis | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-TAINT-005` | high | taint-analysis | Design for boundaries; Validate parameters; Constrain and sandbox tool execution | ASI02 Tool Misuse |
| `AAK-TAINT-006` | medium | taint-analysis | Design for boundaries; Validate parameters; Constrain and sandbox tool execution; Filter and monitor output pipelines and chained execution | ASI05 Unexpected Code Execution |
| `AAK-TAINT-007` | medium | taint-analysis | Design for boundaries; Validate parameters; Constrain and sandbox tool execution | ASI02 Tool Misuse |
| `AAK-TAINT-008` | medium | taint-analysis | Design for boundaries; Validate parameters; Constrain and sandbox tool execution | ASI02 Tool Misuse |
| `AAK-TASKS-001` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-TASKS-002` | high | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-TASKS-003` | medium | mcp-config | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-TASKS-004` | medium | mcp-config | Design for boundaries; Instrument for logging and detection | ASI08 Cascading Failures |
| `AAK-TIKTOK-AGENT-HIJACK-001` | high | trust-boundary | — | ASI09 Human-Agent Trust Exploitation |
| `AAK-TOXICFLOW-001` | high | tool-poisoning | Design for boundaries; Validate parameters; Constrain and sandbox tool execution | ASI02 Tool Misuse; ASI09 Human-Agent Trust Exploitation |
| `AAK-TRANSPORT-001` | critical | transport-security | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-TRANSPORT-002` | high | transport-security | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-TRANSPORT-003` | medium | transport-security | Instrument for logging and detection | ASI08 Cascading Failures |
| `AAK-TRANSPORT-004` | high | transport-security | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-TRUST-001` | critical | trust-boundary | Design for boundaries; Instrument for logging and detection | ASI10 Rogue Agents |
| `AAK-TRUST-002` | critical | trust-boundary | Design for boundaries; Instrument for logging and detection | ASI10 Rogue Agents |
| `AAK-TRUST-003` | high | trust-boundary | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-TRUST-004` | high | trust-boundary | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-TRUST-005` | high | trust-boundary | Design for boundaries; Instrument for logging and detection | ASI10 Rogue Agents |
| `AAK-TRUST-006` | medium | trust-boundary | Design for boundaries | ASI09 Human-Agent Trust Exploitation |
| `AAK-TRUST-007` | medium | trust-boundary | Design for boundaries; Sign and verify MCP messages; Scan local network for open or vulnerable MCP servers | ASI03 Identity & Privilege Abuse |
| `AAK-WINDSURF-001` | high | mcp-config | Sign and verify MCP messages; Instrument for logging and detection | ASI06 Memory & Context Poisoning |
