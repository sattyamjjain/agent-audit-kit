# OWASP Mapping

AgentAuditKit maps to three security frameworks:

## OWASP Agentic Top 10 (ASI01-ASI10)

| Code | Name | AgentAuditKit Coverage |
|------|------|----------------------|
| ASI01 | Agent Goal Hijacking | AAK-AGENT-001 to 005 |
| ASI02 | Tool Misuse | AAK-MCP-004, AAK-TAINT-005/007/008 |
| ASI03 | Identity & Privilege Abuse | AAK-SECRET-*, AAK-TRUST-003 |
| ASI04 | Supply Chain | AAK-SUPPLY-*, AAK-LEGAL-* |
| ASI05 | Unexpected Code Execution | AAK-HOOK-*, AAK-TAINT-001/002 |
| ASI06 | Memory & Context Poisoning | AAK-POISON-*, AAK-RUGPULL-* |
| ASI07 | Insecure Inter-Agent Communication | AAK-A2A-* |
| ASI08 | Cascading Failures | AAK-TRANSPORT-003 |
| ASI09 | Human-Agent Trust Exploitation | AAK-TRUST-006 |
| ASI10 | Rogue Agents | AAK-TRUST-001/002 |

## OWASP MCP Top 10

| Code | Name | Rules |
|------|------|-------|
| MCP01:2025 | Token Mismanagement | 14 rules |
| MCP02:2025 | Context Over-Sharing | 4 rules |
| MCP03:2025 | Supply Chain Attacks | 9 rules |
| MCP04:2025 | Command Injection | 12 rules |
| MCP05:2025 | Tool Poisoning | 10 rules |
| MCP06:2025 | Privilege Escalation | 5 rules |
| MCP07:2025 | Insufficient Auth | 5 rules |
| MCP09:2025 | SSRF | 3 rules |
| MCP10:2025 | Package Risks | 6 rules |

Run `agent-audit-kit scan . --owasp-report` for live coverage data.
