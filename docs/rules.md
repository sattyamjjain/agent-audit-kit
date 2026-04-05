# Rule Reference

## Summary

| Category | Rules | IDs |
|----------|-------|-----|
| MCP Configuration | 10 | AAK-MCP-001 to 010 |
| Hook Injection | 9 | AAK-HOOK-001 to 009 |
| Trust Boundary | 7 | AAK-TRUST-001 to 007 |
| Secret Exposure | 9 | AAK-SECRET-001 to 009 |
| Supply Chain | 6 | AAK-SUPPLY-001 to 006 |
| Agent Config | 5 | AAK-AGENT-001 to 005 |
| Tool Poisoning | 6+3 | AAK-POISON-001 to 006, AAK-RUGPULL-001 to 003 |
| Taint Analysis | 8 | AAK-TAINT-001 to 008 |
| Transport Security | 4 | AAK-TRANSPORT-001 to 004 |
| A2A Protocol | 4 | AAK-A2A-001 to 004 |
| Legal Compliance | 3 | AAK-LEGAL-001 to 003 |
| **Total** | **74** | |

## Full Rule List

Run `agent-audit-kit scan . --owasp-report` for a complete mapping of rules to OWASP frameworks.

Each rule includes:
- Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- OWASP MCP Top 10 reference
- OWASP Agentic Top 10 reference (ASI01-ASI10)
- Adversa AI Top 25 reference
- CVE references where applicable
- Remediation guidance
