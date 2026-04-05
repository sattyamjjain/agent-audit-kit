# Comparison

## AgentAuditKit vs Competitors

| Feature | AgentAuditKit | mcp-scan | Snyk Agent | Agent Audit | Microsoft AGT |
|---------|:---:|:---:|:---:|:---:|:---:|
| **Rules** | 74 | ~10 | ~15 | 57 | N/A (runtime) |
| MCP config scanning | Yes | No | Yes | No | No |
| Hook injection detection | Yes | No | No | No | No |
| Trust boundary analysis | Yes | No | No | No | Yes |
| Secret exposure scanning | Yes | No | Yes | No | No |
| Supply chain analysis | Yes | No | Yes | No | No |
| Agent instruction scanning | Yes | No | No | No | No |
| Tool poisoning detection | Yes | Yes | Yes | No | No |
| Tool pinning / rug pull | Yes | Yes | No | No | No |
| Taint analysis (@tool) | Yes | No | No | Yes | No |
| A2A protocol scanning | Yes | No | No | No | No |
| Multi-agent discovery | Yes | No | Yes | No | No |
| OWASP Agentic Top 10 | 10/10 | 0/10 | Partial | 10/10 | 10/10 |
| OWASP MCP Top 10 | 10/10 | Partial | Partial | 0/10 | 0/10 |
| Compliance frameworks | 5 | 0 | 0 | 0 | 3 |
| SARIF output | Yes | No | Yes | No | No |
| Auto-fix mode | Yes | No | No | No | No |
| Security scoring | Yes | No | No | No | No |
| Pre-commit hook | Yes | No | No | No | No |
| GitHub Action | Yes | No | Yes | No | No |
| Runtime proxy | Yes | No | No | No | Yes |
| Offline / no network | Yes | No | No | Yes | Yes |
| Zero dependencies | Yes* | No | No | No | No |

*Only click + pyyaml required.

## When to Use Each

- **AgentAuditKit**: Comprehensive static + config scanning, compliance reporting, CI/CD integration
- **mcp-scan**: Quick tool description poisoning check via cloud API
- **Snyk Agent Scan**: Enterprise multi-agent MDM with cloud backend
- **Agent Audit**: Academic-quality taint analysis for LangChain/CrewAI code
- **Microsoft AGT**: Runtime policy enforcement with execution rings

These tools are complementary. Use AgentAuditKit alongside runtime tools for defense-in-depth.
