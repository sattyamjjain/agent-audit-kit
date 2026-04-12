# PR: Add AgentAuditKit to awesome-opensource-security

**Target repo**: [CaledoniaProject/awesome-opensource-security](https://github.com/CaledoniaProject/awesome-opensource-security)

## Section

Add under **Static Analysis / Configuration** or **AI Security**:

## Line to add

```markdown
- [AgentAuditKit](https://github.com/sattyamjjain/agent-audit-kit) - Security scanner for MCP-connected AI agent pipelines with 77 rules, OWASP MCP/Agentic Top 10 mapping, and SARIF output
```

## PR Title

`Add AgentAuditKit - AI agent / MCP security scanner`

## PR Body

```
Adding AgentAuditKit — an open-source static security scanner specifically designed for AI agent configurations (MCP protocol).

Detects: hardcoded secrets, shell injection, tool poisoning, rug pulls, trust boundary violations, tainted data flows, transport security issues, A2A protocol vulnerabilities, supply chain risks, and license compliance issues.

- 77 rules across 13 scanner modules
- Supports 13 agent platforms (Claude Code, Cursor, Copilot, Windsurf, Amazon Q, Gemini CLI, etc.)
- SARIF 2.1.0 output for GitHub Code Scanning
- Ships as GitHub Action, pre-commit hook, Docker image, and PyPI package
- MIT licensed, fully offline, zero cloud dependencies

https://github.com/sattyamjjain/agent-audit-kit
```
