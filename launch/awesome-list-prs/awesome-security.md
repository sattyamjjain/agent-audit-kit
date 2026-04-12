# PR: Add AgentAuditKit to awesome-security

**Target repo**: [sbilly/awesome-security](https://github.com/sbilly/awesome-security)

## Section

Add under **Tools / Static Analysis** or create new **AI Agent Security** section:

## Line to add

```markdown
- [AgentAuditKit](https://github.com/sattyamjjain/agent-audit-kit) - Security scanner for MCP-connected AI agent pipelines — 77 rules, OWASP MCP/Agentic Top 10 coverage, SARIF output, fully offline.
```

## PR Title

`Add AgentAuditKit - MCP/AI agent security scanner`

## PR Body

```
Hi! I'd like to add AgentAuditKit to this list.

AgentAuditKit is an open-source security scanner for AI agent configurations (MCP, Claude Code, Cursor, VS Code Copilot, Windsurf, etc.). It's the "npm audit" for AI agents.

- **77 rules** across 11 security categories
- **OWASP coverage**: MCP Top 10 (10/10), Agentic Top 10 (10/10)
- **Output**: Console, JSON, SARIF (GitHub Security tab integration)
- **Zero dependencies**: Only click + pyyaml, runs fully offline
- **CI/CD**: GitHub Action, GitLab CI, pre-commit hook, Docker
- MIT licensed, 452 tests at 90% coverage

GitHub: https://github.com/sattyamjjain/agent-audit-kit
PyPI: https://pypi.org/project/agent-audit-kit/
```
