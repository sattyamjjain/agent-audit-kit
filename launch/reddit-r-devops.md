# r/devops Post

**Title:** One-line GitHub Action to scan your AI agent configs for security misconfigurations — catches hardcoded keys, shell injection, tool poisoning

**Body:**

If your team uses Claude Code, Cursor, or any MCP-connected AI assistant, you probably have `.mcp.json`, `.claude/settings.json`, or similar config files in your repos. These configs can contain hardcoded API keys, shell injection vectors, and wildcard permissions that nobody reviews.

I built a GitHub Action that scans these in CI:

```yaml
- uses: sattyamjjain/agent-audit-kit@v0.2.0
  with:
    fail-on: high
```

That's it. Findings show up as inline PR annotations in the Security tab via SARIF.

**What it catches (77 rules):**

- Hardcoded Anthropic/OpenAI/AWS/GitHub keys in MCP server env blocks
- Shell injection in MCP server commands (`sh -c`, pipes, `$()`)
- `enableAllProjectMcpServers: true` — the flag that leaked 512K lines of Claude Code source (CVE-2026-21852)
- Wildcard permissions without deny rules
- Unpinned npx/uvx packages (supply chain risk)
- Tool poisoning via invisible Unicode in tool descriptions
- Missing lockfiles, known vulnerable dependencies

**Also works as CLI and pre-commit hook:**

```bash
pip install agent-audit-kit
agent-audit-kit scan .
agent-audit-kit scan . --ci  # SARIF + exit code enforcement
```

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/sattyamjjain/agent-audit-kit
    rev: v0.2.0
    hooks:
      - id: agent-audit-kit
```

Scans configs for 13 agent platforms: Claude Code, Cursor, VS Code Copilot, Windsurf, Amazon Q, Gemini CLI, Goose, Continue, Roo Code, Kiro.

MIT licensed, runs offline, 441 tests.

GitHub: https://github.com/sattyamjjain/agent-audit-kit
PyPI: `pip install agent-audit-kit`
Marketplace: https://github.com/marketplace/actions/agentauditkit-mcp-security-scan
