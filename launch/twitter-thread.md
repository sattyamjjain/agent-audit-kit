# X/Twitter Thread (post each as a reply to the previous)

## Tweet 1 (Hook)

I built the missing `npm audit` for AI agents.

AgentAuditKit — 77 security rules, 13 scanners, one command.

Scans Claude Code, Cursor, VS Code Copilot, Windsurf, Amazon Q, Gemini CLI configs for misconfigurations, secrets, and tool poisoning.

`pip install agent-audit-kit`

github.com/sattyamjjain/agent-audit-kit

## Tweet 2 (Problem)

30 MCP CVEs dropped in 60 days this year.

CVE-2026-21852 leaked source code via a single config flag.

Every AI coding assistant uses MCP now. Nobody is auditing the configs.

## Tweet 3 (What it catches)

What it finds:

→ Hardcoded API keys (Shannon entropy detection)
→ Shell injection in MCP commands
→ Tool poisoning via invisible Unicode
→ Rug pulls (tool definitions changed silently)
→ Trust boundary violations
→ @tool param flows to eval/subprocess/SQL (Python AST)

## Tweet 4 (GitHub Action)

Ships as a GitHub Action. Findings show as inline PR annotations via SARIF.

```yaml
- uses: sattyamjjain/agent-audit-kit@v0.2.0
  with:
    fail-on: high
```

Also: CLI, pre-commit hook, VS Code extension.

## Tweet 5 (Stack)

This is one piece of a bigger vision — the open-source security stack for AI agents:

🔍 agent-audit-kit → static scanning (pre-deploy)
🛡️ agent-airlock → runtime firewall
⚙️ ferrumdeck → AgentOps control plane
🧠 mnemo → MCP-native memory DB

All open source. All on my GitHub.

github.com/sattyamjjain
