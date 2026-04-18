# Reddit submission drafts

Post on the same Tuesday as HN but wait 30–60 minutes after the HN
submission so mods don't mark them as cross-post spam. `/r/netsec` is
the #1 channel for this repo.

## r/netsec

**Title:**
> We scanned 500 public MCP servers for 2026 CVEs. 82% have path
> traversal. 37% have SSRF. Here's the scanner + the leaderboard.

**Body:**
> Model Context Protocol is the tool-call substrate Anthropic shipped
> in late 2024 that every major AI vendor now speaks. 30+ CVEs were
> filed against MCP servers in January–February 2026 alone; the
> pattern is uniform — auth middleware missing from one route that
> shares a handler with an authenticated route, empty IP allowlists
> that default to allow-all, path traversal in resource handlers,
> SSRF in outbound-fetch tools, tokens in query params.
>
> We built agent-audit-kit, an OSS scanner: 124 deterministic rules,
> SARIF + OWASP MCP Top 10 + compliance report for EU AI Act /
> SOC 2 / ISO 27001 / HIPAA / NIST AI RMF. No auth, no cloud. Apache 2.0.
>
> Published the MCP Security Index — weekly leaderboard of 500 public
> servers, per-server grade cards, 90-day coordinated disclosure
> policy before findings hit the public card.
>
> Links:
> - Scanner: https://github.com/sattyamjjain/agent-audit-kit
> - Leaderboard: https://mcp-security-index.com/
> - Disclosure policy: https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/disclosure-policy.md
> - CVE-to-rule ledger (48h SLA): https://github.com/sattyamjjain/agent-audit-kit/blob/main/CHANGELOG.cves.md

**Expected questions & answers**

- "What makes this better than Snyk MCP-scan / `snyk/agent-scan`?"
  → No account required, air-gap friendly, compliance-evidence output,
  48h SLA we publicly track, Sigstore-signed rule bundles.
- "Is the 82% stat your number or someone else's?"
  → Not ours. A 2,614-server survey, cited in the scanner's README.
  Our scan found similar proportions on the 500 we picked.
- "How do you pick which 500?"
  → Top GitHub results for `topic:mcp-server`, plus Anthropic's
  official marketplace, aitmpl.com, buildwithclaude.com, claudemarketplaces.com.

## r/ClaudeAI

**Title:**
> We built a security scanner specifically for Claude Code + MCP configs. Free, no account.

**Body:** shorter; lead with "scan your agent setup in 30 seconds":
> `pip install agent-audit-kit && agent-audit-kit scan .`
> Finds misconfigured hooks (CVE-2025-59536 was the catalyst), MCP
> servers without auth, skill poisoning in SKILL.md files, supply-chain
> risks in marketplace manifests, missing OAuth 2.1 PKCE. 124 rules.
> Outputs SARIF for GitHub Security tab.
>
> Repo: https://github.com/sattyamjjain/agent-audit-kit
> Index: https://mcp-security-index.com/

## r/LocalLLaMA

**Title:**
> Deterministic security scanner for local MCP setups — no cloud, no LLM calls

**Body:** lean into the "no data leaves my machine" angle. Emphasize:
- zero network requests by default
- rules are regex/AST, no LLM inference
- grades your local config 0–100
- optional `--llm-scan` for semantic checks, opt-in only
- pip install / Docker / VS Code extension / pre-commit hook

## r/mcp

**Title:**
> OWASP MCP Top 10 reference scanner — 10/10 coverage, SARIF, EU AI Act evidence

**Body:** developer-audience, technical:
> If you maintain an MCP server, this is the linter. 124 rules mapped
> to OWASP MCP Top 10 and OWASP Agentic 2026 (ASI01–ASI10). GitHub
> Action that surfaces findings in the Security tab via SARIF. Docker
> image at ghcr.io. VS Code extension with on-save diagnostics.
> Pre-commit hook: `agent-audit-kit install-precommit`.
