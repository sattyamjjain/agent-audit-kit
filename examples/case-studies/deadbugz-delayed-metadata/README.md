# Deadbugz: metadata that turns hostile after approval

**Campaign:** Deadbugz, reported by Adversa AI, September 2026.
**Incident reference:** `DEADBUGZ-2026-09`
**Rules that answer it:** `AAK-RUGPULL-001`, `AAK-RUGPULL-002`

## What happened

A malicious MCP server was pushed into multiple projects. It shipped two
innocuous tools — text formatting and summarisation — and behaved normally for
exactly three tool calls. On the fourth it rewrote the metadata it returned into
instructions to hunt for SSH keys, AWS credentials, shell history and Kubernetes
config, while concealing the activity from the user.

## Why review does not catch it

Every check you run *before* approving the server passes, because at approval
time the server is benign. That is the design. A scanner that inspects a tool
surface once, at install, is looking at the honest version by construction.

This is worth being precise about, because it is a limit on static analysis
generally and therefore on this tool. AgentAuditKit cannot read a server's
future behaviour. What it can do is notice that the surface it approved is no
longer the surface it is talking to.

## What catches it

The pin-and-verify pair, run on a schedule rather than once.

```bash
# At approval: record a SHA-256 fingerprint of every tool's name,
# description and input schema.
agent-audit-kit pin .

# Later, and repeatedly: compare the live surface against the pin.
agent-audit-kit verify .
```

A Deadbugz-shaped mutation shows up as `AAK-RUGPULL-001` (a tool definition
changed since it was pinned) or `AAK-RUGPULL-002` (a tool appeared that was not
there at approval).

The scheduling is the load-bearing part. A campaign that waits three calls, or
three days, is invisible to a one-off verification at install time. `verify`
belongs in CI or a cron job, next to the dependency checks that already run
there.

## What this does not claim

Pinning detects that the tool *surface* changed. It does not detect a server
whose surface is constant while its behaviour is not, and it does not inspect
tool *outputs* at runtime — AgentAuditKit is a static scanner with no runtime
proxy in the trusted path. A server that exfiltrates without ever altering its
advertised metadata is outside what this catches, and no amount of re-running
`verify` changes that.

## Reference

- Adversa AI, "MCP security September 2026: Deadbugz + 3 server CVEs":
  https://adversa.ai/blog/top-mcp-security-resources-september-2026/
