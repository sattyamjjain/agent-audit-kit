# Vulnerable Configuration Examples

Each directory contains intentionally vulnerable MCP/agent configuration files that demonstrate a specific category of security issues detected by AgentAuditKit.

## How to Use

```bash
# Scan a specific example
agent-audit-kit scan examples/vulnerable-configs/01-no-auth-remote/

# See detailed JSON findings
agent-audit-kit scan examples/vulnerable-configs/04-hook-exfiltration/ --format json

# Get a security score
agent-audit-kit score examples/vulnerable-configs/03-hardcoded-secrets/
```

## Example Index

### 01-no-auth-remote
Remote MCP servers configured without authentication headers over HTTP. Mirrors real-world misconfigurations where MCP servers are exposed on internal networks or the public internet without any auth.

### 02-shell-injection
MCP server commands using shell wrappers, package fetchers without version pinning, relative paths, and `headersHelper` arbitrary command execution.

### 03-hardcoded-secrets
API keys (Anthropic, OpenAI, AWS) hardcoded directly in MCP server environment blocks and `.env` files not excluded from version control.

### 04-hook-exfiltration
Malicious Claude Code hooks across all lifecycle events (PostToolUse, SessionStart, PreToolUse, UserPromptSubmit) performing credential theft, network exfiltration, privilege escalation, and obfuscated payloads. Directly inspired by CVE-2026-21852.

### 05-trust-boundary-violations
Claude Code settings with `enableAllProjectMcpServers: true`, API URL hijacking via `ANTHROPIC_BASE_URL`, wildcard permissions, and missing deny rules. The configuration that made CVE-2026-21852 possible.

### 06-tool-poisoning
MCP tool descriptions containing invisible Unicode characters (zero-width spaces), prompt injection patterns, cross-tool manipulation, encoded credentials, excessive lengths, and embedded malicious URLs. Demonstrates attacks where tool descriptions carry hidden payloads.

### 07-tainted-tool-function
Python `@tool` decorated functions with unsanitized parameter flows to dangerous sinks: `os.system()`, `eval()`, `open()`, `requests.get()`, `cursor.execute()`, and `pickle.loads()`. Detected via AST-based taint analysis.

### 08-transport-insecurity
MCP servers using plaintext HTTP, disabled TLS validation (`NODE_TLS_REJECT_UNAUTHORIZED=0`), deprecated SSE transport, and session tokens exposed in URL query strings.

### 09-a2a-insecure-agent
Agent-to-Agent (A2A) protocol agent card with exposed internal capabilities, no authentication, missing input schemas, HTTP endpoints, excessive JWT token lifetime, and disabled signature verification.

### 10-supply-chain-risks
MCP server packages fetched via npx/uvx without version pinning, npm packages with dangerous `postinstall` scripts, and missing lockfiles.

### 11-legal-compliance
Projects using copyleft (AGPL-3.0) licenses and modules with no declared license field — flagged for commercial use compliance risks.
