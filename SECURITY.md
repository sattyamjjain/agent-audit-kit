# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AgentAuditKit, please report it responsibly. **Do not open a public GitHub issue.**

### Preferred Channels

1. **Email:** [security@agentauditkit.io](mailto:security@agentauditkit.io)
2. **GitHub Security Advisories:** [Report a vulnerability](https://github.com/sattyamjjain/agent-audit-kit/security/advisories/new)

### What to Include

- A clear description of the vulnerability.
- Steps to reproduce the issue.
- The potential impact (e.g., data exposure, privilege escalation, false negatives).
- Any suggested fix, if you have one.

### Response Timeline

| Stage | Timeframe |
|-------|-----------|
| Acknowledgment | Within **48 hours** |
| Initial assessment | Within **7 days** |
| Fix released | Within **30 days** (target) |

We will coordinate disclosure with you. If you want credit, we will include your name in the advisory and changelog.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release (0.2.x) | Yes |
| Older releases | No |

Only the latest release receives security updates. We recommend always running the most recent version.

## Scope

The following are in scope for security reports:

- False negatives: a real vulnerability in a scanned project that AgentAuditKit fails to detect.
- Vulnerabilities in AgentAuditKit itself (e.g., code execution via crafted config files).
- Supply chain issues in AgentAuditKit's dependencies.

The following are **out of scope**:

- Findings in projects you scan with AgentAuditKit (report those to the respective project).
- Feature requests (use [GitHub Issues](https://github.com/sattyamjjain/agent-audit-kit/issues) instead).

## Security Best Practices for Users

- Pin AgentAuditKit to a specific version in CI pipelines.
- Review SARIF output before acting on auto-fix suggestions.
- Keep your vulnerability database updated with `agent-audit-kit update`.
