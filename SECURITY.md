# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AgentAuditKit, please report it responsibly. **Do not open a public GitHub issue.**

### Preferred Channel

**GitHub Security Advisories** — [report a vulnerability privately](https://github.com/sattyamjjain/agent-audit-kit/security/advisories/new).

This is the only channel that works today, and it is the one to use. Private
vulnerability reporting is enabled on this repository, so the form is open to
anyone with a GitHub account; the report stays private to you and the maintainer
until an advisory is published.

> **`security@agentauditkit.io` does not receive mail.** It has been listed here
> as a contact, but `agentauditkit.io` has never been registered — it returns
> NXDOMAIN, with no MX record — so anything sent there bounces. It is kept in
> this document only to say so, because the address still appears in
> `CODE_OF_CONDUCT.md` and throughout the changelog history, and a reader who
> finds it there deserves to learn it is dead from the security policy rather
> than from a bounce message. It will become live if and when the domain is
> registered.

### What to Include

- A clear description of the vulnerability.
- Steps to reproduce the issue.
- The potential impact (e.g., data exposure, privilege escalation, false negatives).
- Any suggested fix, if you have one.

### Response Expectations

AgentAuditKit is maintained by one person as an open-source project, so there is
**no guaranteed response clock** — a fixed-hours SLA would be a promise we can't
always keep. What we commit to instead is best-effort triage, prioritised by
severity:

- **Acknowledgment** — we reply as soon as we reasonably can. Critical reports
  are read first.
- **Assessment** — confirmed reports are triaged by severity; the most serious
  jump the queue.
- **Fix** — once confirmed, a fix or a documented mitigation ships in an
  upcoming release, and critical fixes are fast-tracked.

We will coordinate disclosure with you and keep you posted on progress. If you
want credit, we will include your name in the advisory and changelog. If your
own compliance program needs a contractual response SLA, don't rely on this
project for it — run your own review in parallel.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release (0.3.x) | Yes |
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
