# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AgentAuditKit, please report it responsibly. **Do not open a public GitHub issue.**

### Preferred Channel

**GitHub Security Advisories** — [report a vulnerability privately](https://github.com/sattyamjjain/agent-audit-kit/security/advisories/new).

This is the only channel that works today, and it is the one to use. Private
vulnerability reporting is enabled on this repository, so the form is open to
anyone with a GitHub account; the report stays private to you and the maintainer
until an advisory is published.

> **`security@agentauditkit.io` does not receive mail.** It was listed here as a
> contact, but `agentauditkit.io` has never been registered — it returns NXDOMAIN,
> with no MX record — so anything sent there bounced silently.
>
> As of v0.3.97 it is no longer offered as a route anywhere in this repository.
> `CODE_OF_CONDUCT.md` now names a working conduct contact, and the only places
> the string survives are the changelog history and the `mailto:`/domain
> exclusion in `.github/workflows/link-check.yml` that keeps that history from
> failing a link check. Those are deliberate: rewriting changelog entries to hide
> a past mistake would be worse than the mistake.
>
> This paragraph is the one remaining live mention, and it exists so a reader who
> greps the changelog, finds the address, and comes looking learns it is dead from
> the security policy rather than from a bounce message. Nothing here is waiting
> on a domain registration; the GitHub Security Advisories link above is the
> channel.

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

### Triage targets

CI tracks the `cve-response` queue against these targets, counted from the day an
issue is opened. They are targets, not an SLA: when one is missed, the daily ageing
check goes red. It doesn't block a release, and it isn't a promise to you.

| Severity (CVSS v3.1) | Triage target |
|---|---|
| Critical (9.0 and above) | 3 days |
| High (7.0 to 8.9) | 7 days |
| Medium (4.0 to 6.9) | 21 days |
| Low (below 4.0) | 60 days |

A report deferred to a stated date is judged against that date instead. The budgets
live in [`scripts/check_cve_ageing.py`](scripts/check_cve_ageing.py), and the measured
response times (median and p90) are in [`docs/cve-latency.md`](docs/cve-latency.md).

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release (0.6.x) | Yes |
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
