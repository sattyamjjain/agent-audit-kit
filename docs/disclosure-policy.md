# Coordinated disclosure policy

agent-audit-kit publishes the **MCP Security Index**, an automated
leaderboard grading public MCP servers. Before a finding is ever visible
on that leaderboard, we follow this policy.

## Reporting to maintainers

When our weekly crawl discovers a previously-unseen finding, we:

1. Open a **private** security advisory (or private issue) on the
   affected repository within **48 hours** of the scan that discovered
   it.
2. Include: the rule ID (e.g. `AAK-MCP-011`), the file + line pointer,
   the remediation text the scanner carries, the CVSS-estimated severity,
   and a link to this policy.
3. If no private-issue channel is available, we email the addresses
   listed in `SECURITY.md` / `security@<domain>` / the last-committing
   author address — in that order.

## Disclosure timeline

- **Day 0:** private notice sent.
- **Day 30:** reminder if no response or fix yet.
- **Day 60:** second reminder.
- **Day 90:** the finding is added to the public per-server card on the
  MCP Security Index with full evidence. The maintainer is notified
  again 24 hours before publication.
- **Maintainer-fix earlier:** if the maintainer ships a fix before
  day 90, the finding is published the day the fix lands, with a
  thank-you credit.

## What we publish during embargo

During the 90-day window, a server's grade can still shift (e.g. from
**B** to **C**), but the public per-server card shows only the
aggregate counts, not the specific rule IDs or file locations. Any
research-grade detail is held until embargo expiry.

## What we do *not* do

- We do not publish proof-of-concept exploits.
- We do not publish findings against projects under active coordinated
  disclosure with another party (we honor the earliest embargo).
- We do not accept bug bounties.

## Contact

Security reports about agent-audit-kit itself: open a private advisory
at <https://github.com/sattyamjjain/agent-audit-kit/security/advisories>.
This is the only supported channel — it creates a timestamped, triaged
record and starts the 90-day disclosure clock automatically.

## Scope

This policy applies only to detections produced by agent-audit-kit's
automated scanners and to the MCP Security Index published from those
scans. Hand-authored research we happen to come across is reported via
the affected project's own policy and has its own timeline.

## Changes

| Date | Change |
|---|---|
| 2026-04-18 | Initial version (v0.3.0 launch). 90-day embargo. |
