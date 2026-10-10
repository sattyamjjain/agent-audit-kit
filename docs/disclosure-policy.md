# Coordinated disclosure policy

agent-audit-kit publishes the **MCP Security Index**, an automated
leaderboard grading public MCP servers. Before a finding is ever visible
on that leaderboard, we follow this policy.

## Reporting to maintainers

When our weekly crawl discovers a previously-unseen finding, we:

1. Open a **private** security advisory (or private issue) on the
   affected repository as soon as we reasonably can after the scan that
   discovered it — best-effort, prioritised by severity, with no fixed
   clock (this is a solo-maintained project).
2. Include: the rule ID (e.g. `AAK-MCP-011`), the file + line pointer,
   the remediation text the scanner carries, the CVSS-estimated severity,
   and a link to this policy.
3. If no private-issue channel is available, we email the addresses
   listed in `SECURITY.md` / `security@<domain>` / the last-committing
   author address — in that order.
4. Record the notice in
   [`benchmarks/disclosure_ledger.json`](https://github.com/sattyamjjain/agent-audit-kit/blob/main/benchmarks/disclosure_ledger.json):
   the date and the channel, nothing else. That file is public, so it
   never holds rule IDs, email addresses or advisory links. The index
   reads its 90-day clock from this record and from nothing else.

## Disclosure timeline

- **Day 0:** the private notice is sent and recorded in the ledger. A
  server whose maintainer has not been notified has no Day 0: its
  rule-level detail stays withheld however long it has been in the
  index.
- **Day 30:** reminder if no response or fix yet.
- **Day 60:** second reminder.
- **Day 90:** the server's rule IDs and per-rule counts are added to
  its public card on the MCP Security Index, with the first weekly
  snapshot on or after day 90 that includes the server. File and line
  locations are not published. The maintainer is notified again
  24 hours before publication.
- **Maintainer fix earlier:** if the maintainer ships a fix before
  day 90, we record the date as `fixed_at` and the detail is published
  with the next weekly snapshot after it, with a thank-you credit.

Reminders, the 24-hour heads-up and the credit are sent by hand. The
index automates only the dates: it withholds detail until the ledger
says the 90 days have passed or a fix has landed.

## What we publish during embargo

Until then, a server's grade can still shift (e.g. from **B** to
**C**), but its public card and its row in `data/index.json` show only
the aggregate severity counts, not the rule IDs. Any research-grade
detail is held until embargo expiry.

## What we do *not* do

- We do not publish proof-of-concept exploits.
- We do not publish findings against projects under active coordinated
  disclosure with another party (we honor the earliest embargo).
- We do not accept bug bounties.

## Contact

Security reports about agent-audit-kit itself: open a private advisory
at <https://github.com/sattyamjjain/agent-audit-kit/security/advisories>.
This is the only supported channel. It creates a timestamped, triaged
record, and the 90-day clock for a report about agent-audit-kit runs
from that record.

## Scope

This policy applies only to detections produced by agent-audit-kit's
automated scanners and to the MCP Security Index published from those
scans. Hand-authored research we happen to come across is reported via
the affected project's own policy and has its own timeline.

## Changes

| Date | Change |
|---|---|
| 2026-04-18 | Initial version (v0.3.0 launch). 90-day embargo. |
| 2026-10-10 | The clock starts at the recorded private notice (`benchmarks/disclosure_ledger.json`), not at first scan. Until 2026-10-10 the index restarted it every weekly run, so nothing ever reached day 90, and `data/index.json` carried the rule IDs of withheld servers. Servers not yet notified now stay withheld, `data/index.json` carries no rule IDs while a server is withheld, and the doc says which steps are manual. |
