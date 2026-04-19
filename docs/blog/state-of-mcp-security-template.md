# State of MCP Security — Week YYYY-WW

_A template. Every Monday we publish one of these tied to the latest
MCP Security Index snapshot._

## Top-line

- Servers in index: **N**
- Median grade: **X**
- New criticals this week: **N**
- Maintainers notified under embargo: **N**

## What changed

- Highest-impact new finding this week: `AAK-XXX-NNN` (NVD: `CVE-YYYY-NNNNN`)
- Shipped detection for it in agent-audit-kit vX.Y.Z (N hours after NVD disclosure)

## Trend

![grade distribution by week](../site/trend.svg)

Short paragraph summarizing movement — which classes of bugs are up/down,
whether the median shifted, anything notable about maintainer fix latency.

## The worst 5 publicly-graded servers this week

_Only includes servers where the 90-day disclosure window has expired or
maintainers published the fix themselves. Everything else is embargoed._

| # | Server | Grade | Top finding |
|---|---|---|---|
| 1 |  |  |  |
| 2 |  |  |  |
| 3 |  |  |  |
| 4 |  |  |  |
| 5 |  |  |  |

## Maintainer shout-outs

Projects that shipped a fix within 30 days of private notice:

- `org/name` — fixed `AAK-XXX-NNN` in 12 days

## What we did *not* publish

N findings are under embargo this week. Details will surface in their
per-server cards once the 90-day window closes.

## Call to action

If you maintain an MCP server:

1. Install agent-audit-kit and run `agent-audit-kit scan .` locally.
2. Open your security advisory inbox — that's the channel we use first.
3. If we have an embargoed finding against your server you'd like to fix
   faster than 90 days, open a Discussion on
   [the agent-audit-kit repo](https://github.com/sattyamjjain/agent-audit-kit/discussions)
   and we'll share the detail immediately.

---

Published by [agent-audit-kit](https://github.com/sattyamjjain/agent-audit-kit).
Raw data: [index.json](../site/data/index.json).
