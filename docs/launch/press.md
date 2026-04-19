# Press outreach drafts (The Register / Dark Reading / SecurityWeek / The Hacker News)

Send these **24 hours before** the Tuesday 13:00 UTC public launch. Ask
for a same-day embargo so they publish at or just after launch.

## One-paragraph pitch (pasted into every email)

> Subject: Embargoed briefing — 500-server MCP security survey + OSS
> scanner launching Tue {date}
>
> Hi {first name},
>
> I'm launching an OSS static scanner and weekly public leaderboard
> for Model Context Protocol (MCP) servers on Tuesday. The leaderboard
> is seeded with 500 public MCP implementations; {N}% have the
> CVE-2026-33032-class auth-bypass pattern, {M}% have outbound SSRF in
> tool handlers, {K}% are shipping hook scripts with the CVE-2025-59536
> shape still present. Full dataset: {redacted URL}.
>
> Headline angle: MCP has gone from experimental protocol (2024) to
> the tool-call substrate for every major vendor (Anthropic, OpenAI,
> Google, AWS Bedrock, Azure AI Foundry) in 18 months. 30+ CVEs filed
> in Jan–Feb 2026 alone. Commercial scanner market consolidated
> around Snyk (acquired Invariant Labs June 2025). Our angle: OSS,
> air-gap friendly, compliance-evidence output mapped to EU AI Act
> Article 15 (cybersecurity + robustness obligations apply Aug 2
> 2026), SOC 2, ISO 27001/42001, HIPAA, NIST AI RMF.
>
> Happy to share the raw per-server dataset under embargo until
> Tuesday 13:00 UTC. I can also make the maintainer-fix rate, the
> per-category breakdown, or the disclosure policy (90-day window)
> available as angles if they're more interesting than the headline
> numbers.
>
> Founder contact: {your-public-email}
> Repo: https://github.com/sattyamjjain/agent-audit-kit
> Leaderboard: https://mcp-security-index.com/
>
> Thanks,
> {Sattyam}

## Target reporters (research before sending)

- **The Register** — Richard Speed, Iain Thomson, Jessica Lyons
- **Dark Reading** — Jai Vijayan, Kelly Jackson Higgins, Becky Bracken
- **SecurityWeek** — Eduard Kovacs, Ionut Arghire
- **The Hacker News** — Ravie Lakshmanan

> Check each reporter's last 5 pieces. If they've covered an LLM
> security story in the last 90 days, pitch to them. If not, skip —
> cold outreach to a generalist is wasted reach.

## What to include in the follow-up email

- Link to embargoed access to the dataset (`mcp-security-index.com/press`)
- One-pager PDF: auditor-ready compliance mapping (generate with
  `agent-audit-kit report . --framework eu-ai-act --format pdf`)
- Founder bio, 1 paragraph
- Technical contact for fact-checking (you)
- Offer a 30-min Zoom briefing before launch

## Don't

- Don't send the same email to 50 reporters. One per outlet, tailored
  to their beat.
- Don't over-promise novelty — the 82% path-traversal stat is from the
  2,614-server academic survey, not ours. Cite it as such.
- Don't share the full per-server breakdown publicly before the 90-day
  disclosure window closes — press drops can reveal vulnerable servers
  faster than the policy allows.

## Post-launch

If nobody picks up the launch in the first 48 hours, do NOT pivot
strategy. Keep shipping weekly blog posts, weekly index snapshots, and
weekly CVE-response shipments. Inbound press interest correlates with
the boring-reliable pattern more strongly than with launch bursts.
