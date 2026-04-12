# AgentAuditKit: Market Research & Growth Strategy
**Date**: April 12, 2026 | **Version**: v0.2.0 | **Current stars**: 1

---

## PART 1: WHERE YOU STAND (Competitive Landscape)

### Direct Competitor Matrix

| Tool | Owner | Stars | Offline | Rules | OWASP Coverage | Key Differentiator |
|------|-------|-------|---------|-------|----------------|-------------------|
| **Snyk Agent Scan** (ex mcp-scan) | Snyk (acquired Invariant Labs) | 2,107 | No (API calls) | 15+ detectors | Partial | Auto-discovers agents across Claude/Cursor/Windsurf; enterprise MDM scanning |
| **Microsoft Agent Governance Toolkit** | Microsoft | 959 (10 days old) | Yes | Policy engine | 10/10 Agentic | Runtime enforcement (<0.1ms); Rust+Go+Python SDKs; LangChain/CrewAI hooks |
| **Cisco MCP Scanner** | Cisco AI Defense | 881 | No (LLM-as-judge) | YARA + LLM | Partial | Three scan engines; supply-chain focus |
| **Proximity** | fr0gger (Nova) | 287 | Yes | NOVA rules | Partial | Prompt/tool/resource enumeration |
| **rodolfboctor/mcp-scan** | rodolfboctor | 22 | Yes | Partial | Partial | Scans 10 AI client configs for secrets/CVEs |
| **qsag-core** | Neoxyber | 0 | Yes | New | Agentic Top 10 | Ghost agent detection; very new |
| **agent-audit-kit** | **You** | **1** | **Yes (fully)** | **77 rules, 13 scanners** | **MCP+Agentic+LLM (triple)** | Widest static rule set; fully offline; triple OWASP |

### Commercial Players

| Company | Product | Notes |
|---------|---------|-------|
| **Pillar Security** | Pillar Platform | Full lifecycle: discovery, red-team, runtime guardrails, compliance. Enterprise SaaS. |
| **Enkrypt AI** | mcpscan.ai | Freemium SaaS. Found 33% of 1,000 servers critically vulnerable. CI/CD integration. |
| **Protect AI** (Palo Alto) | Guardian + ModelScan | Acquired by Palo Alto. Model-level scanning, broader AI security. |
| **Snyk** | Agent Scan + Snyk Evo | Enterprise background scanning via MDM/CrowdStrike. Central dashboard. |

### Your Defensible Advantages

1. **Fully offline** -- Snyk, Cisco, Enkrypt all phone home. You run air-gapped. Enterprises with classified environments need this.
2. **77 rules across 13 scanners** -- Widest static rule set in OSS. Snyk has 15+ detectors, Cisco uses YARA + cloud APIs.
3. **Triple OWASP coverage** -- No other OSS tool maps to MCP Top 10 + Agentic Top 10 + LLM Top 10 simultaneously.
4. **Zero dependencies** -- Only click + pyyaml. Competitors pull in LLM APIs, cloud SDKs.
5. **SARIF output** -- GitHub Security tab integration out of the box.

### Your Gaps

1. **Stars/visibility** -- 1 star vs. 2,107 (Snyk), 959 (Microsoft), 881 (Cisco). Brand distribution matters.
2. **No runtime protection** -- Microsoft and Pillar offer runtime policy enforcement. You're static/pre-deploy only.
3. **No auto-discovery** -- Snyk auto-discovers configs across Claude/Cursor/Windsurf/Gemini.
4. **No enterprise dashboard** -- Snyk offers central MDM scanning. Pillar offers compliance reporting.

---

## PART 2: THE MARKET OPPORTUNITY

### By the Numbers

| Metric | Value | Source |
|--------|-------|-------|
| MCP servers in the wild | 10,000+ active, 16,000+ indexed | contextstudios.ai, WorkOS |
| MCP SDK downloads | 97M+ monthly (Python+TS combined) | devstarsj.github.io |
| MCP CVEs in 2026 | 30+ in first 60 days alone | heyuan110.com |
| Servers vulnerable to SSRF | 36.7% | Adversa AI |
| Implementations with path traversal risk | 82% | Multiple sources |
| Developers using AI coding assistants | 74% | JetBrains 2026 survey |
| Enterprise apps with AI agents by end 2026 | 40% (up from <5% in 2025) | Gartner |
| Agentic AI spending 2026 | $201.9B (+141% YoY) | CyberArk |
| AI cybersecurity CAGR | 74% | Multiple sources |

### Community Pain Points (What People Are Asking For)

1. **"How do I know if an MCP server is safe?"** -- No universal scanning/vetting pipeline exists
2. **"We need npm audit for MCP"** -- Your exact tagline. Community is asking for this.
3. **"Traditional SAST is blind to MCP"** -- Semgrep/Trivy/Checkov miss tool poisoning, shadow configs, agent-specific vectors
4. **"We need CI/CD integration"** -- Pre-merge checks that scan MCP configs like Snyk scans package.json
5. **"Tool description integrity"** -- Nothing validates tool descriptions against known-good baselines (you have pinning!)

### Key OWASP Frameworks You Cover

- **OWASP MCP Top 10** (MCP01-10) -- Protocol-specific risks. Finalized.
- **OWASP Top 10 for Agentic Applications 2026** -- Agent-level risks. 100+ expert contributors.
- **OWASP LLM Top 10** -- Model-level risks. Industry standard.

You are the **only OSS tool claiming coverage across all three**. This is your moat.

---

## PART 3: EXAMPLES TO ADD (Credibility Builders)

### Priority 1: `examples/vulnerable-configs/` (HIGH IMPACT)

Create 6-8 intentionally vulnerable MCP configs with expected scan results. Each file should demonstrate a specific vulnerability category:

```
examples/
  vulnerable-configs/
    01-no-auth-server.json           # MCP server with no authentication
    01-no-auth-server.expected.json  # What agent-audit-kit finds
    02-shell-injection.json          # Command injection in server args
    03-tool-poisoning.json           # Invisible Unicode in tool descriptions
    04-hardcoded-secrets.json        # API keys in plain text
    05-excessive-permissions.json    # Wildcard allow rules, no deny
    06-rug-pull-config.json          # Tool definition changed after pinning
    07-path-traversal.json           # File access outside project root
    08-tainted-tool-function.py      # Python @tool with unsanitized param -> eval()
    README.md                        # Explains each vulnerability + OWASP mapping
```

**Why**: damn-vulnerable-MCP-server (1,277 stars) proves people want this. Self-contained examples in YOUR repo let people try without cloning another project.

### Priority 2: Scan damn-vulnerable-MCP-server (HIGH IMPACT)

Run agent-audit-kit against `harishsg993010/damn-vulnerable-MCP-server` (1,277 stars) and publish results as a case study:

```
examples/
  case-studies/
    damn-vulnerable-mcp/
      README.md          # What we scanned, what we found, annotated results
      scan-results.json  # Raw JSON output
      scan-results.sarif # SARIF output
```

**Why**: This is the recognized MCP security testbed. Showing you detect its vulnerabilities is the single highest-impact credibility demo.

### Priority 3: Real-World Popular Server Scan (MEDIUM)

Scan configs from popular MCP server repos and show results:

```
examples/
  real-world-scans/
    playwright-mcp/      # microsoft/playwright-mcp (30K stars)
    github-mcp-server/   # github/github-mcp-server (28K stars)
    mcp-toolbox/         # googleapis/mcp-toolbox (14K stars)
    README.md            # Summary: "We scanned the top 3 MCP servers..."
```

**Why**: "We scanned 50 popular MCP servers and found X" is the #1 content format that gets HN upvotes and newsletter pickups.

### Priority 4: CI Integration Examples (MEDIUM)

```
examples/
  ci-integration/
    github-actions-sarif.yml   # Full workflow: scan + upload SARIF
    gitlab-ci-scan.yml         # GitLab CI stage
    pre-commit-config.yaml     # Pre-commit hook example
    docker-one-liner.sh        # docker run one-liner
```

### Priority 5: Comparison Table (MEDIUM)

Add to README or docs:

| Capability | agent-audit-kit | Semgrep | Trivy | Snyk Agent Scan | Cisco MCP Scanner |
|-----------|----------------|---------|-------|-----------------|-------------------|
| MCP config scanning | 77 rules | Generic YAML only | N/A | 15+ detectors | YARA + LLM |
| Tool poisoning detection | Yes (Unicode + semantic) | No | No | Yes | Yes (LLM) |
| Rug-pull / pinning | SHA-256 pinning + verify | No | No | No | No |
| Python @tool taint analysis | AST-based | Yes (generic) | No | No | No |
| OWASP MCP Top 10 | 10/10 | N/A | N/A | Partial | Partial |
| OWASP Agentic Top 10 | 10/10 | N/A | N/A | Partial | Partial |
| Fully offline | Yes | Yes | Yes | No (API) | No (API + LLM) |
| SARIF output | Yes | Yes | Yes | No | No |
| GitHub Action | Yes | Yes | Yes | No | No |

### Priority 6: SARIF Screenshot in README

Add a screenshot showing findings appearing as inline PR annotations in GitHub's Security tab. Visual proof > documentation.

### Priority 7: Benchmark Suite Expansion

Expand `/benchmarks/` with a `vulnerable-corpus/` containing test cases with known-good expected outputs. Publish detection rates:

> "Detects 12/12 tool poisoning variants, 8/8 secret exposure patterns, 6/6 trust boundary violations"

---

## PART 4: MARKETING PLAYBOOK

### Week 1-2: Repo Optimization (Do This First)

- [ ] **Add `examples/` directory** with vulnerable configs + expected outputs (Priority 1 above)
- [ ] **Add comparison table** to README (Priority 5)
- [ ] **Add SARIF screenshot** to README (Priority 6)
- [ ] **Embed demo GIF** at top of README (you have `demo.gif` -- make sure it's in the README)
- [ ] **Submit to awesome lists**: [awesome-security](https://github.com/sbilly/awesome-security), [awesome-opensource-security](https://github.com/CaledoniaProject/awesome-opensource-security), [awesome-github-actions-security](https://github.com/johnbillion/awesome-github-actions-security)
- [ ] **Add `.pre-commit-hooks.yaml`** to repo root (every top security scanner ships this -- Semgrep, Checkov, osv-scanner)
- [ ] **Publish GitHub Action** to the Marketplace (you have `action.yml` -- just need marketplace listing)
- [ ] **GitHub topics**: You already have 16 good topics. Add: `owasp-mcp-top-10`, `devsecops`, `llm-security`

### Week 3-4: Content Blitz (2 Posts/Week)

**Content that works** (ranked by expected impact):

1. **"We scanned 50 popular MCP servers. Here's what we found."** -- Original research. This is the #1 HN format.
2. **"CVE-2026-21852: How a single config flag leaked your source code"** -- CVE deep-dive with your tool detecting it.
3. **"The npm audit for AI agents: Why MCP needs security tooling"** -- Problem framing piece.
4. **"Tool poisoning: How invisible Unicode in MCP tool descriptions steals your data"** -- Specific attack demo.
5. **Benchmark comparison** -- "agent-audit-kit vs. Snyk Agent Scan vs. Cisco MCP Scanner" (be fair, highlight niches).

**Where to publish**:
- **Dev.to** -- Your `devto-article.md` is ready. Publish it.
- **Medium** -- Cross-post with canonical URL to Dev.to
- **Your own blog** (if you have one) -- SEO long game

### Week 5: Coordinated Launch Day (Tuesday-Thursday)

**Timing**: Tuesday-Thursday, 8-10am Pacific. All channels same day.

**Hacker News** (highest technical engagement):
- You already have `show-hn.md` -- it's good. Title: `Show HN: AgentAuditKit -- 77-rule security scanner for MCP agent pipelines (OSS)`
- Post the first comment IMMEDIATELY (your existing draft works)
- Need 8-10 upvotes in 30 minutes to reach top 10
- Lago hit #1 but 90% of their HN posts flopped -- persistence matters. If first attempt doesn't work, try again next week with a different angle.

**Reddit** (same day):
- You have drafts for r/netsec, r/devops, r/machinelearning -- all ready
- r/netsec: Technical deep-dive angle (CVE focus)
- r/devops: CI/CD integration angle (GitHub Action)
- r/machinelearning: AI security angle
- Also post to: r/LocalLLaMA, r/ClaudeAI, r/mcp (if it exists)

**Twitter/X**:
- Your thread is ready. Tag: @AshishRajan_ (AI Security Podcast), @AnthropicAI, @OWASPFoundation, @SlowMist_Team
- Add demo GIF to first tweet

**Dev.to**:
- Publish `devto-article.md`

### Week 6-8: Integration-Driven Growth

1. **GitHub Actions Marketplace** -- 158K+ repos use CodeQL scanning. Being in the Marketplace is the #1 passive discovery channel.
2. **Pre-commit hook** -- Zero-config adoption for existing workflows
3. **GitLab CI template** -- You already have this (recent commit)
4. **Docker Hub** -- Publish the Docker image for easy container-based scanning
5. **PyPI visibility** -- Make sure pyproject.toml metadata (keywords, classifiers) is optimized for search

### Ongoing: Community & Outreach

**Podcasts to pitch**:
- [AI Security Podcast](https://www.aisecuritypodcast.com/) (Ashish Rajan) -- covered MCP risks at RSAC 2025+2026. Perfect fit.
- Darknet Diaries -- MCP CVE storytelling angle
- Software Engineering Daily -- OSS security tooling angle

**Newsletters to submit to**:
- [Help Net Security monthly roundup](https://www.helpnetsecurity.com/2025/10/30/hottest-cybersecurity-open-source-tools-of-the-month-october-2025/) of hot OSS security tools
- tl;dr sec (Clint Gibler's newsletter -- massive reach in appsec)
- The Pragmatic Engineer (if you can get featured)

**Product Hunt**:
- Works for security tools -- Aikido Security hit #1 Product of the Day
- Prep 2 months ahead; first 2 hours are critical
- Schedule for Week 8-10

**Conferences**:
- RSAC 2026 (OWASP GenAI summit happening there)
- BSides (local BSides events for talks)
- OWASP chapter meetings (virtual talks)

**Community building**:
- GitHub Discussions (enable on the repo)
- `good-first-issue` labels on 5-10 issues for contributor onboarding
- Response SLA: 48 hours on issues
- Consider a Discord for community

---

## PART 5: STRATEGIC POSITIONING

### Your Tagline (Keep It)

> "The missing `npm audit` for AI agents."

This is perfect. It's the exact phrase the community is using when asking for this tool.

### Your Moat (Defend These)

1. **Triple OWASP coverage** -- Nobody else has MCP + Agentic + LLM Top 10. Keep this current.
2. **Fully offline** -- Enterprises with air-gapped environments need this. Snyk/Cisco can't compete here.
3. **Rule depth** -- 77 rules is 5x Snyk's detector count. Keep adding rules.
4. **Pinning/verification** -- SHA-256 tool pinning + verify is unique. Nobody else does rug-pull detection.

### Your Narrative (For All Content)

> In early 2026, 30 MCP CVEs dropped in 60 days. CVE-2026-21852 demonstrated source code exfiltration via a single Claude Code config flag. Every AI coding assistant adopted MCP with zero security tooling. We built the scanner that was missing.

### Growth Milestones to Target

| Milestone | Strategy | Timeline |
|-----------|----------|----------|
| 0 -> 100 stars | Launch day (HN + Reddit + Twitter) + examples directory | Week 5-6 |
| 100 -> 500 stars | Content blitz + awesome-list submissions + podcast appearances | Month 2-3 |
| 500 -> 1,000 stars | Original research post ("We scanned 50 MCP servers") + Product Hunt | Month 3-4 |
| 1,000 -> 5,000 stars | Enterprise adoption stories + conference talks + community contributors | Month 4-8 |

### The Biggest Threat

**Microsoft's Agent Governance Toolkit** (959 stars in 10 days). It has brand distribution you can't match. But it's runtime-focused (policy enforcement), not static analysis. Position yourself as complementary: "Use agent-audit-kit in CI/CD (pre-deploy) + Microsoft AGT at runtime (post-deploy)."

### The Biggest Opportunity

**Nobody has published "We scanned N MCP servers and here's what we found."** First-mover on original research gets massive HN/newsletter traction. Do this ASAP.

---

## PART 6: IMMEDIATE NEXT ACTIONS (Prioritized)

### This Week

1. **Create `examples/vulnerable-configs/`** with 6-8 vulnerable configs + expected outputs
2. **Scan damn-vulnerable-MCP-server** and publish results as a case study
3. **Add comparison table** to README
4. **Add `.pre-commit-hooks.yaml`** to repo root
5. **Publish Dev.to article** (draft is ready)

### Next Week

6. **Publish GitHub Action to Marketplace**
7. **Submit to 3 awesome lists**
8. **Scan top 10 popular MCP servers** and write the "original research" blog post
9. **Post Show HN** (Tuesday-Thursday, 8-10am Pacific)
10. **Post Reddit threads** (same day as HN)
11. **Post Twitter thread** (same day)

### Month 2

12. **Pitch AI Security Podcast**
13. **Submit to Help Net Security + tl;dr sec newsletter**
14. **Prep for Product Hunt launch**
15. **Enable GitHub Discussions + add good-first-issue labels**
16. **Write 2 more blog posts** (CVE deep-dive + tool poisoning demo)

---

## Key Sources

- [Snyk Agent Scan](https://github.com/snyk/agent-scan) | [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | [Microsoft AGT](https://github.com/microsoft/agent-governance-toolkit)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) | [OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [damn-vulnerable-MCP-server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) (1,277 stars) | [vulnerable-mcp-servers-lab](https://github.com/appsecco/vulnerable-mcp-servers-lab) (248 stars)
- [30 CVEs in 60 Days](https://www.heyuan110.com/posts/ai/2026-03-10-mcp-security-2026/) | [CVE-2026-21852](https://borncity.com/win/2026/03/02/vulnerabilities-cve-2025-59536-cve-2026-21852-in-anthropic-claude-code/) | [CVE-2026-32211](https://dev.to/michael_onyekwere/cve-2026-32211-what-the-azure-mcp-server-flaw-means-for-your-agent-security-14db)
- [Gartner: 40% enterprise AI agents by 2026](https://www.gartner.com/en/newsroom/press-releases/2025-08-26-gartner-predicts-40-percent-of-enterprise-apps-will-feature-task-specific-ai-agents-by-2026)
- [74% devs use AI coding assistants](https://blog.jetbrains.com/research/2026/04/which-ai-coding-tools-do-developers-actually-use-at-work/)
- [How Lago got 1,000 GitHub stars](https://www.getlago.com/blog/how-we-got-our-first-1000-github-stars)
- [AI Security Podcast](https://www.aisecuritypodcast.com/) | [tl;dr sec newsletter](https://tldrsec.com/)
- [Adversa AI MCP Top 25](https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/) | [Unit 42 MCP Attacks](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [CoSAI MCP Security Guide](https://www.coalitionforsecureai.org/securing-the-ai-agent-revolution-a-practical-guide-to-mcp-security/)
