# The State of MCP Security, 2026

**Report version 1.1** · **Published 2026-08-17, revised 2026-10-15** · **Scan date 2026-07-26** · **Corpus:** <!-- report:corpus -->2,303<!-- /report --> distinct public MCP server configs · **Tool:** AgentAuditKit (offline, deterministic) · **Licence:** Apache-2.0 (same as the tool)

> **Stable identity.** Cite this document as *The State of MCP Security, 2026*,
> version 1.1. The version changes only when a number in it changes; re-running the
> pipeline on the same committed corpus reproduces this exact file, so version 1.1
> always refers to these numbers. Version 1.1 supersedes version 1.0 (2026-08-17):
> the corpus is the same, and corrected rules and a corrected scan harness moved
> the figures. [What changed in v1.1](#what-changed-in-v11) lists every number that
> moved and why. See [How to cite this report](#how-to-cite-this-report).

We statically scanned **<!-- report:corpus -->2,303<!-- /report --> distinct public Model Context Protocol server
configurations** — the largest snapshot we know of — and measured what fraction
fail each security rule family. The headline: **more than half of public MCP
servers declare a remote endpoint with no authentication.** Every number below
carries its numerator, denominator, and — where a metric is not computable for
the whole corpus — its coverage.

**Methods in one paragraph.** The corpus was collected **2026-07-26** from two
provenance-tracked sources — <!-- report:corpus-crawl -->664<!-- /report --> GitHub-crawled `.mcp.json` files
(`benchmarks/data/`) and <!-- report:corpus-registry -->1,639<!-- /report --> latest-version servers from the official MCP Registry
(`registry.modelcontextprotocol.io`) — deduplicated by SHA-256 of the normalised
JSON. Each config was written alone into an empty directory as `.mcp.json`, scanned
with AgentAuditKit's engine and graded on the same penalty-based A–F scale as
`aak score`. The scan makes **zero network calls** and is **deterministic**: the
same corpus yields a byte-identical `results.json` across runs and Python hash
seeds. Reproduce the published numbers with `make report` (offline); refreshing the
corpus itself is a separate, explicitly network step
(`python research/state-of-mcp-2026/fetch_registry.py --target 5000`). Full detail,
including what a config-only corpus cannot measure, is in [Method](#method) and
[Limitations](#limitations).

## Headline findings

| Finding | Rule | Share of corpus |
|---------|------|----------------:|
| Remote MCP server with **no authentication** | `AAK-MCP-001` (critical) | **<!-- report:noauth-pct -->50.6<!-- /report -->%**, <!-- report:noauth-n -->1,166<!-- /report --> of <!-- report:corpus -->2,303<!-- /report --> |
| Carries at least one **critical** finding | — | <!-- report:critical-pct -->51.4<!-- /report -->% (<!-- report:critical-n -->1,184<!-- /report -->) |
| Fetches and executes a package at launch via `npx`/`uvx` (supply-chain surface) | `AAK-MCP-005` (medium) | <!-- report:mcp005-pct -->19.5<!-- /report -->% (<!-- report:mcp005-n -->450<!-- /report -->) |
| OAuth surface with **no RFC 9728** Protected-Resource-Metadata discovery | `AAK-OAUTH-008` (low) | <!-- report:oauth008-pct -->18.4<!-- /report -->% (<!-- report:oauth008-n -->424<!-- /report -->) |
| Launches a package with **no pinned version** | `AAK-SUPPLY-001` (medium) | <!-- report:supply001-pct -->12.3<!-- /report -->% (<!-- report:supply001-n -->284<!-- /report -->) |
| Command uses a **relative path** (PATH-hijack surface) | `AAK-MCP-006` (medium) | <!-- report:mcp006-pct -->7.8<!-- /report -->% (<!-- report:mcp006-n -->179<!-- /report -->) |
| **stdio launcher injection**: shell interpreter with exec flag / interpolated args | `AAK-MCP-STDIO-LAUNCHER-INJECT-001` (high) | <!-- report:launcher-inject-pct -->2.1<!-- /report -->% (<!-- report:launcher-inject-n -->49<!-- /report -->) |
| Deprecated **SSE** transport (2026-07-28 stateless break) | `AAK-TRANSPORT-003` (medium) | <!-- report:transport003-pct -->2.0<!-- /report -->% (<!-- report:transport003-n -->47<!-- /report -->) |
| **Secret in the env block** (hardcoded credential) | `AAK-MCP-003` (high) | <!-- report:mcp003-pct -->1.3<!-- /report -->% (<!-- report:mcp003-n -->30<!-- /report -->) |
| URL contains an **internal network address** (SSRF surface) | `AAK-MCP-009` (high) | <!-- report:mcp009-pct -->0.1<!-- /report -->% (<!-- report:mcp009-n -->3<!-- /report -->) |

Auth posture, the 2026-07-28 profile:

- **No authentication:** <!-- report:noauth-n -->1,166<!-- /report --> of <!-- report:corpus -->2,303<!-- /report --> (**<!-- report:noauth-pct -->50.6<!-- /report -->%**).
- **RFC 9728 PRM discovery:** <!-- report:rfc9728-n -->0<!-- /report --> of <!-- report:corpus -->2,303<!-- /report --> (**<!-- report:rfc9728-pct -->0.0<!-- /report -->%**). This counts configs
  that reference the discovery document; it does not say whether a server serves
  it. A live probe of the corpus's public endpoints on 2026-10-11 found that more
  than half of those that answered DNS do
  ([AAK-MCP-001 measurement](../../benchmarks/aak_mcp_001/RESULTS.md)).
- **Remote configs:** <!-- report:remote-n -->1,648<!-- /report --> of <!-- report:corpus -->2,303<!-- /report --> (<!-- report:remote-pct -->71.6<!-- /report -->%). Of the <!-- report:inline-auth-d -->424<!-- /report --> that embed an inline
  credential, **<!-- report:inline-auth-n -->424<!-- /report --> of <!-- report:inline-auth-d -->424<!-- /report --> (<!-- report:inline-auth-pct -->100<!-- /report -->%)** hardcode a static secret rather than
  reference an env var or use OAuth.

## Method

### Corpus construction

Two provenance-tracked sources, deduplicated by configuration content (SHA-256
of the normalised JSON):

| Source | Candidates | In corpus |
|--------|-----------:|----------:|
| GitHub-crawled `.mcp.json` files (`benchmarks/data/`) | <!-- report:crawl-candidates -->748<!-- /report --> | <!-- report:corpus-crawl -->664<!-- /report --> |
| Official MCP Registry, latest-version servers (`registry.modelcontextprotocol.io`) | <!-- report:registry-candidates -->1,641<!-- /report --> | <!-- report:corpus-registry -->1,639<!-- /report --> |
| **Combined** | **<!-- report:corpus-candidates -->2,389<!-- /report -->** | **<!-- report:corpus -->2,303<!-- /report -->** |

<!-- report:corpus-duplicates -->85<!-- /report --> byte-duplicate configs and <!-- report:corpus-unparseable -->1<!-- /report --> unparseable file were removed. Registry servers
were fetched on **2026-07-26** via cursor pagination (40-page crawl), filtered to
`isLatest = true` / `status = active`, and each converted to a scannable
`.mcp.json`-shaped config. A server with a remote endpoint becomes one `http` or
`sse` entry for that endpoint, carrying the names of the headers it declares. A
package server launches the release its registry record states:
`npx -y <package>@<version>` for npm, `uvx <package>@<version>` for PyPI, and
`docker run` of the image for OCI. The registry has grown fast — this snapshot is
**<!-- report:registry-servers -->1,641<!-- /report --> distinct latest-version registry servers**, up from 710 on 2026-07-19
(2.3×). Provenance for every registry server — name, version, transport, auth
mode, source URL, fetch date — is recorded in `corpus/registry-manifest.json`,
so each number here is reproducible from the committed manifest without
re-fetching. The manifest is rebuilt offline from the raw registry pages the fetch
cached (`fetch_registry.py --from-cache`), so a change to the conversion does not
move the snapshot.

### Scanning

Each config is written alone into an empty directory as `.mcp.json`, the name the
crawler saved it under and one that every AgentAuditKit scanner that reads MCP
configs opens, then scanned with AgentAuditKit's engine and scored with the same penalty-based A–F grade the
`aak score` command and the MCP Security Index use. The scan is **offline** (zero
network calls) and **deterministic**: the same corpus yields a byte-identical
`results.json` on every run, across Python hash seeds — the property that makes a
published number auditable.

Note on what is and isn't config-detectable: rule families that live in a
client `.mcp.json` — no-auth, launcher injection, relative-path commands, env
secrets, `npx`/`uvx` fetch-execute, unpinned launches, CVE version pins,
transport — fire here. Families that require
**server source** (tool-poisoning `AAK-POISON-*`, taint `AAK-TAINT-*`, the
`AAK-MCP-STDIO-CMD-INJ-*` source detectors) do not fire on a config-only corpus
and are reported as ~0% by construction, not by absence of risk. The MCP CVE
version pins (`agent_audit_kit/scanners/mcp_cve_pins_2026_07.py`, and the older
pins in `supply_chain.py`) fire when a config launches a package at an affected
version, or names one whose fixed version it cannot show, such as an unpinned git
launch. A registry config launches the version its record states, so a pin fires
there only on an affected release.

The top-misconfiguration table and the OWASP MCP tally leave out two advisory
posture rules, `AAK-MCP-ATTEST-001` (deny-by-default attestation, which fires on
nearly every config) and `AAK-MCP-007` (no version pin in `args`), so neither
figure is inflated. `results.json` lists them under `excluded_advisory_rules`, and
its per-rule `rule_hit_rate` keeps them.

### Reproduce

```bash
make report          # refreshes results.json from the committed manifest, offline + deterministic
# or, explicitly:
python research/state-of-mcp-2026/run_report.py \
    --corpus benchmarks/data \
    --registry-manifest research/state-of-mcp-2026/corpus/registry-manifest.json \
    --out research/state-of-mcp-2026/results.json
```

Refreshing the corpus itself (the one network step) is separate:
`python research/state-of-mcp-2026/fetch_registry.py --target 5000`.

At the published run this walk collected **<!-- report:registry-servers -->1,641<!-- /report --> distinct latest-version servers**
(`corpus/registry-manifest.json` → `distinct_latest_servers`, `fetched_at`
**2026-07-26**). `--target 5000` is deliberately larger than that count so the walk
runs to cursor-exhaustion rather than stopping early; the MCP Registry grows over
time, so a later rerun that returns a larger N is registry growth, not a broken
command. (`--target` is kept identical across the Makefile, the fetcher default, and
this document by `tests/test_corpus_target_consistency.py`.)

## Grade distribution (score calibration)

| Grade | Configs | Share |
|:-----:|--------:|------:|
| A | <!-- report:grade-a -->789<!-- /report --> | <!-- report:grade-a-pct -->34.3<!-- /report -->% |
| B | <!-- report:grade-b -->1,279<!-- /report --> | <!-- report:grade-b-pct -->55.5<!-- /report -->% |
| C | <!-- report:grade-c -->96<!-- /report --> | <!-- report:grade-c-pct -->4.2<!-- /report -->% |
| D | <!-- report:grade-d -->52<!-- /report --> | <!-- report:grade-d-pct -->2.3<!-- /report -->% |
| F | <!-- report:grade-f -->87<!-- /report --> | <!-- report:grade-f-pct -->3.8<!-- /report -->% |

n = <!-- report:corpus -->2,303<!-- /report -->. The median config scores **<!-- report:median-grade -->B<!-- /report -->**. **<!-- report:critical-n -->1,184<!-- /report --> (<!-- report:critical-pct -->51.4<!-- /report -->%)** carry at least one
critical-severity finding — driven almost entirely by the no-auth remote server
class. Most public configs are not catastrophic, but the single most common
public posture is *a remote server anyone can call*.

## Why this matters now — and the two wedges

The market backdrop is a supply-chain and trust crisis, not a scanner gap:

- **Shai-Hulud 2.0** — the self-propagating npm worm that republishes legitimate
  packages with a malicious `preinstall` script and uses GitHub infrastructure as
  C2 — compromised **25,000+ repositories across ~350 maintainers** (Zapier,
  PostHog, Postman), with a *Mini Shai-Hulud* resurgence in May 2026 hitting 170+
  npm packages ([Microsoft Security](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)).
  Our finding that **<!-- report:mcp005-pct -->19.5<!-- /report -->% of public MCP configs fetch and execute a package
  at launch through `npx`/`uvx`**, and <!-- report:supply001-pct -->12.3<!-- /report -->% launch one with no pinned version,
  is that same blast radius, one `.mcp.json` away.
- **NSA MCP hardening guidance** — the NSA AISC *MCP Security Design
  Considerations* CSI (U/OO/6030316-26, 2026-05-20) put MCP posture on
  government letterhead. It is prose, not a checklist — so the gap is *evidence*,
  not awareness.

Against that backdrop, two things a free hosted scanner structurally can't match:

1. **Offline + deterministic scanning.** Zero network calls in the default scan
   path; the same input always yields the same finding (no model in the loop), so
   CI diffs, audit re-runs, and regression baselines stay byte-stable. This report
   is itself the proof: every number regenerates identically from the committed
   manifest.
2. **A compliance-evidence crosswalk.** Every rule is mapped — rule by rule — to
   the **NSA MCP Security CSI** control it evidences and its **OWASP Agentic
   Top-10 (2026)** slot (also OWASP MCP Top-10 and EU AI Act), emitted as
   machine-readable evidence: `agent-audit-kit --emit-coverage --format json`
   (see [`docs/coverage.json`](../../docs/coverage.json) and
   [`docs/crosswalk/nsa-csi-owasp-agentic.md`](../../docs/crosswalk/nsa-csi-owasp-agentic.md)).
   That turns a finding into audit evidence an assessor can cite.

We are **not** claiming to be first — public MCP-security surveys and vendor
disclosures predate this. What is offline, deterministic, and standards-mapped is
the combination.

## 2026-07-28 stateless-transport exposure

The ratified 2026-07-28 spec removes the `initialize` handshake and the
`Mcp-Session-Id` header (stateless core). The measurable proxy in a client config
is deprecated **SSE** transport: **<!-- report:transport003-n -->47<!-- /report --> configs (<!-- report:transport003-pct -->2.0<!-- /report -->%)** still declare it
(`AAK-TRANSPORT-003`, from a `type` or `transport` key or an `/sse` endpoint) and
will break when the session model goes. streamable-HTTP dominates the fresh
corpus (<!-- report:transport-http -->1,726<!-- /report --> server entries) over stdio (<!-- report:transport-stdio -->1,347<!-- /report -->) and SSE (<!-- report:transport-sse -->62<!-- /report -->).

## Responsible-disclosure posture

Findings here are aggregate and de-identified; no server is named as vulnerable.
The corpus is public registry metadata and public GitHub `.mcp.json` files. AAK's
90-day [disclosure policy](../../docs/disclosure-policy.md) governs any per-server
notification.

## Limitations

- **Config-only for source-based families.** Tool-poisoning and taint need server
  source; their ~0% here is a coverage boundary, not an all-clear (stated above).
- **Registry snapshot is a 40-page crawl** (<!-- report:registry-servers -->1,641<!-- /report --> distinct latest); the registry
  is larger and still growing, so the true corpus is a floor.
- **Registry configs are synthesised from the registry record.** Each takes the
  record's first remote that declares headers (or its first remote), or its first
  package. Header values, package arguments and runtime hints are not carried
  over, so a server whose real config differs from that shape is measured on the
  shape.
- **Auth posture is inferred from declared config**, not a live probe — a server
  could enforce auth the config doesn't declare (and vice-versa).
- **"Benign" is not claimed.** This measures declared posture, not exploitability;
  see the [benign-slice false-positive rate](../../benchmarks/false_positive/RESULTS.md)
  for how precise the high-severity findings are.

## What changed in v1.1

Version 1.1 rescans the same 2026-07-26 corpus. No config was added or removed.
Every number that moved is below, with the step that moved it. The steps were
applied one at a time to the v1.0 code, in the order listed, and every figure was
recorded after each.

- **(0)** Version 1.0's grade table disagreed with its own `results.json`: it kept
  an earlier run's A and F counts, 637 and 85, where the data said 636 and 86.
- **(i)** Rule changes merged after the code that produced v1.0, through #991. They
  changed no config's findings on this corpus; they moved only the OWASP breakdown
  (#971, below).
- **(ii)** `AAK-MCP-001` and `AAK-MCP-009` no longer report a loopback server
  (localhost, 127.0.0.0/8, ::1, 0.0.0.0), which is the developer's own process.
- **(iii)** `AAK-MCP-001` recognises more API-key header names: any name ending in
  `_API_KEY` or `ApiKey`, and a `-Subscription-Key` suffix.
- **(iv)** `AAK-MCP-003` reports only literals that can be credentials, not
  settings such as `*_TOKEN_NAME` or short demo values.
- **(v)** The harness wrote each config as `config.mcp.json`. Seven scanners read
  MCP configs by name and never open that one, among them the supply-chain scanner
  and the CVE pin table, so up to 128 rules were never measured on the corpus. And
  `AAK-SECRET-007`, which stands down on `.mcp.json` because `AAK-MCP-003` reports
  the same env literal there, counted every env secret a second time. Each config
  is now scanned as `.mcp.json`.
- **(vi)** The registry conversion dropped the version each record states, so its
  161 npm and PyPI configs were unpinned launches by construction. They now launch
  the stated release.
- **(vii)** The OWASP MCP tally leaves out the two advisory rules, as the
  top-misconfiguration table already did.
- **(viii)** `AAK-TRANSPORT-003` reads the `type` key, where Claude Code and VS Code
  declare SSE, as well as `transport`, and reports each server once.

| Figure | v1.0 | v1.1 | What moved it |
|---|--:|--:|---|
| Configs with a remote server and no auth (`AAK-MCP-001`) | 1,201 (52.1%) | <!-- report:noauth-n -->1,166<!-- /report --> (<!-- report:noauth-pct -->50.6<!-- /report -->%) | (ii) -34 · (iii) -1 |
| Configs with a critical finding | 1,213 (52.7%) | <!-- report:critical-n -->1,184<!-- /report --> (<!-- report:critical-pct -->51.4<!-- /report -->%) | (ii) -34 · (iii) -1 · (v) +6 |
| Configs with a high finding | 165 (7.2%) | <!-- report:high-n -->110<!-- /report --> (<!-- report:high-pct -->4.8<!-- /report -->%) | (ii) -37 · (iv) -36 · (v) +18 |
| Configs launching a package with no pinned version (`AAK-SUPPLY-001`) | 0 (0.0%) | <!-- report:supply001-n -->284<!-- /report --> (<!-- report:supply001-pct -->12.3<!-- /report -->%) | (v) +444 · (vi) -160 |
| Configs with an env secret, `AAK-MCP-003` | 70 (3.0%) | <!-- report:mcp003-n -->30<!-- /report --> (<!-- report:mcp003-pct -->1.3<!-- /report -->%) | (iv) -40 |
| Configs with an env secret, `AAK-SECRET-007` | 70 (3.0%) | <!-- report:secret007-n -->0<!-- /report --> (<!-- report:secret007-pct -->0.0<!-- /report -->%) | (v) -70 |
| Configs with an internal-network URL (`AAK-MCP-009`) | 44 (1.9%) | <!-- report:mcp009-n -->3<!-- /report --> (<!-- report:mcp009-pct -->0.1<!-- /report -->%) | (ii) -41 |
| Configs declaring SSE (`AAK-TRANSPORT-003`) | 36 (1.6%) | <!-- report:transport003-n -->47<!-- /report --> (<!-- report:transport003-pct -->2.0<!-- /report -->%) | (viii) +11 |
| Grade A | 637 (27.7%) | <!-- report:grade-a -->789<!-- /report --> (<!-- report:grade-a-pct -->34.3<!-- /report -->%) | (0) -1 · (ii) +21 · (iv) +2 · (v) -28 · (vi) +160 · (viii) -2 |
| Grade B | 1,421 (61.7%) | <!-- report:grade-b -->1,279<!-- /report --> (<!-- report:grade-b-pct -->55.5<!-- /report -->%) | (ii) +5 · (iii) +1 · (iv) +10 · (v) +8 · (vi) -160 · (viii) -6 |
| Grade C | 111 (4.8%) | <!-- report:grade-c -->96<!-- /report --> (<!-- report:grade-c-pct -->4.2<!-- /report -->%) | (ii) -13 · (iv) -10 · (viii) +8 |
| Grade D | 49 (2.1%) | <!-- report:grade-d -->52<!-- /report --> (<!-- report:grade-d-pct -->2.3<!-- /report -->%) | (ii) -8 · (v) +11 |
| Grade F | 85 (3.7%) | <!-- report:grade-f -->87<!-- /report --> (<!-- report:grade-f-pct -->3.8<!-- /report -->%) | (0) +1 · (ii) -5 · (iii) -1 · (iv) -2 · (v) +9 |
| Critical findings | 1,335 | <!-- report:findings-critical -->1,292<!-- /report --> | (ii) -46 · (iii) -3 · (v) +6 |
| High findings | 319 | <!-- report:findings-high -->208<!-- /report --> | (ii) -49 · (iv) -85 · (v) +23 |
| Medium findings | 4,432 | <!-- report:findings-medium -->4,930<!-- /report --> | (v) +645 · (vi) -160 · (viii) +13 |
| Low findings | 1,224 | <!-- report:findings-low -->652<!-- /report --> | (v) -572 |
| Configs with a secret-exposure finding | 70 (3.0%) | <!-- report:cat-secret-n -->4<!-- /report --> (<!-- report:cat-secret-pct -->0.2<!-- /report -->%) | (v) -66 |
| Configs with a transport-security finding | 42 (1.8%) | <!-- report:cat-transport-n -->53<!-- /report --> (<!-- report:cat-transport-pct -->2.3<!-- /report -->%) | (viii) +11 |
| Configs with a supply-chain finding | 0 (0.0%) | <!-- report:cat-supply-chain-n -->287<!-- /report --> (<!-- report:cat-supply-chain-pct -->12.5<!-- /report -->%) | (v) +447 · (vi) -160 |
| Configs with a legal-compliance finding | 0 (0.0%) | <!-- report:cat-legal-n -->8<!-- /report --> (<!-- report:cat-legal-pct -->0.3<!-- /report -->%) | (v) +8 |

The new findings in (v) are `AAK-SUPPLY-001`, eight CVE version pins (the Serena
pin, on 19 configs that launch Serena from its git repository or a local checkout
at no stated version, enters the top ten), and the EU AI Act Art. 50 transparency
rules on 8 configs. `AAK-MCP-007` stands
down wherever `AAK-SUPPLY-001` reports the same launch, and that is the whole
low-severity drop. In (vi) the 160 registry configs that launched an unpinned
package lose that finding, and each moves from B to A.

**Statements v1.0 made that the corrected scan does not support:**

- "19.5% of public MCP servers fetch-and-execute *unpinned* remote packages." The
  19.5% is `AAK-MCP-005`, which counts every `npx`/`uvx` launch, pinned or not.
  Unpinned launches are `AAK-SUPPLY-001`, <!-- report:supply001-pct -->12.3<!-- /report -->%, which v1.0 never measured.
- "Not a single public server serves the discovery document." The figure counts
  configs, which cannot serve anything; the 2026-10-11 probe found that more than
  half of the public endpoints that answered DNS serve it.
- "Pinned-CVE hits are rare because registry configs use unpinned `npx -y`." The
  pins never ran on the corpus in v1.0 (step v), and the registry configs were
  unpinned only because the conversion dropped their versions (step vi).

**Where order matters.** The combined effect does not depend on the order of the
steps; how it splits between two of them can:

- (iv) and (v) remove the same double-counted env literal from two sides:
  `AAK-MCP-003` at high severity in (iv), `AAK-SECRET-007` at medium in (v). In
  this order the OWASP MCP01 tally moves only in (v) (-37); the other way round it
  moves in (iv) (-38) and (v) adds 1. Grades and the count of configs with a high
  finding split differently too.
- (v) and (vi): the versions change only what `AAK-SUPPLY-001` reports, and that
  rule reads the corpus only from (v) on. In this order (v) adds `AAK-SUPPLY-001`
  to 444 configs and (vi) removes it from 160. The other way round, (vi) first
  removes `AAK-MCP-007` (low) from 160 configs and (v) then adds `AAK-SUPPLY-001` to
  284. The grade moves are the same either way.
- (ii) and (v): 2 configs lose their only critical finding in (ii) and gain a
  critical CVE pin in (v), so (ii) moves the critical count by -34 in this order and
  -32 after (v). (iii) and (vii) each shift one or two configs the same way.
- (viii) moves the same figures whether it is applied first or last.

**The OWASP MCP breakdown changed meaning as well as value.** v1.0 tallied AAK's
own `MCPnn` labels, which named different risks from OWASP's list; #971 remapped
every rule to the risk OWASP names (step i). Under OWASP's ids, with the advisory
rules left out (step vii), the most common risk is MCP07, Insufficient
Authentication & Authorization, at <!-- report:owasp-mcp07-pct -->69.3<!-- /report -->% (<!-- report:owasp-mcp07-n -->1,595<!-- /report -->). v1.0's table put its own
MCP07 label at 99.8%. The full v1.1 table is in [PREVALENCE.md](PREVALENCE.md).

## How to cite this report

Cite the report, not the repository, when you are citing a number from it — the
repository moves and the report does not. Version 1.1 refers to the 2026-07-26 scan
of <!-- report:corpus -->2,303<!-- /report --> configs described above.

**Plain text**

> Jain, S. (2026). *The State of MCP Security, 2026* (Version 1.1). AgentAuditKit.
> https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/REPORT.md

**BibTeX**

```bibtex
@techreport{jain2026mcpsecurity,
  author      = {Jain, Sattyam},
  title       = {The State of MCP Security, 2026},
  institution = {AgentAuditKit},
  year        = {2026},
  month       = {10},
  type        = {Technical Report},
  number      = {Version 1.1},
  url         = {https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/REPORT.md},
  note        = {Corpus: 2,303 distinct public MCP server configurations, collected 2026-07-26. Offline, deterministic scan; reproducible with \texttt{make report}.}
}
```

Repository-level metadata is in [`CITATION.cff`](../../CITATION.cff) at the repo
root, which GitHub renders as a "Cite this repository" widget. It points at this same
identity, so the two cannot disagree about the report version.

**Citing a specific number.** Every figure above carries its numerator and
denominator; quote both. For example: "<!-- report:rfc9728-n -->0<!-- /report --> of <!-- report:corpus -->2,303<!-- /report --> public MCP configs referenced
RFC 9728 Protected Resource Metadata discovery (Jain 2026, v1.1)." If you need the
raw data, `results.json` beside this file is the machine-readable output, and
`corpus/registry-manifest.json` records per-server provenance.
