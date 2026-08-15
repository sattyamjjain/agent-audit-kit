# Changelog

All notable changes to AgentAuditKit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `AAK-MCP-MEMSERVICE-CVE-2026-50027-001` (SUPPLY_CHAIN, CRITICAL) — mcp-memory-service < 10.67.1 serves every `/api/documents/*` route with no auth dependency even when `MCP_API_KEY` or OAuth is configured; the sibling `/api/memories` routes do enforce it, making this an inconsistent boundary. Floor `>= 10.67.1`. Closes #589.
- `AAK-MCP-CORTEX-CVE-2026-49986-001` (SUPPLY_CHAIN, HIGH) — Cortex `<= 3.17.0` treats `CLAUDE_PROJECT_DIR` as a trusted source root, validated only by two marker files, then executes `visualize_bootstrap.py` from it. Floor `>= 3.18.0` per GHSA — **not** the 3.17.1 the NVD text names, which was never published. Closes #585.
- `AAK-MCP-CKAN-CVE-2026-73846-001` (SUPPLY_CHAIN, MEDIUM) — `@aborruso/ckan-mcp-server` < 0.4.112: cache-key collision, prefix-only host validation, and verbose error reflection. One pin, three CVEs. Closes #586, #587, #588.
- `aak` is now an installed console script, aliasing `agent-audit-kit`. The docs, changelogs and release notes have used `aak scan` / `aak score` / `aak watch-cve` as shorthand for many releases, but it was never declared in `[project.scripts]`, so every one of those snippets exited 127 when copied. Both names share a single entry point, and `tests/test_console_scripts.py` asserts they stay in step — plus that every `` `aak <cmd>` `` in the docs names a command that actually exists.
- `AAK-AGENT-ZERO-CVE-2026-30624-PIN-001` (SUPPLY_CHAIN, HIGH) — Agent Zero 0.9.8 executes the `command`/`args` of a user-supplied MCP server config without validation (CVE-2026-30624, CVSS 8.6). Git-reference-only pin with the floor at 1.0: `agent-zero` on PyPI is an unrelated voice-agent framework, and the repo moved `frdel/` → `agent0ai/`. Closes #160.
- `AAK-POLICY-TRUNCATION-001` (TRUST_BOUNDARY, HIGH) — a deny policy evaluated against a truncated copy of the value the executor receives, so anything past the cut point bypasses the deny list. CVE-2026-73614 (ClaudeHookBridge, CVSS 8.8) is the disclosed instance — truncation to 500 chars before `denyPatterns` while Claude Code ran the full command — but that package resolves on neither npm, PyPI nor GitHub, so the rule is written against the shape rather than the vendor. Fires only when the untruncated source is still used elsewhere in the file, which is what separates a policy/executor split from ordinary display truncation. Covers JS/TS `slice`/`substring`/`substr` and Python slicing. Zero findings against AAK's own source, the VS Code extension, and the benchmark corpus.
- `AAK-MCP-AUTHFETCH-CVE-2026-49857-001` (SUPPLY_CHAIN, HIGH) — auth-fetch-mcp `<= 3.0.1`: `isPrivateV6()` misses IPv4-mapped IPv6 loopback in hex-normalised form, so `http://[::ffff:127.0.0.1]/` normalises to `[::ffff:7f00:1]`, `net.isIPv4('7f00:1')` is false, and the SSRF guard passes the URL through to loopback. Floor `>= 3.0.2` per GHSA-pvrj-8cg3-j5f8 — **not** the 3.0.1 the NVD prose names as the fix, which is inside the affected range. (#578)
- `AAK-MCP-JSHOOK-CVE-2026-49856-001` (SUPPLY_CHAIN, MEDIUM) — @jshookmcp/jshook 0.3.1 enforces its SSRF authorization policy only on the raw HTTP/TCP/TLS tools; ICMP probe and traceroute call the native sink directly, giving internal reachability mapping with private-network access disabled. Floor `>= 0.3.2`. (#577)
- `CVE-2026-73601` added to `AAK-FLOWISE-001` — the Custom MCP node stdio RCE shares Flowise's 3.1.3 fix floor, which that rule's detector already enforces, so it is a reference addition rather than a duplicate pin. (#575)

### Changed

- Fixed four dangling relative links in `docs/`: one written a directory level too shallow, two pointing at per-rule pages that were never authored (for rules that do exist in the registry), and one to a doc explicitly marked "queued for v0.4.0". `tests/test_docs_links.py` now asserts every relative link under `docs/` resolves — the deterministic half of the link check, without the network flakiness.
- Launch copy and `CLAUDE_PROMPT.md` now point at `https://sattyamjjain.github.io/agent-audit-kit/` instead of `mcp-security-index.com`, which never resolved and had been failing the docs link check on every PR (6 files).
- Adjudicated out of scope after a registry check, with reasons recorded in `CHANGELOG.cves.md`: CVE-2026-73614 (ClaudeHookBridge — absent from npm, PyPI and GitHub, so nothing to key a detector on), CVE-2026-19751 / CVE-2026-19752 (mcp-dominican-layer — rolling release, NVD states version details cannot be specified), CVE-2026-19753 (mcp-rdf-explorer — unresolvable, no published fix), CVE-2026-73037 (Next AI Draw.io — reflected XSS in a web app, no MCP surface and no XSS detector here). (#576, #579, #580, #581, #582)

- `AAK-MCP-UFO-CVE-2026-73296-001` (MCP_CONFIG, CRITICAL) — Microsoft UFO < 3.0.8 serves its mobile MCP data-collection (8020) and action (8021) Streamable-HTTP endpoints without inbound auth, handing an unauthenticated caller the ADB device-control tools. New `ufo_mobile_mcp` scanner over vendored source, MCP config, and git dependency; a detection rule rather than a pin, because UFO ships as a git checkout and `ufo` on npm is an unrelated package. (#573)
- `AAK-MCP-ATLASSIAN-CVE-2026-73498-001` (SUPPLY_CHAIN, HIGH) — mcp-atlassian < 0.22.0 opens `confluence_upload_attachment`'s caller-supplied `file_path` without `validate_safe_path`, so any readable file can be exfiltrated to Confluence. Pin floor `>= 0.22.0` plus a vendored-source detector. (#574)
- `agent_audit_kit/sessions/adapters.py` and `aak scan --sessions PATH` — normalises OpenAI Agents SDK run traces, LangGraph checkpoint/thread state, and raw JSONL into the ordered call list `AAK-AGENT-COMPOSE-002` already expects, so the rule fires on transcripts frameworks actually write. No rule change. Documented in `docs/session-transcripts.md`.
- `scripts/cve_latency.py` and `docs/cve-latency.md` — CVE-to-rule latency as a published, checkable number (median and p90 days from NVD publication to the release that shipped the rule), regenerated on every tag by the `cve-latency` release job. Published dates cached in `docs/data/cve-published.json`; `--refresh` is the one network step.

### Fixed

- `strict_loading` was ignored once the scanner registry was cached: a lenient call (`scanner_manifest()`, an earlier `run_scan`) baked its mode into a single-slot cache, so a later `run_scan(strict_loading=True)` silently skipped an unimportable scanner instead of raising `ScannerLoadError`. The cache is now keyed by mode. Supersedes #570, which had the right fix but left `tests/test_engine.py` patching `_REGISTRY` as a list — where `_REGISTRY[False] = ...` overwrites index 0 rather than failing, quietly disarming two crash-handling tests. Warm-registry regression tests added; the suite previously only covered the cold path.

### Changed

- Unguarded "N rules" totals in launch copy rewritten to the `N detection rules` phrasing `scripts/check_counts.py` already guards, fixing counts that had drifted to 291 where no pattern was looking.

## [0.3.74] - 2026-08-12

### Added

- **`AAK-AGENT-COMPOSE-002`, a session-scoped instruction-splice check.**
  `AAK-AGENT-COMPOSE-001` unions capability across a set of skills; it cannot see one
  intent fragmented across several individually-compliant tool calls. This rule reads an
  ordered transcript of tool calls (`*.session.json` or JSON under `.aak/sessions/`) and
  flags when the concatenation of arguments across consecutive same-tool calls
  reconstructs a sensitive file path (`.ssh/id_rsa`, `.env`, `.aws/credentials`) or a URL
  to a non-allowlisted host that no single call would have been allowed to request. This
  is the GhostSplice / cross-channel trust-fragmentation attack (ASSET Research Group,
  https://asset-group.github.io/disclosures/ghostsplice/); the rule was written from that
  public disclosure, not from a reproduction we ran. It reuses `AAK-AGENT-COMPOSE-001`'s
  config (`.aak/composition-boundaries.yaml`). It defaults to a warning (MEDIUM), not a
  failure, and says so, because it WILL raise false positives on legitimate chunked work:
  a large file written in path-sized pieces reassembles the same way. Scope is narrow on
  purpose — file-path and URL reassembly only, not general intent detection.

### Fixed

- **`CLAUDE_PROMPT.md` said "289 existing rules" two rules after the v0.3.72 sweep
  that was supposed to end count drift.** The whole-repo guard (`scripts/check_counts.py`)
  scanned the file, but none of its patterns matched the phrasing "N existing rules", so
  the drift slid through. Added an `existing rules` pattern, and switched the
  `DEEP_ANALYSIS.md` / `ROADMAP_2026.md` exemption from a hard-coded name list to a
  dated historical-snapshot banner: a snapshot file is exempt only while it carries its
  banner, and a test asserts both files still do — so a future file that drops its banner
  (or forgets to add one) gets its counts checked instead of hiding. The count is fixed by
  reading `RULE_COUNT`, not by typing it.

### Changed

- **`aak watch-cve` now ships one live feed instead of only stubs.** The command counts
  inside "26 CLI commands" but exited non-zero on every invocation — a claim ahead of
  evidence. It now wires the NVD 2.0 API (`nvd`) as a real feed: the network call is
  opt-in behind `--online`, so CI and offline runs never touch the network (the feed
  reads an on-disk cache at `~/.agent-audit-kit/nvd-cache.json`), and one request per
  poll stays under NVD's public rate limit (5 requests / 30 s; more with `NVD_API_KEY`).
  The other four feeds (ox, cert-cc, thaicert, ironplate) stay stubbed; the stub message
  now names which feeds are live, and the command exits 0 when at least one requested
  feed polled cleanly. What it still does not do: no live ox / cert-cc / thaicert /
  ironplate fetchers, and no notification sinks (payloads print to stdout/stderr).

### Security

- **Two newly disclosed MCP-adjacent CVEs, triaged in scope and pinned** — draining the
  open `cve-response` backlog that gated this release. Rule count 292 → 294; see
  [`CHANGELOG.cves.md`](CHANGELOG.cves.md).
  - **`AAK-MCP-N8N-CVE-2026-72768-001`** (SUPPLY_CHAIN, MEDIUM): n8n before 2.32.1 has an
    SSRF-protection bypass in the MCP Client node — an authenticated workflow author can
    reach internal or blocked hosts without routing through n8n's SSRF protection and read
    the responses back ([CVE-2026-72768](https://nvd.nist.gov/vuln/detail/CVE-2026-72768)).
    Pinned at floor `n8n >= 2.32.1`; a third distinct n8n arm, separate from CVE-2026-59207
    and CVE-2026-65594.
  - **`AAK-MCP-CCTEMPLATES-CVE-2026-73222-001`** (SUPPLY_CHAIN, HIGH): claude-code-templates
    before 1.29.4 launches the `--studio` server on `0.0.0.0:3444` with CORS open and no
    authentication, passing request-body fields (`prompt`, `agentName`) to
    `child_process.spawn()` with shell execution enabled → unauthenticated OS command
    execution with the developer's privileges
    ([CVE-2026-73222](https://nvd.nist.gov/vuln/detail/CVE-2026-73222), CVSS 8.8). Pinned at
    floor `claude-code-templates >= 1.29.4` (no 1.29.3 was published).
  - Both packages resolve on npm with the fixed version present, so both are in-scope
    version pins in `mcp_cve_pins_2026_07`, verified against the registry before shipping.

## [0.3.73] - 2026-08-11

### Added

- **`AAK-AGENT-COMPOSE-001`, a composition-aware capability-union check.** The
  `AAK-AGENT-TRUST-*` and `AAK-SKILL-*` rules inspect one artifact at a time, so they
  cannot see intent split across several individually-benign skills. That is the
  ColluSkill attack (arXiv:2608.09732), reported at a 96.0% average success rate across
  six per-skill scanners. This rule operates on the SET of skills that load into one
  agent context: it computes the union of declared capability (filesystem read/write,
  network egress by destination, shell execution, credential access, memory write) and
  flags a union that crosses a configured risk boundary no single skill requested. The
  shipped default: a skill that can read files or credentials, composed with a skill
  that can egress to a non-allowlisted destination, is an exfiltration path, flagged
  HIGH, even when each skill is individually clean. The finding names which skill
  contributed which capability and emits each contributor as a SARIF related location.
  The boundary and egress allowlist are configurable via `.aak/composition-boundaries.yaml`;
  the default and its reasoning are in `docs/rules/skill-composition.md`. What it does
  not do: it reasons about DECLARED capability, not data flow. A skill that under-declares
  its tools, or reaches a capability through an MCP server it does not name, is out of
  scope, and it flags a possible exfiltration path, not a proven one.
- **`AAK-MCP-GRAFANA-CVE-2026-19516-001`: pin `mcp-grafana >= 1.1.0`.** In mcp-grafana
  1.0.0 and earlier, a caller-controlled `X-Grafana-URL` header set the destination of the
  server's outbound requests, giving SSRF to internal, loopback, and metadata endpoints
  (CVE-2026-19516, CVSS 9.1). This is the incomplete-fix follow-up to CVE-2026-15583, so
  the correct control is destination restriction, not token handling: 1.1.0 restricts the
  destination to the configured Grafana instance. mcp-grafana is a Go server but ships a
  resolvable PyPI wrapper (`uvx mcp-grafana`), so it is pinnable after all, superseding
  the earlier "unpinnable Go module" ledger note.

### Changed

- **The four `AAK-AGENT-TRUST-*` rules now state their own limits.** They are a
  single-artifact pre-screen, not a boundary control, and single-artifact scanning does
  not detect intent split across multiple individually-benign skills. Each rule carries a
  `limitations` note (new `RuleDefinition.limitations` field) citing ColluSkill
  (arXiv:2608.09732, 96.0% average attack success across six scanners) and SkillsMetric
  (arXiv:2608.08468, 0% detection for host-destruction via common shell commands, 42% for
  natural-language prompt injection). The docs page `docs/rules/skill-composition.md` says
  the same, without softening it. The composition blind spot these four cannot see is
  covered by the new `AAK-AGENT-COMPOSE-001`.

## [0.3.72] - 2026-08-10

### Fixed

- Rule and scanner counts were stale in several launch, research, and analysis files that
  nothing guarded. Bumped the current-state claims (owasp-outreach,
  awesome-opensource-security, the Black Hat Arsenal skeleton, CLAUDE_PROMPT) to the live
  counts, and left the dated measurements (blog-50, DEEP_ANALYSIS, ROADMAP, the v0.3.41 and
  v0.3.56 reports) as the versions they describe, adding an in-file dated note where one was
  missing. The count guard now scans every tracked markdown except the changelogs and those
  dated artifacts (`scripts/check_counts.py`); the test and `make count-check` share it, and
  the release job fails on a mismatch with the offending file and line.
- The scanner-count assertion in `tests/test_scanner_manifest.py` no longer hardcodes a
  number in its docstring, so it cannot go stale when a scanner is added.

### Added

- `docs/benchmarks/third-party-grading.md`. Went to grade AAK against the OASB benchmark.
  Recorded honestly that its submission API returns 404 and that it withdrew its comparative
  metrics on 2026-08-09 because the benign class was self-labelled by the scanner under test,
  so there is no measured grade to publish. Published the two numbers we do stand behind
  instead: the determinism digest (20/20 runs, one SHA-256, 0% variance) and the benign-slice
  HIGH/CRITICAL false-positive rate with its Wilson interval. Linked from the README badges.

## [0.3.71] - 2026-08-09

### Added

- **A repo-resident agent config/skill auto-trust scanner (`AAK-AGENT-TRUST-001..004`).**
  Coding agents auto-load skill and config files on open and trust them on first use, and
  a non-interactive `-p` / headless run removes the workspace-trust prompt that is the
  guardrail. The scanner flags a coding-agent CLI run headless in CI (high), the same on
  an attacker-controllable ref such as `pull_request_target` or a PR-head checkout, where a
  fork PR's config executes with the base repo's secrets (critical), checked-in agent
  settings that bake in `bypassPermissions` / `autoApprove` / `yolo` / `trust` (high), and a
  Gemini `GEMINI.md` context file carrying an embedded shell payload (medium). It extends
  the per-file families (`AAK-IDE-TASK-*`, `AAK-SKILL-*`, `AAK-AGENT-*`) rather than
  re-detecting their content. Motivated by the measured result in arXiv:2608.05223 (Gemini
  CLI ran the shell commands hidden in benign-looking skill files in 95.5-96.1% of runs,
  with explicit safety recognition in 1.99% of 5,629 runs); it does not claim validation
  against that paper's unpublished 2,826-skill benchmark. Ships with fixtures.

### Changed

- Adjudicated the three cve-response issues filed on 2026-08-09 (all MEDIUM CVSS 5.3) on
  their merits against the npm registry. One new pin: `@adenot/mcp-google-search` <= 0.3.1
  for the `read_webpage` SSRF (CVE-2026-19337), the same shape as the astrbot
  MCP-test-endpoint pin. No patched release exists yet, so the pin is presence-only and
  fires on any installed version, with remediation to remove or replace the server until a
  fix ships. Two are out of scope as unpinnable: codex_mcp (CVE-2026-19329) and MCP4EDA
  (CVE-2026-19332) are GitHub-only projects with no versioned registry artifact, so a
  version pin has nothing to resolve. RULE_COUNT moves 284 to 285. Closes #556, #557, and #558.
- Archived pre-0.3.60 changelog history. CHANGELOG.md (205 KB) and CHANGELOG.cves.md (86 KB)
  had grown unreviewable in a PR diff at a two-day tag cadence, so 0.3.58 and earlier
  moved to `docs/changelog/archive/` with a pointer in each live file; the last ~10
  releases stay live. The archive is exempted from the prose-count fence and the docs
  link-check.

### Removed

- Dropped the orphan `findings.sarif` from the repo root. It was referenced by nothing and
  held eight findings from an old scan, drifting from `rules.json` on every rule change.
  Root-level SARIF is now gitignored; scan output is generated on demand (`aak scan
  --format sarif`) and uploaded to Code Scanning by the Action. The example SARIF under
  `examples/case-studies/` is untouched.

## [0.3.70] - 2026-08-08

### Added

- **A machine-readable scanner manifest (`scanners.json`, generated from the engine
  registry) so the scanner count is countable the way the rule count is, not asserted.**
  `agent-audit-kit scanners --json` prints it, the README marker renders from it, and a
  test asserts they agree. Before this the count came from a directory listing that
  included two back-compat shims (`typescript_scan` and `rust_scan`, which only re-export
  the registered `*_pattern_scan` modules), so `87 scanners` was really 85. The number is
  now 85, and reproducible in one command.

### Fixed

- **The GitHub "About" description said 271 rules for a third release in a row**, while
  the code has said 284 since 2026-08-08. The render target (`make repo-description`) and
  the release-time drift check both already existed; the check was silently useless
  because the job crashed with `ModuleNotFoundError` before it ever reached the
  byte-compare. The job now runs (`PYTHONPATH=.`), so a stale description actually fails
  the release job and the failure prints the exact string to paste, in the annotation and
  the run summary. The description still has to be pasted into repo Settings by hand — a
  CI token cannot set it — but a stale one is no longer invisible.
- **docs/CNAME pointed at `docs.agentauditkit.io`, which has no DNS record**, while
  `mkdocs.yml` pointed at the Pages URL that actually serves. Two documented docs URLs,
  one of them dead. Deleted the CNAME so the working Pages URL is the one docs URL, and
  added a link-check over `docs/` and `README.md` (weekly + on doc changes) so a dead
  docs link fails a build instead of sitting for months. The `security@agentauditkit.io`
  contact address is left in place and excluded from the link-check.

## [0.3.69] - 2026-08-08

### Added

- **VS Code IDE task/launch folder-open RCE coverage (`AAK-IDE-TASK-001..004`).** The
  scanner read `.vscode/mcp.json` but not the task surface right next to it. A
  `.vscode/tasks.json` task with `runOptions.runOn: folderOpen` runs the moment a
  repository is opened, before any interaction and before the workspace-trust prompt.
  That is the vector the keyv npm worm used to spread, and before today AAK did not read
  this file at all. The new scanner flags folderOpen auto-run (high, and critical when
  the command is a shell, an interpreter, or a network fetch), `command`/`args` that
  reach a shell (pipe-to-shell, a repo-local interpreter path, or an interpolated
  variable), and `launch.json` `preLaunchTask` chains into a flagged task.
  `.vscode/tasks.json` and `.vscode/launch.json` are now also reported by `discover`.
  JSONC comments and trailing commas are stripped before parsing, and a file that still
  will not parse is reported (low) rather than skipped silently.
- **`make repo-description`** prints the GitHub "About" description rendered from
  `RULE_COUNT`, and the release workflow prints the same string at the end of a run with
  a paste instruction, so the manual paste (the description is not writable from a CI
  token) is impossible to forget instead of only detectable afterward by the liveness
  check.

### Changed

- Adjudicated the eleven open cve-response issues into the public CVE-to-rule ledger.
  Two new pins: `awslabs.documentdb-mcp-server` >= 1.0.12 (CVE-2026-18954, the fifth
  `awslabs.*-mcp-server` pin) and `frontmcp` >= 1.5.7 (CVE-2026-67531, a Zod-proxy
  sandbox escape to RCE). Six fold into existing pins: five Langflow CVEs
  (CVE-2026-17623, 17626, 8446, 9077, 7646) into the `langflow` pin, whose 1.11.0 floor
  already exceeds every affected version, and CVE-2026-48168 into the `praisonai` pin,
  whose 4.6.78 floor already exceeds its 4.6.40 fix. Three are out of scope: an
  ssh-mcp-server CVE with no pinnable version (rolling release, disputed, local-trust
  model), and two MissionSquad mcp-api CVEs whose project is not distributed on npm/PyPI
  under a resolvable name. Three more cve-response issues filed on 2026-08-07/08 were
  drained in the same cut: two more pins (`meta-ads-mcp` >= 1.0.109 for the
  unauthenticated tool-invocation + access-token leak CVE-2026-48039, and
  `langgraph-checkpoint-postgres`/`-sqlite` >= 3.1.1 for the cross-tenant namespace leak
  CVE-2026-71433, the Postgres/SQLite sibling of the mongo one), plus one out of scope
  (HKUDS nanobot, whose GitHub project is not the unrelated PyPI `nanobot`). With the two
  IDE-scanner rules that carry framework mappings folded in, RULE_COUNT moves 276 to 284
  and the scanner count moves 86 to 87. Closes #537 through #550.

## [0.3.68] - 2026-08-05

### Fixed

- **The github.com repo description still says "271 rules" while the code says 275.**
  The previous change made the description renderable from `RULE_COUNT` and added a
  test that fails if the rendered string carries a different number, but it could not
  change the live description (that needs repo-admin rights a CI token does not have),
  so the highest-traffic surface stayed stale. Added a `description-liveness` job to
  the release workflow that fetches the live description from api.github.com and
  byte-compares it to the rendered template, failing loudly on a mismatch. It is
  non-gating (fixing it unblocks nothing) and release-only so it does not flake on a
  fork that cannot read the description.
- **A failed cve-response gate did not say which issue blocked the tag.** The release
  gate now prints the issue number, the CVE id parsed from the title, and the full
  title for every open cve-response issue, so a blocked release is diagnosable from
  the failed run instead of a trip to the issue list.

### Changed

- Adjudicated CVE-2026-18655 and CVE-2026-66065 into the public CVE-to-rule ledger.
  CVE-2026-18655 (`awslabs.amazon-mq-mcp-server` < 2.0.24, a broker-hostname SSRF that
  exfiltrates broker credentials and OAuth tokens) is pinned as the fourth
  `awslabs.*-mcp-server` family pin, so RULE_COUNT moves 274 to 275 and README updates
  with it. CVE-2026-66065 (Ouroboros AI-agent runtime, distributed via GitHub releases)
  is out of scope: not a PyPI/npm artifact the pin detector reads. Closes #530 and #531.
- Three cve-response issues had no written disposition. Each one now has one in the
  public CVE-to-rule ledger. CVE-2026-48121 (`@langchain/langgraph-checkpoint-mongodb`
  at or below 1.3.0, a NoSQL injection that leaks checkpoints across tenants) is pinned
  as a new rule, so RULE_COUNT moves 275 to 276. CVE-2026-69263 (an `npm_config_yes`
  bypass of the npx denylist) and CVE-2026-69257 (an IPv4-mapped IPv6 SSRF) fold into
  the existing `AAK-FLOWISE-001` rule, whose floor was already 3.1.3, so they add no new
  rule. Closes #533, #534, and #535.

## [0.3.67] - 2026-08-03

### Fixed

- **The GitHub repo description said 271 rules while the code said 274.** The repo
  description is the highest-traffic surface this project has, and it was the one
  place the rule count was never guarded. It is now rendered from `RULE_COUNT`
  through `.github/repo-metadata.yml` and `scripts/render_repo_metadata.py`, with
  `tests/test_repo_metadata_matches_code.py` failing the build if the rendered string
  ever carries a different number. GitHub's description is not writable from a CI
  token, so the maintainer step is a paste into repo Settings, now written down in
  CONTRIBUTING.md ("Release checklist") rather than remembered.
- **The State-of-MCP corpus size was a hand-reconciled string in five places.**
  `2,303` is now `CORPUS_N` in `agent_audit_kit/__init__.py`, measured from
  `results.json`, with `tests/test_corpus_n_single_source.py` tying every published
  occurrence back to it (dated/frozen artifacts excluded), so the next corpus growth
  cannot leave a stale number behind.

### Changed

- Adjudicated CVE-2026-68578 and CVE-2026-67357 into the public CVE-to-rule ledger
  (both ArcadeDB < 26.7.3, dispositioned out of scope: a Java/Docker database the pin
  detector does not read; server-side MCP-server flaws). Closes #528 and #527.

## [0.3.66] - 2026-08-02

### Fixed — corpus refresh `--target` reconciled so the documented command reproduces the published N

- **The State-of-MCP report's one network step quoted three different targets.**
  `PREVALENCE.md` and `REPORT.md` documented `fetch_registry.py --target 5000`, but the
  `Makefile` `corpus` target and the argparse default both said `--target 700`. Since
  `fetch()` stops at `len(records) >= target or not cursor`, anyone running the
  documented `make corpus` collected ~700 of the registry's 1,641 distinct latest
  servers and reproduced a different headline N — in a report whose entire pitch is
  reproducibility. Reconciled all four surfaces to the canonical **`--target 5000`**
  (large enough to walk the whole registry to cursor-exhaustion; the published run
  collected **1,641 distinct latest servers on 2026-07-26**). Added
  `tests/test_corpus_target_consistency.py` — asserts the Makefile, the argparse
  default, and both docs agree, and that the target exceeds the committed manifest's
  `distinct_latest_servers` so it can't stop early — and a dated provenance sentence in
  both docs so a reader who reruns and gets a larger N knows it's registry growth, not
  a broken command.

### Changed — cve-response queue adjudicated (#523, #524, #525)

- #523 (CVE-2026-15988, AI-Engine-for-WordPress CSRF) dispositioned **out of scope** —
  a WordPress/PHP plugin the pin detector doesn't read. #524 (CVE-2026-67333,
  `redirect_uri` scheme not validated) and #525 (CVE-2026-67336, weak crypto defaults)
  **folded into the existing `better-auth` pin**, whose floor is raised 1.6.11 → 1.6.13.
  No new rule (count stays 274); full rows in `CHANGELOG.cves.md`.

## [0.3.65] - 2026-08-01

### Fixed — EU AI Act Article 15 application date corrected for the AI Omnibus

- **The repo asserted in seven live places that Article 15 is "binding on
  2026-08-02"** — the original Regulation (EU) 2024/1689 Article 113 staging. The
  **AI Omnibus Regulation** (OJ L_202601744, in force July 2026) moved those dates:
  **Annex III high-risk use cases to 2027-12-02** and **Annex I product-embedded
  high-risk systems to 2028-08-02**. Per the European Commission's AI Act page
  (updated 2026-07-27): *"the rules for high-risk AI systems embedded into
  regulated products (Annex I) have an extended transition period until 2 August
  2028 and the rules for high-risk use cases in certain sensitive areas (Annex III)
  have been extended to 2 December 2027 as a result of the political agreement on
  the proposal to simplify the AI Act – 'AI Omnibus'."*
- Corrected the `AAK-EU-AI-ACT-ART15-LOCALE-001` finding evidence, its rule
  description and module docstring, the `compliance.py` Article-15 evidence
  subsection, and the README Legal Compliance row; regenerated `rules.json` via
  `scripts/sync_rule_count.py` (the date correction itself adds no rule). Severity
  stays INFO and the rule carries no OWASP-Agentic tag, so the Article-15 control
  status is unchanged.
- The previously shipped 2 Aug 2026 date was **superseded by a regulation change,
  not invented** — the historical 0.3.x CHANGELOG entry that recorded it is left
  intact (rewriting shipped history would itself be a credibility defect). Sources:
  the Commission AI Act page
  <https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai> and
  the AI Omnibus Regulation itself
  <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ:L_202601744>.

### Changed — determinism evidence artifact re-cut at v0.3.65 and fenced against staling

- **`benchmarks/determinism/RESULTS.md` still advertised "Generated … on AAK
  v0.3.46 (231 rules)"** — 18 patch releases and 42 rules behind HEAD when caught —
  with a digest that no longer reproduced on the shipped version, so a reader who
  did the one thing the artifact invites (run it on the installed build) would
  wrongly conclude reproducibility was broken. Re-cut it at v0.3.65 (274 rules) via
  `python benchmarks/determinism/run.py --write`. The finding-set SHA-256 changed
  (`199278f2…` → `189055d0…`) and findings-per-run went 9 → 10 **because the rule
  set grew, not because determinism regressed** — every run in the batch still
  produces one shared digest (0% variance); that invariant is unchanged.
- **Added `test_published_results_md_matches_live_run`** — the freshness fence that
  did not exist. It asserts the RESULTS.md header stamps
  `v{__version__} ({RULE_COUNT} rules)` and that the published SHA-256 equals a live
  `run_benchmark` digest, failing with the exact regenerate command. The artifact
  drifted for 18 releases precisely because no test read it; it now cannot re-stale
  without failing CI. This matters as third-party AI/cyber evaluation capacity comes
  online (EU Action Plan on Cybersecurity and AI, 2026-07-07) and CRA reporting
  obligations phase in (Regulation (EU) 2024/2847 — manufacturer reporting from
  2026-09-11, full obligations 2027-12-11): published evidence digests that
  re-verify against the shipped version are the whole differentiator.

### Security — pinned gemini-bridge tool-argument path traversal (CVE-2026-54785)

- **New pin `AAK-MCP-GEMINIBRIDGE-CVE-2026-54785-001`** — `gemini-bridge` (PyPI)
  1.0.0–1.3.0 reads any file path passed to `consult_gemini_with_files` (inline
  mode) without confining it to the working directory, then forwards the contents
  to the Gemini CLI → path-traversal file exfiltration (CVE-2026-54785, MEDIUM 6.2).
  Fix floor `gemini-bridge` 1.3.1 (`introduced` 1.0.0; the npm `gemini-bridge` 0.1.x
  is an unrelated package below the affected range). The NVD watcher filed this
  (`cve-response` #519) while this release was being cut; it was adjudicated and
  pinned here rather than deferred, so the release gate stays honest. Rule count
  **273 → 274**. Full row in `CHANGELOG.cves.md`.

## [0.3.64] - 2026-07-31

### Changed — roadmap correctness: two stale "dead code" notes closed against reality

- **The three RUGPULL rules were never dead.** `ROADMAP_2026.md` §2.1 claimed
  `AAK-RUGPULL-001/002/003` are "defined but never fired by any scanner." In fact
  they fire two ways: `scanners/pin_drift.py` (registered in `engine.py`) emits them
  during a standard scan when a pinned tool's recorded digest changes, and
  `pinning.verify_pins` emits them during `aak verify` — both covered by passing
  tests (`test_pin_drift.py`, `test_pinning.py`, `test_pinning_mod.py`). Removed the
  stale roadmap item; no rule change.
- **TypeScript/Rust "taint analyzers" are honestly named already.** The modules were
  renamed to `typescript_pattern_scan.py` / `rust_pattern_scan.py` back in v0.3.0
  (with back-compat shims), and `engine.py` registers the pattern-scan names. Fixed
  the last stale prose that still called them "taint analysis" (`CLAUDE.md`) and added
  a `docs/rules.md` note stating plainly that real source→sink flow analysis is
  Python-only while TS/JS and Rust are regex dangerous-sink pattern scanners. The
  tree-sitter AST rewrite for TS/Rust remains open as issue #22. Rule IDs and the
  `TAINT_ANALYSIS` category name are unchanged (public contract).

### Changed — adjudicated 6 open cve-response issues (clears the release gate)

- One new pin: `AAK-MCP-LANGFLOW-CVE-2026-12940-001` — IBM Langflow OSS `langflow`
  1.0.0–1.10.1 (CVE-2026-12940, **CRITICAL 9.8**): the MCP stdio launcher's
  `DANGEROUS_ENV_VARS` blocklist omits `SHELLOPTS`/`BASHOPTS`/`PS4` → unauthenticated
  env-var-injection RCE. Fix floor `langflow` 1.11.0 (introduced 1.0.0), a pinnable
  PyPI artifact. Rule count **272 → 273**, sync-driven across every surface.
- Five dispositioned out of scope — all one upstream, Google `mcp-toolbox`
  (`googleapis/genai-toolbox`): CVE-2026-14537 / 14538 / 14539 / 14540 / 14541. It is
  a Go binary the pin scanner cannot read (no `go.mod` in its candidate set) plus
  server-side runtime flaws invisible to a static client scan — same basis as the
  earlier CVE-2026-15829. Each row names the reachable-posture rule (`AAK-MCP-001` /
  `AAK-MCP-SSRF-001` / `AAK-OAUTH-007`). Full verdicts in `CHANGELOG.cves.md`.

## [0.3.63] - 2026-07-30

### Fixed — one canonical State-of-MCP corpus N (2,303) across every publication surface

- The State-of-MCP-2026 corpus grew to **2,303 distinct configs** (a GitHub crawl
  plus the official MCP Registry's latest-version servers; `results.json` is the
  drift-guarded source of truth), but four published surfaces still quoted the
  earlier crawl-only run — a 3.5× discrepancy on the headline. Reconciled all four
  to `results.json`:
  - `research/state-of-mcp-2026/PREVALENCE.md`: 664 → 2,303; critical rate
    26.1% → **52.8% (1,217)**; grade table, OWASP MCP table (99.4%/660 → 99.8%/2,299),
    top-10 findings, and methodology re-derived from the aggregate.
  - `docs/DISTRIBUTION-CHECKLIST.md`: canonical block + all launch copy re-based to
    2,303; report link repointed from `PREVALENCE.md` to the CI-guarded `REPORT.md`;
    the internal 43.7-vs-43.4 `npx`/`uvx` disagreement removed.
  - `docs/STATE-OF-MCP-SECURITY-2026.md`: 1,374 → 2,303; 35.1% (482/1,374) →
    **52.3% (1,205/2,303)** no-auth remote (the 0%-RFC-9728 claim retained).
  - `README.md`: the auth-profile bullet re-based from the pre-dedup 748-file count
    to 2,303 (0% RFC 9728; 52.3% no-auth remote; 100% (421/421) inline-auth static
    credential), with the dated 2026-07-18 748-config readiness scan kept as a
    separate, explicitly-dated point-in-time link.
- **The headline finding reversed, not just drifted.** On the 664-corpus the top
  misconfiguration was `AAK-MCP-005` (`npx`/`uvx` fetch-and-execute, MEDIUM, 43.7%);
  on the 2,303-corpus it is `AAK-MCP-001` (remote server with no authentication,
  **CRITICAL, 52.3%**), and `npx`/`uvx` fell to 19.5%. Every "the top one is boring
  and fixable" framing was renamed to the correct lead at the correct severity.
- Collapsed the two divergent hand-maintained launch-copy blocks into one generated
  home (`docs/DISTRIBUTION-CHECKLIST.md`); `PREVALENCE.md` now points to it instead
  of carrying a second, drifting copy.
- Extended the report drift guard from `REPORT.md`-only to every publication
  surface:
  `tests/test_state_of_mcp_report.py::test_every_publication_surface_matches_results`
  asserts the current corpus N appears and denylists superseded corpus tokens /
  percentages (664/748/1,374 · 26.1/35.1/43.7/43.4/24.2/99.4) outside a narrow,
  commented allowlist of dated lines, so the next corpus refresh fails the build
  until the prose follows.

### Changed — adjudicated 6 open cve-response issues (clears the release gate)

- One new pin: `AAK-MCP-FLYTO-CVE-2026-67425-001` — `flyto-core` < 2.26.6
  (CVE-2026-67425, HIGH 8.6; provider-key exfiltration to a caller-controlled
  `base_url`), a pinnable PyPI artifact the pin scanner resolves from
  `pyproject.toml`/`requirements.txt`/`uv.lock` (same basis as the
  `awslabs.aws-api-mcp-server` PyPI pin). Rule count **271 → 272**, sync-driven
  across every surface.
- Five dispositioned out of scope — all one upstream, the official MCP Ruby SDK
  (`mcp` gem < 0.23.0: CVE-2026-67432 / 67431 / 67430, CVE-2026-63118 / 63119): a
  RubyGems ecosystem the pin scanner does not read (no `Gemfile` in its candidate
  set) plus server-side transport internals invisible to a static client scan. Each
  row states the reachable-posture rule (`AAK-MCP-001` / `AAK-DNS-REBIND-001`) and
  the ≥ 0.23.0 upgrade floor. Full verdicts in `CHANGELOG.cves.md`.

## [0.3.62] - 2026-07-28

### Fixed — README Action pin is now guaranteed to resolve (pin ↔ tag CI guard)

- `0.3.61` was bumped in `pyproject.toml` but never tagged, so the README's
  `uses: sattyamjjain/agent-audit-kit@v0.3.61` snippet pointed at a tag that did
  not exist — every user who copied it got a workflow that failed to resolve the
  action. Cut the real `v0.3.61` tag and added a CI guard,
  `test_version_consistency.test_readme_action_pin_matches_newest_git_tag`, that
  fails the build when the README's `@vX.Y.Z` Action pin does not match the
  newest git tag; `ci.yml` now fetches tags so the guard enforces in CI. Together
  with the existing pin-vs-pyproject check, README pin == version == released tag.

### Changed — retired the residual public "48h CVE-to-rule SLA" claims

- The 48h CVE-to-rule SLA was retired in PR #432 (2026-07-14), but a few public
  files still asserted it as a standing commitment. Rewrote the four live
  `CLAUDE_PROMPT.md` lines to the best-effort language from `SECURITY.md` (no
  guaranteed response clock; the NVD watcher + release gate stay, framed as
  best-effort triage). The dated historical records — `releases/v0.3.5.md`,
  `releases/v0.3.8.md`, `launch/MARKET-RESEARCH-2026-04-12.md` — were **not**
  rewritten; each gets a one-line dated note that the SLA was retired, pointing at
  `SECURITY.md`. `CHANGELOG.md`'s historical mentions are left as dated facts.

### Changed — `aak watch-cve` fails loud instead of silently succeeding

- `aak watch-cve`'s feed fetchers (`agent_audit_kit/feeds`) had been registered
  stubs returning `[]` since v0.3.10, with docstrings promising real fetchers
  "in v0.3.11" — 50 releases ago. The command ran, found nothing, and exited 0,
  looking like a clean poll. It now **fails loud**: `_stub_fetcher` raises
  `NotImplementedError` (matching the `integrations/notify.py` PagerDuty/Linear
  stubs), `run_watch` prints `feed <id>: NOT IMPLEMENTED` and exits non-zero when
  every configured feed is a stub, and the command is marked `[experimental]` in
  `--help` and the README. All "lands/ship in v0.3.11" promises removed. `aak
  watch` (the pin-drift monitor, a different module) is unaffected.

### Added — placeholder-CVE CI guard

- `tests/test_no_placeholder_cves.py` sweeps `agent_audit_kit/**`, `rules.json`,
  and `docs/**` (excluding `tests/`, whose fixtures/mocks legitimately use
  placeholder CVEs) for CVE-shaped identifiers whose sequence is a known
  placeholder (`99999`, `999999`, `00000`, `0000`, `12345`, `11111`) and fails
  with the offending `file:line`. Prevents a fabricated CVE from entering the rule
  registry as a false coverage claim.

## [0.3.61] - 2026-07-28

### Removed — private strategy note taken out of the public tree

- Removed `KILL-CRITERIA.md` from version control (`git rm --cached` + `.gitignore`);
  the local working copy is kept. The file was a private strategy note whose own
  header read "Do not commit to the public repo" — it named a competitor and an
  acqui-hire/services monetization path candidly, which does not belong in a public
  repository. This only stops future tracking; the file remains in past commits and
  was **not** scrubbed from git history.

### Fixed — one canonical framework (12) & agent-platform (10) count, fenced in CI

- **README was the sole outlier** on two counts that live in code. Reconciled to the
  source of truth: **12 compliance frameworks** = `report --framework` PDF/text evidence
  packs (`pdf_report._FRAMEWORK_TITLES`); **10 agent platforms** = `discovery.AGENT_CONFIGS`.
  Fixed README's "13 frameworks" (×2) and "13 agent platforms", `docs/index.md`
  ("10 frameworks" → "10 agent platforms" — those are platforms, not frameworks),
  CLAUDE.md's architecture-tree "(13 platforms)", and the outbound `launch/**` marketing
  copy (owasp-outreach + both awesome-list PR bodies), which also carried stale
  `225 rules` / `79 scanners`.
- **`report --framework mcp-2026-roadmap` was never valid.** The README listed "MCP 2026
  Roadmap" under the `report --format pdf --framework <name>` enumeration, but
  `mcp-2026-roadmap` is a `scan --compliance` value only — `report --framework
  mcp-2026-roadmap` exits with a Click usage error. Moved it to a correctly-attributed
  `scan --compliance mcp-2026-roadmap` half-sentence so an auditor following the README
  doesn't hit that error. (Three framework surfaces, now stated plainly: **12** =
  `report --framework` evidence packs; **8** = `compliance.FRAMEWORKS` behind
  `scan --compliance`; **10** = agent platforms `discover` walks.)
- **Extended the prose-count fence** (`test_no_stale_hardcoded_counts_in_prose`) to
  `frameworks` + `platforms` and to `launch/**/*.md`, and added
  `test_report_framework_choices_match_titles` (the `report --framework` Click choices
  minus `standards-crosswalk` must equal `_FRAMEWORK_TITLES`, so `len(_FRAMEWORK_TITLES)`
  can't silently drift). Dated empirical case studies
  (`launch/state-of-mcp-security-2026.md`, `launch/blog-50-mcp-servers.md`,
  `research/state-of-mcp-2026/**`) stay exempt — their rule/scanner counts are the
  methodology of a specific past scan run and must keep their published numbers.
- **Fixed two phantom paths** the docs told readers to open: README's `data/history.json`
  (no root `data/`; generated into the published index site by `benchmarks/index_builder.py`,
  served at the gh-pages URL) and ROADMAP's `ECOSYSTEM_STATE_2026-04.md` (not in this repo
  → now points at the in-repo `launch/MARKET-RESEARCH-2026-04-12.md`).
- **`docs/RELEASING.md`**: replaced the repo-description framework count derived by grepping
  the README's own claim with a code read (`len(_FRAMEWORK_TITLES)`), corrected "FRAMEWORKS
  is currently 6" (it is 8), and removed the phantom `_FRAMEWORK_COUNT_RE` / `_RULE_COUNT_RE`
  references. Date-stamped `DEEP_ANALYSIS.md` as a v0.2.0 historical snapshot so its
  77-rule / 9-command figures don't read as current state.
- No rules, scanners, CLI commands, or frameworks added; no runtime behaviour change.

### Changed — public coverage artifact refreshed

- Regenerated `public/owasp-agentic-coverage.json` (the gh-pages coverage board's
  data file) so its `aak_version` / rule mapping track the count-fence work above.
  Generated output only — no rule or scanner changes.

## [0.3.60] - 2026-07-27

Collapses the previously shipped-but-untagged 0.3.58 → 0.3.60 work (State-of-MCP
report, `--emit-coverage` crosswalk, CI codeql-action pin) into one tagged
release, together with the 2026-07-27 release-truth / doc-count reconciliation /
CVE-backlog adjudication (see the "Fixed — release truth" and "Security" sections
below).

### Added — State of MCP Security 2026 data report (fresh 2,303-config corpus)

Publish the credibility artifact — no new detection, nothing gated.

- **Refreshed the corpus** via `fetch_registry.py` from the live MCP Registry:
  **1,641 distinct latest-version servers @ 2026-07-26**, up 2.3× from 710 on
  2026-07-19 (the registry has grown fast). Combined with the GitHub crawl, the
  scanned corpus is now **2,303 distinct public MCP server configs** (up from
  1,374). Snapshot date + N logged in the manifest for reproducibility.
- **Re-ran the aggregation** (`run_report.py`, offline + deterministic) →
  refreshed `results.json`. Headline: **52.3% (1,205/2,303) declare a remote
  server with no authentication** (up from 35.1% as the registry skewed toward
  no-auth remotes), 0% use RFC 9728 PRM discovery, 100% (421/421) of inline-auth
  configs hardcode a static credential, 19.5% `npx`/`uvx`-fetch-execute unpinned
  packages, 52.8% carry a critical finding.
- **Rewrote `research/state-of-mcp-2026/REPORT.md`** — headline `% fail X` per
  rule family, method, corpus size + date, reproduce CLI, the two defensible
  wedges (offline/deterministic + NSA-CSI/OWASP-Agentic compliance crosswalk),
  and the market backdrop (Shai-Hulud 2.0 npm worm, NSA MCP CSI). Explicitly not
  claiming "first". Added a **human PDF** via `output/pdf_report.py`
  (`emit_report_pdf`): `state-of-mcp-security-2026.pdf`.
- README "State of MCP Security 2026" section refreshed with the live headline.
- Counts stay canonical — this data report added no rules. The release total
  lands at **271 rules / 86 scanners** after the CVE-backlog pin below; see
  "Fixed — release truth" for the full one-number-everywhere reconciliation.

### Added — coverage crosswalk asset (`--emit-coverage`) + State-of-MCP report seed

Make the tool's coverage legible without adding any rules.

- **`agent-audit-kit --emit-coverage [--format json|md]`** — walks the built-in
  rule registry and emits, per rule: id, title, severity, the CVE(s) it covers,
  its OWASP MCP Top-10 slot, OWASP Agentic Top-10 (2026) slot, NSA MCP Security
  CSI control, and EU AI Act article — grouped and counted by framework. One
  source of truth: `agent_audit_kit/output/coverage_map.py`, reusing the
  committed compliance + OWASP mappings (nothing hand-typed; `total_rules` is
  always `len(RULES)`). Byte-deterministic.
- **Two artifacts:** [`docs/coverage.json`](docs/coverage.json) (machine-readable)
  and [`docs/STATE-OF-MCP-SECURITY-2026.md`](docs/STATE-OF-MCP-SECURITY-2026.md)
  (human report seed — coverage table + a stubbed "we scanned N public MCP
  servers, here's what breaks" corpus section cross-linking the live data run).
  README gains a "Coverage, mapped to frameworks" section.
- **Reserved 2026-07-28 MCP-final crosswalk slots** (no rules invented): stateless
  `_meta`-per-request and JSON-Schema-2020-12 tool schemas are **reserved**;
  SEP-1865 MCP Apps and SEP-2663 Tasks are already **covered** by shipped rules.
- **Count-drift guard:** the count is canonical across the README badge/anchors,
  `__init__.RULE_COUNT`, and the signed bundle, enforced by
  `test_rule_count_is_canonical`. The report seed's rule count is an auto-synced
  `<!-- rule-count:total -->` anchor, and `docs/coverage.json` has a byte-staleness
  test — so the artifacts can't drift.

### Fixed — release truth: version/tag + one-number-everywhere reconciliation

- **Cut the real `v0.3.60` tag.** The README told users to pin
  `sattyamjjain/agent-audit-kit@v0.3.60` and `rev: v0.3.60`, but neither the tag
  nor the PyPI release existed (newest was v0.3.58). Collapsed the three
  shipped-but-untagged `[Unreleased]` blocks into this single tagged release so
  the documented install path resolves.
- **One number everywhere.** Reconciled every count surface to the live registry:
  **271 rules, 86 scanner modules, 25 CLI commands, 12 categories, 12 compliance
  frameworks.** Fixed the GitHub repo description (was "225 rules across 11
  categories"), the README CLI list (was "16 CLI commands" — the real,
  `--help`-listed set is **25**, previously under-counted as 22; added the missing
  `corpus`, `pipelock`, `rule`), CLAUDE.md's stale `v0.3.41` header (now references
  `pyproject.toml` / `__version__` instead of hard-coding a version), the docs
  standards-crosswalk total, and `docs/index.md`.
- **Guards.** New `tests/test_version_consistency.py` fails if `pyproject`
  version ≠ `__version__` or if any README `@vX` / `rev: vX` / `==X` self-pin
  disagrees with the declared version. Extended
  `test_no_stale_hardcoded_counts_in_prose` to scan README.md, CLAUDE.md, and all
  `docs/**/*.md` for headline `N rules` / `N scanner modules` / `N CLI commands`
  claims and fail on any disagreement with the registry.

### Security — 2026-07-27 CVE-response backlog adjudicated (7 issues, 270 → 271 rules)

Every open `cve-response` issue got a visible verdict against the NVD record and
was closed, clearing the release gate:

- **In scope — new pinned rule.** `AAK-MCP-AWSAPIMCP-CVE-2026-16584-001` (HIGH) —
  the AWS API MCP Server (`awslabs.aws-api-mcp-server`) skips its security-policy
  check for the process lifetime when policy-data init fails at startup; affected
  0.2.13–1.3.46, fixed 1.3.47. Pinnable `uvx`/PyPI artifact → version pin in
  `mcp_cve_pins_2026_07` (introduced-bounded). (CVE-2026-16584, #491)
- **Already covered.** CVE-2026-63732 (9router 0.4.59, CVSS 9.9) is caught by the
  existing `AAK-MCP-9ROUTER-CVE-2026-46339-001` (`< 0.5.2` floor); appended to its
  CVE ledger so the crosswalk records it. (#496)
- **Out of scope — server-side flaw / no pinnable artifact.** SiYuan `POST /mcp`
  missing-authorization (CVE-2026-66012, #499), MountDev WordPress MCP connector
  OAuth bypass (CVE-2026-15015, #490), Jan local-API CORS reflection
  (CVE-2026-66005, #498), NanoClaw approval-bridge authz — no vendor fix to pin
  (CVE-2026-17433, #500), and APIFold unauth-webhook resource poisoning —
  commit-level fix, URL-referenced (CVE-2026-47769, #492). Each closed with a
  one-paragraph rationale naming the upstream fix and the config-side AAK rule
  (e.g. `AAK-MCP-001`) that flags the reachable posture.

### Changed — security-response SLA rewritten to best-effort (solo maintainer)

- Replaced the "**within 48 hours**" acknowledgment SLA (and the 7-day / 30-day
  clock) in `SECURITY.md` with an honest, severity-prioritised best-effort
  commitment — no fixed clock a single maintainer can't keep. Same for the
  outbound 48h notification promise in `docs/disclosure-policy.md` and the
  "correct within 48 hours" claim in `docs/comparisons.md`. Fixed the stale
  `sla-48h` label reference in `docs/RELEASING.md` (the gate keys on
  `cve-response`; `sla-48h` was retired in PR #432). Nothing silently deleted —
  every claim rewritten in place.

### Fixed — CI: codeql-action version consistency + reproducible lint (#493)

- Pinned all `github/codeql-action/*` steps to one version (v4.37.1) — Dependabot's
  per-sub-action PRs left init/analyze at different versions, failing CodeQL with
  a configuration error. Bumped `actions/cache` v5 → v6, grouped github-actions
  Dependabot bumps into one PR (no more mismatch), and capped `ruff>=0.15,<0.16`
  so the linter version is reproducible (0.16.0 flagged 281 pre-existing style
  issues on fresh installs). Closed Dependabot PRs #398–#402.

## Older releases

Entries for **0.3.58 and earlier** (down to 0.2.0) are archived in [docs/changelog/archive/CHANGELOG.md](docs/changelog/archive/CHANGELOG.md) to keep this file reviewable in a PR diff. New entries go here; the archive is frozen history.
