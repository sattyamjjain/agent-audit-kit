# Changelog

All notable changes to AgentAuditKit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.94] - 2026-09-04

### Added

- **Two rules, and the nine deferred CVEs they close.** Rules 331 and 332.
  `AAK-MCP-MCPHUB-CVE-2026-79748-001` (SUPPLY_CHAIN, **CRITICAL**) and
  `AAK-MCP-SEQTHINKING-CVE-2026-81845-001` (SUPPLY_CHAIN, **MEDIUM**).

  Nine issues had sat under `cve-deferred` with dated targets. What released them
  was not the clock, it was checking a registry, and in both cases the check
  changed what got written.

  **MCPHub** was held open on one question: is PyPI `mcphub` the same project as
  npm `@samanhappy/mcphub`? It is not. The npm package is a self-hosted MCP
  gateway on the 1.0.x line (latest 1.0.34); PyPI `mcphub` is Cognitive-Stack's
  framework-integration library on 0.1.x (latest 0.1.11), different author,
  different repository. That distinction is load-bearing rather than pedantic:
  PyPI `mcphub` can never reach a 1.0.32 floor, so a bare-token pin would not
  misfire occasionally — it would flag **every dependent, permanently**, for a CVE
  in software they do not run. The pin is keyed on the scoped npm name and a test
  asserts nothing fires on the PyPI package. Eight advisories
  (CVE-2026-79743…79750) fixed across six versions, so one floor at the highest of
  them covers all eight rather than reporting one dependency eight times.

- **A second arm on the n8n pin, which is the part that would have been missed.**
  `AAK-MCP-N8N-CVE-2026-72768-001`'s floor moves 2.34.1 → 2.35.4 for
  CVE-2026-85166, and gains a second `introduced`-bounded arm at 2.36.2.

  The advisory reads "before 2.35.4 **and** 2.36.x before 2.36.2". A single 2.35.4
  floor clears 2.36.0 and 2.36.1 — versions that sort *above* it and are still
  vulnerable — so the obvious one-line floor bump would have silently marked
  vulnerable installs as patched. This is the same two-branch shape
  CVE-2026-65594 already uses, so it stays one n8n rule id rather than becoming a
  fourth. A test states the bug in the form it would have shipped in, so a later
  "simplification" back to one arm fails loudly instead of going quiet.

### Fixed

- **`CITATION.cff` said 0.3.83 while the repo shipped 0.3.93.** Ten releases of
  drift on the file GitHub renders as "Cite this repository" — the one surface
  whose entire job is telling a stranger which version produced the numbers they
  are about to quote.

  It drifted for the ordinary reason. Its header comment read "Bump `version` and
  `date-released` with each release", which is an instruction to a human, and
  nothing read it: `test_version_consistency` enumerates four surfaces (pyproject,
  `__version__`, the README pins, the newest tag) and stops there. Neither field
  is hand-written now. `version` comes from pyproject and `date-released` from the
  CHANGELOG heading for exactly that version — the release date is already written
  down there, and asking a human to retype it elsewhere only creates a second
  place to be wrong. `sync_repo_metadata.py --check` fails the build on drift.

  The guard is anchored to the top-level key on purpose. `preferred-citation`
  carries its own `version: "1.0"` — the *report's* identity, which moves when a
  measurement changes, not when software ships — and an unanchored pattern would
  stamp the package version over it on every release, silently claiming the report
  had been revised. A test asserts the pattern matches exactly once.

## [0.3.93] - 2026-09-04

### Added

- **`cve-deferred` now has to say when.** The label is the single thing that
  switches the release gate off. It was added on 2026-09-01 for a good reason —
  the watcher's 6-hour cron outran the triage rate, so `count == 0` became a
  state the repo could not reach on purpose and v0.3.91 sat unpublished for a day
  — and `docs/RELEASING.md` §5 asked deferrals to carry "a disposition comment
  naming what is queued and why". Prose, read by nobody.

  Every deferral in the 2026-08-31 wave did carry a `**Target: YYYY-MM-DD.**`
  line, so the convention was real and working. That is exactly why nobody
  noticed it was unenforced: a label whose only obligation is a convention is one
  busy afternoon away from being a mute button, and a deferral with no date is
  not a deferral, it is a silent drop with a label on it.

  `scripts/check_cve_deferrals.py` runs inside the CVE-response gate and refuses
  the tag when a `cve-deferred` issue names no target date. It accepts the older
  `**Target: …**` spelling as well as the structured `target date:` field —
  rejecting the prose form would have convicted ten issues that did the right
  thing on the day the guard landed, teaching the one lesson a guard must never
  teach. `.github/workflows/cve-deferral-date.yml` says the same thing at label
  time, and deliberately does not strip the label: labelling first and writing
  the disposition second is the natural order, and a bot that yanks the label out
  from under that is a bot people route around. Warn there, refuse the tag here.

  A target date in the **past** is listed on every run and fails nothing. Making
  it fatal was the obvious next step and is a trap: it turns every scheduling
  note in the tree into a time bomb that detonates during an unrelated release,
  on a morning nobody chose.

  All 14 open `cve-response` issues were dispositioned in the same pass. The four
  untriaged ones: n8n CVE-2026-85166 deferred to a floor bump on the existing
  `AAK-MCP-N8N-CVE-2026-72768-001` pin (2.35.4 and 2.36.2 are both published);
  Helicone CVE-2026-85178 and two WordPress plugin advisories closed out of scope
  on the boundary this repo has recorded five times before — the vulnerable code
  is in a hosted platform server or a wordpress.org plugin, and the artifact that
  *does* resolve on npm/PyPI (`helicone`, "a wrapper for the OpenAI API that logs
  all requests") is a client SDK that does not contain it.

### Fixed

- **The benign-slice false-positive rate was 50%, and no rule was at fault.** The
  published badge read `2/4 (50.0%)` on a 536-config slice. Re-adjudicating the four
  HIGH/CRITICAL findings against primary data — the cached registry pages the corpus
  was built from — found no rule defect at all. All four were `AAK-MCP-001` ("remote
  MCP server without authentication"), and the rule was correct about every config it
  was handed. The configs were wrong.

  The mechanism is a disagreement inside the corpus builder that nothing compared.
  `fetch_registry._auth_mode()` looks across **every** remote a registry record
  publishes and reports `static-credential` if any of them declares a secret header.
  `_to_config()` built the scannable config from `remotes[0]` **only**. A server that
  publishes an anonymous or login entry point first and its credentialled endpoint
  second was therefore labelled `static-credential` while being handed to the scanner
  with no auth on it at all. `co.curie/commerce` and `co.huggingface/hf-mcp-server`
  each declare `Authorization` on remote 1; `app.thoughtspot/mcp-server` resolves to a
  `/bearer/mcp` remote declaring `Authorization` + `X-TS-Host`.

  `_to_config()` was fixed on 2026-08-24 to prefer the first remote that declares
  headers, but the committed manifest predated the fix and went on carrying the broken
  configs while every test passed. `RESULTS.md` deliberately did not bundle the
  regeneration into a precision fix, so the number would not move for two reasons at
  once. This is that regeneration, on its own.

  Re-derived from the same cached 2026-07-26 registry snapshot rather than from the
  live registry, so the slice size and the fetch date are unchanged and the two runs
  are directly comparable. **3 of 1,641 configs change, 0 `auth_mode`s change**, and
  the patched manifest was asserted equal to a full re-derivation. Total findings are
  unchanged at 1,158: the three configs stopped firing `AAK-MCP-001` (CRITICAL) and
  started firing `AAK-OAUTH-008` (LOW), the expected posture finding for a
  static-credential server with no RFC 9728 discovery. The scanner did not go quieter,
  it went more accurate, and the severity mix is the evidence.

  **Benign-slice HIGH/CRITICAL false-positive rate: 2/4 (50.0%) → 0/1 (0.0%)**; Wilson
  95% CI [15.0%, 85.0%] → [0.0%, 79.3%]. The interval is wide because the denominator
  is 1, and it is published rather than buried — a 0.0% point estimate on one
  adjudicated finding is not evidence that the scanner is never wrong. No rule
  severity was downgraded and no matcher was narrowed: the standing true positive
  (`ai.spala/public-mcp`) still fires, and a test asserts it, because a lower
  false-positive rate bought with a false negative is not an improvement.

  `tests/test_registry_corpus_auth_consistency.py` is the guard the class was missing:
  **no server labelled `static-credential` may have a config with no auth header.** It
  reads only committed data, so it fails on a stale manifest even when `_to_config`
  itself is correct — which is exactly the state that shipped.

  The corrected corpus moves the State of MCP Security 2026 headline by those same
  three configs: critical 1,215 → 1,212 (52.8% → 52.6%), no-auth 1,203 → 1,200 (52.2%
  → 52.1%), inline-auth 421 → 424 (still 100%). README, REPORT.md, PREVALENCE.md,
  CITATION.cff, `docs/STATE-OF-MCP-SECURITY-2026.md` and
  `docs/DISTRIBUTION-CHECKLIST.md` all follow.

- **`AAK-DNS-REBIND-001` read straight past every Python FastMCP server**
  (CVE-2026-81102, #660). The Dash MCP server bound its listener to loopback and never
  checked the `Host` a request named, so a name rebound to loopback still reached it
  and could drive its tools under the credential the server holds. The detector matched
  `StreamableHTTPSessionManager`, `streamable_http` and `StreamableHTTPServerTransport`.
  FastMCP names none of them: it is built as `FastMCP(...)` and selects its transport
  with `run(transport="streamable-http")` — a **hyphenated string literal**, where the
  detector looked for `streamable_http` with an underscore.

  Extended, not duplicated. Same rule id, same mitigation marker (`allowed_hosts=`
  already covered FastMCP's `TransportSecuritySettings`), same remediation, following
  the 2026-09-02 triage note that these are "the same claims over a language and a
  transport the detectors do not currently read, so they get a scanner path, not a
  second rule id". **stdio is deliberately not flagged**: FastMCP defaults to stdio, a
  stdio server has no listener to rebind onto, and the advisory says only the network
  mode was reachable — requiring an explicit network transport is what keeps this from
  firing on essentially every FastMCP server written. **Binding to loopback is not a
  mitigation** and does not clear the rule, because CVE-2026-81102 was loopback-bound;
  the Host allow-list is the control. Fixtures: `python-fastmcp-unguarded` fires,
  `python-fastmcp-guarded` and `python-fastmcp-stdio` stay silent, and every
  pre-existing fixture keeps its verdict.

- **The transport rules did not recognise WebSocket, and did not say which transports
  they covered** (CVE-2026-37006, #662). Measured rather than assumed: `AAK-MCP-001`
  already treated a `ws://` URL as remote and unauthenticated, so the unauthenticated
  half was covered. `AAK-TRANSPORT-001` (cleartext transport) was not — it matched
  `^http://` only, so a `ws://` MCP server was silently exempt from the project's
  cleartext-transport rule while a byte-identical `http://` server was CRITICAL.
  `ws://` is not a milder form of the defect: the handshake is an unencrypted HTTP
  upgrade, so its headers and every frame after it are on the wire in clear. `wss://`
  is the encrypted counterpart and is not flagged, and the loopback carve-out now
  applies to both schemes rather than one.

  The second half of the gap was documentation. `AAK-TRANSPORT-001` through `-004` each
  now state **which transports they apply to and which they do not**, including where
  stdio stands, instead of leaving a reader to infer "stdio or http" from a regex —
  which is how WebSocket went unread across four rules at once. A test asserts every
  rule in the family carries both statements. `AAK-TRANSPORT-001`'s title changes to
  "MCP server uses a cleartext transport (http:// or ws://)", because the old title
  named only one of the two schemes it now reads.

- **A standing report that read as current, checked by nothing.**
  `docs/reports/mcp-2026-07-28-readiness.md` is written as a live artifact: no
  historical banner, linked as a current finding, closing with a promise to
  re-run "on ratification day (2026-07-28) and on a rolling basis". It was
  generated once, in July, and never re-derived.

  Its nine numbers all still reproduce exactly — the corpus has not moved and
  `AAK-OAUTH-006/007/008` are all still in the registry. That is luck. The corpus
  is a directory any PR may add to, and the day one does, the report becomes a
  confident wrong number carrying a citation, which is worse than no report.
  `tests/test_readiness_report_is_current.py` now asserts the rendered table
  against a fresh `scripts/mcp_2026_07_28_readiness.py` run, so the promise of a
  rolling re-run is kept by a test rather than by intention. It skips where
  `benchmarks/data/` is absent — the corpus is gitignored, so a bare CI checkout
  cannot measure the report at all and zeros there would mean "unmeasurable",
  not "wrong". The guard therefore bites on a maintainer checkout and any job
  that fetches the corpus, which is where a change to it can actually originate.
  Written out rather than described as "guarded by CI", because that would claim
  a gate the check does not have.

  Its tense was wrong independently of its numbers. The report described the
  2026-07-28 specification as a release candidate whose "final publication
  [is] scheduled" — true when written, and read after that date, an artifact
  that is wrong about the calendar invites a reader to discount the parts that
  are right. It now records publication as having happened, carries a
  **Re-validated: 2026-09-04** stamp, and a test fails if the "scheduled"
  phrasing ever comes back.

- **`Category` (12 members) in `CLAUDE.md`, while the enum had 14.** The fourth
  instance of the same blind spot, after "N existing rules" (v0.3.72), "N
  registered scanners" (v0.3.81) and the category count itself (v0.3.84).
  `check_counts.py` matches phrasings, not numbers: the category pattern is
  anchored on the headline "rules … across N categories" form, so it never looked
  at the backticked-enum form, and the corroboration sweep reads `README.md` and
  `docs/**` while this claim lives in `CLAUDE.md`. The result was one file
  asserting "330 rules across 14 security categories" on line 8 and "`Category`
  (12 members)" on line 137 with `make count-check` reporting clean — a count
  wrong in the one file that tells the next reader the counts are guarded. The
  number is corrected and the phrasing is now in `PATTERNS`, anchored on the
  backticked symbol so it only ever matches a claim about the enum itself.

## [0.3.92] - 2026-09-02

### Added

- Three rules. `AAK-SSRF-BRACKETED-HOST-001` for CVE-2026-80347,
  `AAK-MCP-TOOLS-LIST-UNBOUNDED-001` for CVE-2026-84289, and
  `AAK-APPROVAL-PARSER-DESYNC-001` for CVE-2026-19591. Rules 327 to 330. Scanners
  95 to 98.

  All three sit next to a rule that looks like it should already cover them. None
  of them does, and the reason is the same every time. The defence is present, so
  a detector keyed on the defence being missing stays quiet. mcp-fetch has an SSRF
  allow-list. It hands `net.isIP` a bracketed IPv6 literal, which returns 0, so
  the private-address branch never runs and the guard allows. Hermes bounds
  nothing on the upstream tool catalogue, and `AAK-MCP-016` bounds the inbound
  request body, which is a value arriving from the other direction. Codex parses a
  command before approving it, and pwsh reads `--%` as stop-parsing, so the
  command that was approved is not the command that runs.

  Every shape was scanned against the whole engine before a rule was written.
  Nothing fired for any of them. Each rule has a positive fixture and a benign
  fixture, and the benign one is a single line different from the positive. Zero
  hits on the 536-server benign slice, so the published false-positive rate is
  unchanged and needed no re-adjudication.

### Changed

- Triaged all 16 open `cve-response` issues, CVSS descending, NVD entry read for
  each. Three came out NEW-RULE and were written today. Twelve are DEFERRED with a
  target date. One is OUT-OF-SCOPE and closed. The 13 that already carried
  `cve-deferred` all had a disposition comment, but none carried a date, so all 13
  were re-dispositioned with one.

  The closed one is #680. runZero Platform's MCP service is a genuine MCP surface
  and a genuine authorization bypass. It is also a hosted product. `runzero`
  resolves on neither npm nor PyPI, and the fix landed server-side, so there is
  nothing in a user's own repository to pin, patch, or detect.

  Two deferrals stayed deferrals deliberately. #660 and #662 need an existing
  detector widened, not a new rule id. `AAK-DNS-REBIND-001` does not fire on
  Python FastMCP, and the transport rules do not recognise WebSocket. Giving
  either shape its own rule id would report one defect class under two ids.

  The three NEW-RULE issues stay open and carry no `cve-deferred`, so they keep
  blocking the release gate until the rules merge. That is deliberate. Deferred
  work and today's work are not the same thing.


- **The CVE watcher has a limit.** It filed one release-gating issue per CVE on a
  6-hour cron with no upper bound and opened 27 in five days, eight of them one
  product's advisory batch in a single run. At most 5 new issues per run, most
  severe first, and none while 10+ untriaged issues are already open. The
  pre-filter was deliberately left alone: all 27 were genuine MCP CVEs, so
  tightening relevance would have dropped true positives to fix a rate problem.
  The cap lives in `collect_new_cves`, not in the workflow step that creates
  issues, because `state["filed_cves"]` records everything the function returns —
  capping after the fact would mark held CVEs as filed and lose them. The NVD
  window widened 48h → 7 days so a held CVE is still findable when the queue
  drains; that is what separates back-pressure from data loss, and it has a test.
- The 27-issue queue was triaged to 13: 10 closed as already covered by a shipped
  rule (each confirmed by scanning a fixture of that shape, not asserted from the
  rule title), 3 closed as unreachable, 1 closed as out of scope, and 13 left
  open under `cve-deferred` with the queued work named. Two of the deferrals are
  gaps the fixture testing found rather than assumed: `AAK-DNS-REBIND-001` does
  not fire on Python FastMCP's `streamable_http_app()`, and `AAK-MCP-SSRF-001`
  cannot fire on mcp-fetch because the SSRF guard is present and bypassed rather
  than absent.

### Fixed

- The gate can no longer be switched off by labelling. `cve-deferred` exempts an
  issue from the release gate, and docs/RELEASING.md §5 said the label is only
  honest on an issue that has a disposition comment. That was prose, and prose
  does not fail a build. Two tests now read the tracker and fail if a deferred
  issue has no maintainer comment, or no `## Disposition` comment. When the
  tracker cannot be read they skip and say they did not check, rather than
  passing. The predicates are unit-tested on synthetic data, so the check still
  holds on a machine with no network.
- Verified the registry parity gate catches the defect it was written for.
  Declared 0.3.91 against a registry serving 0.3.90, on the real git clock, exits
  1 and prints both versions. A wrong declared version fails. A registry ahead of
  the repository fails. An unreachable registry warns that it did not compare. No
  defect in the failure path, so nothing needed fixing there.

- **0.3.91 was written and never shipped, and nothing could see it.** pyproject
  said 0.3.91, the CHANGELOG had a dated 0.3.91 section, the counts were synced,
  the tests passed and main was pushed — while PyPI served 0.3.90. The proximate
  cause was that the tag was never pushed (no `[skip ci]` on the bump commit;
  `on: push: tags: ['v*']` would have fired; no release run exists to have failed
  quietly — the workflow simply never ran). The **root cause** is that pushing it
  could not have worked: the CVE-response gate refused to release while *any*
  `cve-response` issue was open, and the watcher opens them on a 6-hour cron with
  no back-pressure. The queue reached 27, so `count == 0` had stopped being a
  state the repository could reach on purpose. The gate had quietly changed
  meaning from "every disclosure has been looked at" to "never ship".
- The gate now blocks on **untriaged** issues. `cve-deferred` marks one that has
  been read, dispositioned in a comment and scheduled; anything without a
  disposition still blocks exactly as before. `docs/RELEASING.md` §5 carries the
  disposition table and says plainly that the label is only honest on an issue
  that has the comment — a label without one turns the gate off rather than
  satisfying it.
- **Every version check this repo owned compared one in-repo surface to another.**
  pyproject against `__version__`, the CHANGELOG heading against the newest tag,
  the README's Action pin against both. All of them passed for a full day while
  the declared version did not exist on PyPI. The repo can be perfectly
  self-consistent about a version nobody can install, and was.
  `scripts/check_registry_parity.py` compares the declared version to the
  **registry**, and runs daily as well as on push — on push,
  0.3.91-declared-vs-0.3.90-published is correct for ten minutes and a defect
  after a day, the two states produce an identical diff, and a release that never
  happens produces no push to check at all. The age clock is read from git rather
  than the CHANGELOG's own date, so a back-dated heading cannot hide it. An
  unreachable registry is a loud SKIP, never a silent pass.
- **The repo description was checked on a clock that only ticks during a
  release.** It read "326 rules" against a live count of 327 because the check
  lives inside `release.yml` and 0.3.91 never released — the same root cause as
  above, in a second surface. There is now a daily `description-liveness`
  workflow.
- **The description writer and its own checker disagreed about the text.**
  `sync-repo-metadata.yml` writes `sync_repo_metadata._description_string()`,
  which composed its own string; `description-liveness` compares against
  `render_repo_metadata.render()`, which folds the template in
  `.github/repo-metadata.yml`. A successful write would have set a description
  the next release rejected. It never surfaced only because the write step has
  never run — it needs a `METADATA_SYNC_TOKEN` that does not exist. Two latent
  bugs were cancelling out. The writer now delegates to the renderer, one test
  fails if they diverge, and the comparison itself moved into
  `render_repo_metadata.py --check-live` so `release.yml` and the scheduled
  workflow cannot drift apart either.
- `render_repo_metadata.py` could not import the package it reads counts from
  unless the caller set `PYTHONPATH=.`. `python scripts/x.py` puts *scripts/* on
  `sys.path`, not the repo root, so `from agent_audit_kit import RULE_COUNT`
  fails in any job that has not pip-installed the package. `release.yml` carried
  a `PYTHONPATH=` workaround and a comment calling the omission the reason "a
  stale description survived three release cycles undetected";
  `sync-repo-metadata.yml` had none, so making it a dependency of
  `sync_repo_metadata --description` broke that job in the v0.3.91 release run.
  The module now puts the repo root on `sys.path` itself, which fixes it for
  every caller instead of once per workflow. Regression test runs both scripts
  under `python -S`, so the editable install's `.pth` is not read and the
  reproduction is real — without the fix it raises `ModuleNotFoundError`.
- `render_repo_metadata.py` ignored its own command line: `main()` defaults argv
  to `[]` for deterministic parsing under pytest, so `__main__` has to pass
  `sys.argv[1:]` and did not — `--check-live` silently rendered instead of
  checking. Third occurrence of this pattern in the repo, so it is now commented
  where the next person will read it.


## [0.3.91] - 2026-08-31

### Added

- `AAK-MCP-TRANSPORT-SESSION-UNAUTH-001` (critical, transport-security) for
  CVE-2026-82456 — argocd-mcp 0.8.0, CVSS 10.0 on both 3.1 and 4.0. Rules 326 → 327,
  scanners 94 → 95. A family rule keyed on the conjunction rather than the package:
  an MCP HTTP transport, an any-interface bind, and a credential that points outward.
  Nothing in the rule text names argocd, and a test asserts that.
- `scanners/mcp_transport_session_unauth.py`, and `CVE-2026-82456` in the ledger with
  its 2-day disclosure-to-rule latency (published 2026-08-29, shipped 2026-08-31).

### Fixed

- The project's own no-auth rule read a CVSS 10.0 as authenticated.
  `AAK-MCP-HTTP-NOAUTH-SERVER-001` asks whether a file holds any auth marker, and
  `_AUTH_MARKER_RE` counts a bare `Authorization:` — which an **outbound** header
  satisfies. Per GHSA-rp45-5x3v-48mr: "The environment variable is an outbound Argo
  CD credential. It does not authenticate the caller." Verified before the rule was
  written: on the advisory's own snippet the engine reported only
  `AAK-DNS-REBIND-001`, and fixing just that leaves the server exploitable from the
  LAN.
- The same rule could not see the bind either. It needs a literal `0.0.0.0`/`::`;
  argocd-mcp has neither, because `app.listen(port)` binds every interface by
  omitting the host. That implicit bind is now detected — for JS/TS only, since
  `uvicorn.run` and `Flask.run` default to loopback and inferring it there would
  invent findings.
- `CLAUDE.md` claimed "97 .py files on disk" while `scanners/` held 96. The phrasing
  was not in `check_counts.PATTERNS`, so `make count-check` never looked at it — a
  count wrong in the file that tells the next reader the counts are guarded. Added
  `scanner_files` as its own canonical entry and pattern.

### Changed

- Dependabot: `actions/setup-python` 6 → 7 (#669, also normalising `@v7.0.0` → `@v7`)
  and `github/codeql-action/{init,autobuild,analyze,upload-sarif}` 4.37.7 → 4.37.9;
  `click` 8.4.2 → 8.5.0 (#668). No `setup-python@v6` remains in `.github/`.

### Notes

- SARIF `security-severity` for the new rule is **9.5**, the repo's CRITICAL band
  constant — scores are derived from the severity band for all rules and there is no
  per-rule CVSS field, so the advisory's 10.0 lives in `cve_references` and the
  ledger rather than in the SARIF property.
- The new rule fires zero times on the 536-server benign slice (`make fp-check`), so
  the published false-positive figure is unchanged and needed no re-adjudication.


## [0.3.90] - 2026-08-26

### Fixed

- The State of MCP report's headline number was published two ways and one was wrong.
  `results.json` says 52.2% (1,203) no-auth; README:55, README:571,
  docs/DISTRIBUTION-CHECKLIST.md (four places, including the Show HN title and the
  Reddit drafts), docs/STATE-OF-MCP-SECURITY-2026.md, PREVALENCE.md (four places)
  and CITATION.cff still said 52.3% (1,205). PREVALENCE.md and the distribution copy
  also said 1,217 configs with a critical finding where results.json says 1,215.
- The `report:` marker generator now covers README.md,
  docs/STATE-OF-MCP-SECURITY-2026.md and PREVALENCE.md rather than README alone, and
  gained `critical-n` / `critical-pct` keys.
- CITATION.cff and docs/DISTRIBUTION-CHECKLIST.md are corrected but deliberately
  carry no markers: the first states its figures in a YAML block scalar that renders
  into the citation abstract, and the second is copy a human pastes into a comment
  box. Both are asserted against results.json in the test instead.
- `tests/test_report_headline_numbers.py` was a three-way lock on README + REPORT.md,
  which is why the other five surfaces rotted. It now checks every marker occurrence
  on every marker file, asserts the prose surfaces, requires the file list to match
  the generator's, and fails if a marker appears in the paste copy.
- The README comparison table's "A2A protocol scanning | 13 rules" was unguarded.
  The number was correct; it is now a per-category anchor.
- `test_readme_per_category_anchors_match_registry` summed every anchor occurrence
  and compared that to the rule total, which only held while each category appeared
  once. It now asserts what was intended — that no category is missing — and that
  two anchors for one category agree.
- Two source comments still asserted the retired 48h CVE-to-rule SLA:
  `mcp_middleware.py` justified a design decision by it, and `supply_chain.py`
  recorded "48h SLA met" beside a latency of 72 hours. Both reworded, and a test now
  fails if the claim reappears in source.

### Added

- Five rules for the 2026-08-26 CVE wave: `AAK-MCP-QWED-CVE-2026-55546-001`,
  `AAK-MCP-NEXTCLOUD-CVE-2026-55640-001`, `AAK-MCP-BROWSEMCP-CVE-2026-55557-001`,
  `AAK-MCP-GENIEACS-CVE-2026-55637-001`, `AAK-MCP-SUBLINEAR-CVE-2026-55609-001`.
  Rule count 321 -> 326.
- Three PraisonAI CVEs (CVE-2026-55532, CVE-2026-55529, CVE-2026-55531) recorded on
  the existing `AAK-MCP-PRAISONAI-CVE-2026-61427-001`, whose 4.6.78 floor already
  sits above their 4.6.58 fix. No second pin: two pins on one package report one
  dependency twice.
- Five CVEs closed out of scope with written reasons: three mcp-shell advisories
  (Go; the same-named npm and PyPI packages are different projects and never reach
  the 0.6.0 fix), Coroot (Go binary, on neither registry) and the MCP PHP SDK
  (Composer).


## [0.3.89] - 2026-08-25

### Added

- Rule AAK-MCP-TOOL-ARG-OSCMD-001 for CVE-2026-78430: a tool handler passing a
  model-supplied argument into an OS command. Positive and negative fixtures.
- The coverage page publishes median and p90 CVE-publication-to-rule-shipped days
  over the trailing 90 days, with n, and fails the build when the figure is stale.

### Changed

- AAK-TAINT-001 is suppressed on any line where AAK-MCP-TOOL-ARG-OSCMD-001 fires.
  Both are CRITICAL and both matched the same line, which reported one defect twice.
- scripts/build_coverage_page.py takes --check, and main() no longer reads sys.argv
  when called from Python. It parsed pytest's own flags and exited.
- cve_latency.py recognises every dated ledger heading. It required parentheses, so
  the nine most recent `## DATE: title` sections never matched and their rows
  inherited the date of the parenthesised heading above them. Published p90 over the
  trailing 90 days: 4 days -> 2 days, n=47.

### Triaged

- CVE-2026-19801 (BetterLinks for WordPress) closed as out of scope. The plugin ships
  a real MCP server under includes/Mcp/, so this is not a name collision, but the
  vulnerability is in WordPress wp_ajax_* handlers in includes/Admin/Ajax.php and
  nothing under includes/Mcp/ references them. Fixed upstream in 3.1.1.

## [0.3.88] - 2026-08-24

### Fixed

- **None of the VS Code extension's commands were reachable.** `sarifReader.ts` was known dead code, but the cause turned out to be wider than that one module: `package.json` declared no `contributes.commands` at all, while `extension.ts` registered `agent-audit-kit.scan` and `agent-audit-kit.showOutput` and `sarifReader.ts` registered `agent-audit-kit.loadSarif`. Three commands in code, zero in the manifest, so the Command Palette showed none of them. All three are declared now, and `activate()` calls `registerSarifCommands(context)`, which it never did — so the SARIF-to-diagnostics feature ran for the first time. Verified by `npm run compile`: `out/sarifReader.js` is emitted and required by `out/extension.js`. The SARIF reader keeps its own diagnostic collection (`agent-audit-kit-sarif`), so imported findings never overwrite scanned ones. Extension version 0.3.2 → 0.3.3.
- `vscode-extension/.gitignore` was missing, which `.vscodeignore` already assumed existed by listing it. A single `npm install && npm run compile` left `node_modules/` and `out/` as untracked noise in every `git status`. Both are ignored now, along with `*.vsix`.
- Removed a stale **draft** release for `v0.2.0`, created 2026-04-05 with no assets and superseded by 30 published releases. It sat at the top of the releases API response, so any tooling reading `.[0]` got a four-month-old draft instead of the current release. The `v0.2.0` tag is untouched, and the draft's body was backed up before deletion.

- **The two open `cve-response` issues closed as `wontfix-static`, with the reason recorded as the artifact.** CVE-2026-60083 and CVE-2026-59809 are both real SiYuan defects fixed in v3.8.0, and neither is detectable by this scanner. Everything about the pair looks pinnable — one named product, one clean fix version, a package by that exact spelling on both npm and PyPI — which is why the disposition is pinned as a test rather than left as an empty result. Three independent reasons: both GHSAs declare ecosystem `go` (`github.com/siyuan-note/siyuan`) and there is no `go.mod` reader in `_CANDIDATE_NAMES`; npm `siyuan` is the plugin API typings from `siyuan-note/petal` (1.2.5) and PyPI `siyuan` a third-party client (0.1.2), neither line reaching 3.x, so a `>= 3.8.0` floor on either fires on 100% of their releases; and SiYuan mounts MCP on its own kernel, so a consumer's config holds a URL and a token and no version. The reachable half was already covered — `AAK-TRANSPORT-004` reports a secret placeholder in a URL query string in both the `{{secrets.NAME}}` and `${VAR}` dialects, verified by scanning the advisory's own PoC URL. `test_the_pin_detector_reads_no_go_manifest` fails the moment a `go.mod` reader is added, which is how these become re-triageable rather than forgotten.
- **The benign-slice false-positive badge was stale and also read wrong.** `0/1 (n=1)` parses as "one thing was tested"; it was not — 368 configs were tested and one high-severity finding came out of them. Meanwhile the corpus manifest had been refreshed 1,374 → 1,641 registry servers and the benign slice had grown 368 → 536, with nothing re-running the benchmark, because the harness had no Makefile target and therefore no guard. Re-measured on the current 536-config slice and published untuned first, in its own commit: **6 HIGH/CRITICAL findings, adjudicated 4 FP / 1 TP / 1 ambiguous = 4/6 (66.7%)**. Then fixed and re-measured: **2/4 (50.0%)**.
- **`AAK-MCP-001` recognises the `-token` and `-secret` credential-header families.** #475 generalised the `X-*-Key` family in July and stopped there, so `X-Velarion-Agent-Token` and `X-SignDocs-Client-Secret` still read as "no authentication". Widening a CRITICAL rule is not free, so it is bounded and measured: across the whole 1,641-config corpus the change silences exactly those two configs and nothing else (1,046 → 1,044 firing, 0 newly firing). A bare `client_id` is still not auth (it is a public identifier; the pair is recognised via its secret half), `X-CSRF-Token`/`X-XSRF-Token` are still not auth despite the suffix, and a hardcoded literal in a custom auth header still fires. All four boundaries are pinned in `tests/test_mcp_auth_header_family.py`, which also keeps the true positive firing so "no false positives" cannot be satisfied by disabling the rule.
- **`fetch_registry._to_config()` converted `remotes[0]` unconditionally**, so a server publishing an anonymous or login entry point first lost the auth it declares on a later remote — two of the four adjudicated false positives. It now converts the first remote that declares headers. The committed manifest predates the fix, so those two clear on the next `make corpus` refresh; regenerating 1,641 records inside a precision fix would move the number for two reasons at once, so it is deliberately not bundled.
- **The MCP Security Index cadence claim states a date instead of a frequency.** The README first said "weekly" while every scheduled run from 2026-06-15 was dying on an unhandled `HTTP 429`, then said "cadence is currently interrupted" and left it standing after the fault was fixed. The scheduled run on **2026-08-24** landed and published — the first since the v0.3.86 fix, and the verification that was outstanding — and the published history now holds enough snapshots for the trend chart to render. The interruption notice is gone, in the same commit as the verification. What replaces it is not "weekly": one scheduled success is not a cadence. `scripts/index_cadence.py` renders the last published snapshot date from the history the index site actually serves, and `--check` fails the build when that date disagrees with the live one or is more than 10 days old — one tolerated miss on a Monday schedule and no more. It runs in the link-check workflow, next to the dead-docs-domain check it is a sibling of.
- `docs/comparisons.md` advertised the leaderboard as "weekly, 500+ servers". It grades 147. That row now carries the real count and the snapshot date.
- **`make count-check` reported clean on a stale badge.** It ran only `check_counts.py`, which matches a fixed list of prose phrasings; `rules-320-blue.svg` is not one of those shapes. Verified by corrupting the badge to 999 and watching the target pass. It now runs `sync_rule_count.py --check` too, because each guard alone gives a false all-clear — the prose guard cannot see generated surfaces and the generator never looks at free prose. `docs/index.md` carried a bare "320 detection rules" and is now an anchor the generator writes. New named CI job `counts`, so a stale count fails under "Rendered counts match the registry" instead of inside a red 4-way matrix.
- Retired one more expired promise: the README said the frozen security baseline's "re-measure is scheduled for **2026-08-11**". That date passed. The comparison command was run (corpus 1,374 → 2,303 configs; `AAK-MCP-001` 482 → 1,203) and the README now states a reproducible fact instead of a date that expires.
- **`sync_repo_metadata.py` rewrote `@vX.Y.Z` inside dated artifacts on every release.** Its docstring has always stated that historical artifacts "should pin the version they documented", but that was implemented for exactly one filename pattern (`release-notes-v*.md`), so each release quietly edited `docs/launch/` collateral and dated `docs/presets/` docs — rewriting a published social thread to quote a version it never quoted. `scripts/check_counts.py` already treated those same paths as frozen, so two guards disagreed about what "frozen" meant. They agree now, and `tests/test_repo_metadata_sync.py` asserts both the predicate and that the file selector actually applies it. The already-rewritten pins cannot be recovered, so they hold at v0.3.87 and stop moving from here.
- The State of MCP Security report numbers moved as a direct consequence of the `AAK-MCP-001` fix, which is the intended kind of movement: no-auth 1205 → 1203 of 2,303 (52.3% → 52.2%), configs with a critical finding 1,217 → 1,215, grade A 632 → 634 and B 1,426 → 1,424. Two servers that authenticate with a vendor token header are no longer graded down for it. `results.json` and REPORT.md were regenerated together, and `make report-check` is clean.


## [0.3.87] - 2026-08-22

### Fixed

- **Four pieces of automation that had never worked, found by auditing what was still outstanding rather than by anything failing loudly.**
- `sync-repo-metadata.yml` had never executed once, for three independent reasons any one of which was sufficient. Its only automatic trigger is `release: published`, which cannot fire here because the release is created by `release.yml` with `GITHUB_TOKEN` and GitHub does not raise workflow triggers from `GITHUB_TOKEN` events. `gh repo edit ... || true` swallowed its own failure, so a run that did nothing would still report success. `git commit ... || true` and `git push || true` did the same. The visible consequence was that the repo description drifted on every release, the `description-liveness` gate caught it every time, and a human pasted the string by hand — while this file sat in the tree looking like that was already automated. It is now `workflow_call`, invoked directly from `release.yml`, with the `|| true`s removed and an explicit loud message when no admin token is available instead of a silent exit 0.
- `scripts/gen_owasp_coverage.py` ignored every command-line flag. `main()` parsed `[]` whenever `argv` was `None` — which is exactly the CLI case — so `--json /tmp/x` appeared in `--help`, was accepted without error, and wrote to the default path anyway. It now reads `sys.argv` when invoked as a CLI; callers wanting no arguments pass `[]` explicitly.
- Running `pytest` rewrote a tracked file. `tests/test_owasp_public_json.py` regenerated into the canonical `public/owasp-agentic-coverage.json` from an `autouse` fixture, so a plain test run left the working tree dirty — undone by hand many times across sessions. Worse, the assertions then read the file the fixture had just written, so the staleness check passed by construction and could never fail. Both generator calls in the suite now write to a temp path, and the check compares a fresh generation against the committed copy ignoring only `last_updated`. It immediately caught real staleness the old arrangement had been hiding. A full suite run now leaves the tree clean.
- `scripts/watch_csa_mcp_baseline.py` had been in the tree since v0.3.2 with a docstring saying it is "meant to run weekly via the existing cve-watcher.yml cron" — and was wired to nothing, so the poll it describes had never run. Now hosted in `cve-watcher.yml`, which already has `issues: write`. Its duplicate guard does not rely on the state cache surviving: an open-issue label check gates it, because `actions/cache` with a static key does not reliably re-save.
- `docs/cve-latency.md` was stale since 2026-08-15, so `make cve-latency-check` was red locally. Regenerated, and `make cve-latency-refresh` filled in 13 missing published dates, taking the measured population from 35 CVEs to 44.
- Four promises that expired. A remediation told users a source detector for `InMemoryVectorStore(filter=...)` was "queued for v0.3.18" and a comment said an `eval()`-in-`@tool` detector was "queued for v0.3.19"; both were scoped, never written, and shipped that text for another 68 releases. `corpus/manifest.py` said Sigstore bundle verification "queues for v0.3.9" — it is not shipped, and cannot be until `public/corpora/manifest.json` publishes a signature field for a verifier to check, which it does not. `toxic_flow.py` described itself as "behind a feature flag for v0.3.5" while still being off by default at v0.3.86. All four now state the position instead of a version number, including what is not covered as a result.

### Added

- Triaged two `cve-response` issues, both of which blocked the release gate. `AAK-MCP-OMNIGENT-CVE-2026-62674-001` (SUPPLY_CHAIN, CRITICAL) pins `omnigent >= 0.3.0` for **CVE-2026-62674**: a session editor can replace a bound shared or template agent whose `agent.session_id` is `None`, attach a stdio MCP server, and have every later session using that agent launch an attacker-chosen command. Bounded regex, because npm carries an unrelated `omnigent` published only at 2.0.0. The remediation says more than "upgrade", since the payload persists in shared state and survives one.
- **CVE-2026-53509** (CKAN MCP Server) needed no rule at all, which is the more interesting half. `AAK-MCP-CKAN-CVE-2026-73846-001` has carried a floor of 0.4.112 since 2026-08-15, above this advisory's 0.4.106 fix, so every affected version was already being reported before the CVE published. It is recorded on the existing rule's `cve_references` rather than given a second pin that would report one dependency twice, and a test asserts the floor stays above 0.4.106 so the "already covered" claim cannot quietly become false.

### Fixed

- The MCP Security Index had **two** faults, and fixing the first only exposed the second. Running the workflow rather than reasoning about it found both. The crawl was dying on `HTTP 429`, the status the GitHub Search API actually returns for a secondary rate limit, which `_api_get` never handled — so the 429 propagated raw past a retry path that already existed. And once the crawl succeeded, the site still said "not enough snapshots yet for a trend chart (need >= 2)": `index_builder.py --clean` removes its output directory *before* reading the previous `history.json`, and the workflow fetched the prior gh-pages state only *after* the build, so every run appended one entry to an empty list. Every published history in this project's life has held exactly one snapshot — 2026-04-18, then 2026-04-18, then 2026-08-21 — so the trend chart was unsatisfiable by construction, independently of the scheduled failures. The gh-pages fetch now runs before the build and feeds a new `--history` seed. **Verified end to end:** two consecutive runs on 2026-08-21 produced a two-entry history (141 then 147 servers) and the site now renders the trend chart instead of the "not enough snapshots" notice. The schedule fix is not verified — both runs were manual dispatches, so the README keeps "weekly" off the page until consecutive Monday runs actually land.
- The rate-limit fix needed a bound. Surviving 429s is unbounded in time: the back-off ladder is 240s per API call, which across 150 configs is about 10 hours against GitHub's 6-hour job timeout — and a timeout kill produces no snapshot at all, which is the original failure with extra steps. The crawl now takes a wall-clock budget (`--max-seconds`, 1500s in CI under a 45-minute job backstop) and emits what it has when the budget is spent. A crawl that produces **zero** configs is the one case that still fails the workflow, because zero is not a data point and publishing it would put a false zero into the trend chart.

## [0.3.86] - 2026-08-21

### Fixed

- **Releases were publishing on a red build, and now they cannot.** `release.yml` ran no tests at all: its `pypi` job depended on `cve-response-gate` alone, so four consecutive versions shipped to PyPI from a main branch whose CI was failing. `pypi`, `docker` and `bundle-and-sign` now all require a `test` job that runs the full suite, the linter, the type checker and the count check on the tagged commit. The brief named `pypi`; `docker` pushes to GHCR and `bundle-and-sign` attaches signed assets, so gating only the first would have closed one publishing path and left two open. It runs in-line rather than through `workflow_run` because this workflow triggers on a tag push, and a `workflow_run` gate would test whatever CI last ran on a branch rather than the tree being published.
- The red build itself. The failing test was `tests/test_version_consistency.py::test_readme_action_pin_matches_newest_git_tag`, not the changelog guard, which was already written to survive this window. On a release commit the README's Action pin is repinned to the new version and the tag does not exist yet, so the newest-tag guard fails for the minutes between push and tag. It now skips, with a reason naming both versions, when HEAD carries no tag **and** the CHANGELOG's newest dated entry is ahead of the newest tag. Both conditions are required: HEAD carrying no tag is the normal state of every ordinary commit, and the changelog being ahead on its own would let a permanently untagged bump hide forever. The assertion is unchanged for the case it was written for, and five tests hold that, including that "carries a tag" is not the same as "a tag is reachable". Also worth recording: the failure was never Python 3.12 specific. It hit 3.11 in one run and 3.11 and 3.10 in another; the matrix fail-fast simply cancels whichever legs lose the race.
- `scripts/check_counts.py` matched **phrases**, so a count written in an uncovered phrasing was never looked at. This changelog records that same blind spot being found three separate times (v0.3.72, v0.3.81, v0.3.84), each time fixed by adding one more phrase. It now also runs a corroboration sweep over every `<n> rules` and `<n> scanners` in `README.md` and `docs/**`, asking whether the number corresponds to anything real: the registry total, a category named on the same line, a generated marker, a stated threshold, or an allow-list entry with a reason. Anything else fails. It cannot be phrase-blind because it does not read phrases. The phrase sweep is kept rather than replaced, because it still covers `CLAUDE.md`, `launch/` and `research/`, which the new sweep's scope does not reach.
- Five count drifts, four from the brief and one the sweep found on its own. The README comparison row claimed **12** A2A rules against a registry 13. `docs/owasp-mapping.md` was a hand-maintained duplicate of the generated coverage tables and had rotted badly, understating every MCP slot by roughly four times (MCP01 said 14 against a live 78, MCP05 said 10 against 55) with MCP08 missing entirely; it is now a stub pointing at the generated pages, because correcting a hand-copy only restarts the clock. `scanners.json` advertised 94 against 96 non-private modules on disk with nothing in the artifact explaining the gap, and now carries a derived `unregistered_shims` list plus a `_comment`, with `check_counts.py` asserting `count + shims == files on disk` and naming the unaccounted module when it does not. The README's `# 1,100+ tests` sat at roughly 60% of the real figure and is now a generated `test-count:total` marker, counted from the AST rather than from pytest collection so it cannot vary by machine.
- Both scheduled workflows had been failing silently while the README kept making the claims they backed. **Docker nightly** was red for six consecutive nights (2026-08-16 to 08-21, not five) and the build was never the problem: the image built and pushed every night and only the Trivy SARIF upload failed, because the workflow's explicit `permissions` block omitted `security-events: write` and an explicit block replaces the defaults rather than extending them. **MCP Security Index** was worse than reported: every scheduled run since 2026-06-15 failed except one on 2026-07-20, which is exactly why the published `history.json` holds a single snapshot and the site renders "not enough snapshots yet for a trend chart". The cause was narrower than it looked, and was found by running the workflow rather than by reading the code: the GitHub Search API returns **HTTP 429** for a secondary rate limit, and `_api_get` only ever handled 403, so the 429 propagated as a raw `HTTPError` and the retry path it already had was never reached. `_api_get` now treats 403 and 429 alike, honours `Retry-After` and `X-RateLimit-Reset` before falling back to capped exponential back-off, and raises a dedicated `RateLimited` on exhaustion. `benchmarks/crawler.py` keeps a partial crawl on that signal instead of dying, recording `partial`, `partial_reason` and `requested_limit` in the artifact so a short week can never be read as a full one, and the crawl size is sized to the token budget as well. Both workflows now file or comment on a single `scheduled-failure` issue when a scheduled run fails, which is the part that actually failed here: nothing told anyone for two months.

- Triaged CVE-2026-59279 (Spring AI 2.0.0, CVSS 7.5, unbounded MCP session retention with no client auth by default) as out of scope: Spring AI publishes to Maven Central only and resolves on neither PyPI nor npm, so its version never appears in a file the pin detector opens. Third advisory on that boundary after ArcadeDB and the Splunk MCP Server app, and written out in full again rather than cross-referenced. The unauthenticated-by-default half is the posture `AAK-MCP-001` reports, which is the part of it a config scan can see.

### Changed

- README claims corrected rather than left standing. The MCP Security Index section now says plainly that the cadence is interrupted, names the dates, and says the "weekly" wording returns once consecutive Monday runs have landed. The GHCR line now distinguishes what is actually attested: SLSA provenance is attached by the release flow and covers version tags, while the nightly rebuild refreshes `:latest` and `:nightly` with no attestation, which the previous wording implied it had.
- `ROADMAP_2026.md` carries a `Historical snapshot` banner matching `DEEP_ANALYSIS.md`, with its authored date and the plain statement that its headline goal, 1,000+ stars and OWASP reference-implementation status within 90 days, was not met: four months on the repo has 13 stars. Kept rather than deleted, because a roadmap quietly removed once it stops flattering is worse than one labelled honestly.
- `docs/comparison.md` and `docs/comparison-gitlab-agentic-sast.md` are consolidated into `docs/comparisons.md` and reduced to stubs. Three comparison pages coexisted while the README linked only one, so the two nobody linked drifted unread. `mkdocs.yml` navigated to a retired page and `sync_rule_count.py` wrote its anchors into both, so both were repointed; a new test asserts in both directions that every doc carrying a rule-count anchor is driven by the script and every driven doc has one.
- Two tests stopped restating what they check. `tests/test_scanner_manifest.py` rebuilt the manifest JSON inline instead of calling the renderer and disagreed the moment the schema gained a key, and `tests/test_rule_count_sync.py` mirrored the script's doc list by hand and broke when two pages were consolidated. Both now derive from the source they are checking.

## [0.3.85] - 2026-08-21

### Added

- Rules for the statically decidable part of the **OWASP Agentic Skills Top 10** (AST10), the OWASP incubator project covering the skill layer rather than the protocol layer. The ten categories were read from that project's own `ast01.md` through `ast10.md`, and three of them turned out to be covered already: `AAK-SKILL-001` through `AAK-SKILL-005` and `AAK-POISON-001` through `AAK-POISON-006` are AST01 and the semantic half of AST04, and `AAK-COMPOSE-003`, which landed last week, is AST03's declared-versus-actual capability mismatch. Re-implementing those would have reported one defect twice, so `agent_audit_kit/scanners/agentic_skills.py` ships the three that were genuinely uncovered. `AAK-AST02-001` (HIGH) reports a skill bundle pulling an external resource that nothing pins: a moving git ref, a `releases/latest` redirect, a pipe-to-shell installer, an unpinned package install. That is AST02 plus the pinning half of AST07, and the scale is why it is a rule rather than a lint, since the research AST02 cites found 17,822 of 142,836 live skills resting on at least one untrusted external resource and 925 sitting on sources that could be taken over outright. `AAK-AST04-001` (CRITICAL) reports a deserialization tag in skill frontmatter, which constructs a language object while parsing, before any field of the skill is read and before it is ever invoked; that is AST04's parsing layer, distinct from `AAK-SKILL-005`, which reads frontmatter values and assumes parsing already happened safely. `AAK-AST10-001` (MEDIUM) reports a bundle whose platform manifests disagree about security metadata, which is a cross-artifact question in the same way the composition rules are: each manifest is internally consistent and the defect exists only between them.
- Three rules rather than ten, and the README says which seven are not covered and why, in the same shape as the OWASP Agentic and MCP tables. AST06 Weak Isolation is a property of the runtime that loads the skill, not of anything in the bundle. AST08 Poor Scanning is about the registry's process rather than the skill. AST09 No Governance is organisational. AST07 is covered only in its pinning half, because detecting that a deployed skill has drifted needs the deployed copy and a baseline that a repository scan does not have. Those are not a backlog; a rule claiming them would be reporting a guess. Every rule in the family carries a `limitations` field, including one interaction worth stating: frontmatter carrying a deserialization tag is rejected by safe parsing and therefore drops out of the AST10 comparison entirely, which without the note would look like a gap rather than the two rules dividing the work.
- `Category` gained `AGENTIC_SKILL`, extended rather than bypassed. `RuleDefinition` and `Finding` gained `owasp_ast_references`, defaulting empty so all 316 pre-existing rule definitions are byte-identical, and `SCHEMA_VERSION` moves 2 to 3, which the schema comment already describes as the path for a new reference field. `OWASP_AST` joins `OWASP_AGENTIC` and `OWASP_MCP` in `output/owasp_report.py`, with titles taken verbatim from the OWASP repository.
- Triaged seven `cve-response` issues in one pass (#621 through #627): the two the day started with and five the watcher filed while they were being worked. Severity decided none of them. The CRITICAL went out of scope and lower-scored advisories shipped rules; what decided each case was whether the vulnerable artifact and the pinnable name are the same project. `AAK-MCP-MARIMO-CVE-2026-75149-001` (HIGH) pins `marimo >= 0.23.15`, where a notebook embeds an MCP server entry whose `command` marimo launches on open, before any cell runs. That is this project's own stdio-launcher shape arriving through a `.py` notebook that no config scanner opens, which is why it needed a pin rather than a pattern rule. `AAK-MCP-N8N-CVE-2026-72768-001` moved 2.32.1 to 2.34.1 and MEDIUM to HIGH for CVE-2026-77068 and CVE-2026-77073, rather than becoming a fifth n8n pin that would report one dependency five times.
- Two presence-only pins, both because there is genuinely nothing to pin to, and in both cases that was checked rather than assumed. `AAK-MCP-NEOMJS-CVE-2026-18482-001` (HIGH): the advisory names a fix commit dated 2026-08-11 and no fix version, and npm's own publish timeline shows no `neo.mjs` release after 2026-07-03, so the fix has never shipped and every published version is affected. It is marked a placeholder rather than a permanent state, unlike `mcp-florence2`, because upstream wrote the fix and simply has not released it. `AAK-MCP-LANGBOT-CVE-2026-54449-001` (HIGH): the GHSA records `patched: null`, NVD states no fix is available, and 4.10.8, published 31 minutes after the advisory, is a media-delivery patch whose notes claim no security fix. Its remediation names the authorization control, since telling anyone to upgrade would be advice that does nothing.

### Fixed

- The fix-recipe coverage number was a liability as written. "11 of 319 rules (3.4%)" read bare invites exactly one reading: that the scanner says what is wrong 319 times and how to fix it 11 times. That reading is false. Every one of the 319 rules carries remediation prose, median 182 characters and none empty, so guidance has no gap at all and the percentage is about *automated application*. The README now states "all 319 of 319 rules" for guidance directly above the recipe count, rendered from the same marker so the two cannot disagree, and says the scope that produces the smaller number: a recipe ships only where the remediation is deterministic and one-line, exactly one correct edit confirmable from the diff. The alternative offered, writing recipes for the top 20 corpus rules, was rejected on evidence already in the tree: `NON_MECHANICAL` records why each of those shapes needs judgement, and raising the number by lowering the bar would make it less truthful rather than more. Three tests hold the claim, including that remediation text is substantive rather than a placeholder, since non-empty is not the same as useful.

### Changed

- Counts move to 319 rules, 94 scanners and 14 categories.

## [0.3.84] - 2026-08-19

### Added

- Rules that hold over a graph of components instead of one artifact. Every rule in the registry answered a question about a single file, with one exception: `AAK-AGENT-COMPOSE-001` unions the declared capabilities of the `SKILL.md` files in one container and asks whether the set spans a boundary no member spans. That is unordered by construction. It has no notion of direction, of one component's output being another's input, of hop count, or of anything that is not a skill, and the two results it cites describe an ordered chain. `agent_audit_kit/scanners/composition.py` adds the graph over skills **and** MCP servers, reusing `skill_composition._extract_skill`, `mcp_config._find_mcp_configs` and `secret_exposure.MCP_ENV_SECRET_KEYS` rather than parsing any config format a second time. `AAK-COMPOSE-001` (HIGH) reports an ordered 2- or 3-component path carrying untrusted input to network egress through something that reads secrets or local state, while no single component holds all three roles, which is CompoSkill (arXiv:2608.16246); the three-component cap is that paper's own result, since attack success falls off past three skills and the search cost is the node count raised to the depth. `AAK-COMPOSE-002` (HIGH) reports two or more skills sharing a writable path none of them declares, which is ColluSkill (arXiv:2608.09732) and is invisible to a capability union by construction, because the relevant capability is the one nobody declared. `AAK-COMPOSE-003` (MEDIUM) reports a skill whose body or adjacent scripts exercise a wider capability than its manifest declares, which is what makes the first two conservative: a graph built from manifests understates the real graph exactly as far as manifests understate their components. Each rule carries a `limitations` field stating that it is static, cannot resolve runtime tool registration, and will miss a chain assembled from a registry fetched at start-up.
- Not double-reporting, which is the property that decides whether a composition pass is worth having at all. It cannot be answered inside a scanner: the contract hands over a project root and nothing about what other scanners found, and re-deriving each rule's predicate inside the composition scanner would be a second copy of the registry, which is the failure already fixed once for remediation keys. `engine.py` therefore stands a composition finding down when any component on its path already carries a finding at or above the composition finding's own severity. Severity rather than presence, and the difference is the whole design: `AAK-MCP-ATTEST-001` (MEDIUM) fires on virtually every MCP config, so suppressing on "any finding at all" would have made every MCP-server chain permanently unreportable while the guard still looked correct. Component identity differs by kind for the same reason, and both directions were wrong before they were right. Keying an MCP server on its file lets one unrelated finding in a shared `.mcp.json` stand down every chain through it; keying it on one exact line misses `AAK-MCP-001`, which reports on the `url` line rather than the line naming the server. A skill is keyed on its file, since a `SKILL.md` is one artifact; a server claims its whole block.
- Measured behaviour on the 748 public MCP configs in `benchmarks/data`: 2 chains in 2 configs (0.27%) from the scanner, 0 after suppression. The first draft treated any remote server as a source of untrusted input, which reported 253 chains across 33.8% of the corpus, because under that reading every tool returns content into the context and the role means nothing. Requiring the source to actually look like untrusted content, a browser or a mail or issue reader, is what took it to 0.27%, so the predicate is precise on its own rather than relying on suppression for its precision. The two it does find are `browsermcp` to `filesystem` to `cloudflare-*`, and `slack` to `notion`. Both go quiet after suppression because a component on each already carries a HIGH or CRITICAL finding, and the corpus is configs with no skills, so the cross-kind case these rules exist for is unrepresented in it. `tests/test_composition.py` holds the 5% line against a future loosening.
- Six fixtures under `tests/fixtures/composition/`, one of which is the point: a chain whose component already fires `AAK-MCP-001` must be reported once by that rule and not again by `AAK-COMPOSE-001`. The 4-component fixture that the cap must reject has a companion test that raises the cap and asserts the finding appears, because a silently malformed fixture and a working cap look identical otherwise.
- **Where the auto-fix work stopped, continued.** Issue #607 targets roughly 30% auto-fixable and coverage is 11 of 313 rules (3.5%, down from 3.6% only because the denominator grew by three). `AAK-OAUTH-008` was the candidate: at 36 findings it is the largest single block without a recipe. It is also the one where a recipe would be actively harmful, and this is demonstrated rather than asserted. The detector clears when the file mentions `authorization_servers` or `oauth-protected-resource`, so the cheapest edit a recipe could make writes that key into an MCP client config, the finding disappears, and the hardcoded bearer token sits untouched beside it. That is the v0.3.78 defect exactly: the user edits their config, the warning goes away, and they believe they are protected by something nothing reads. A real fix serves metadata at `/.well-known/oauth-protected-resource` on the resource server, names an authorization server AAK has no way to know, and moves the client onto a 401 `WWW-Authenticate` challenge. None of that is in the file the finding points at, because the artifact that must change is the server and the artifact AAK would edit is the client. Recorded in `NON_MECHANICAL` with its reason, and `test_a_bare_prm_keyword_silences_oauth_008_without_fixing_anything` demonstrates the failure mode so the next person to propose a recipe meets the evidence rather than the argument. #607 is updated with the number and the reasoning so it stops reading as an unmet target the project has in fact decided against.
- Triaged the six `cve-response` issues from the 2026-08-18 watcher wave (#613 to #618). Packaging decided all six, and only one new rule was needed. `AAK-MCP-CODEWHALE-CVE-2026-75858-001` (SUPPLY_CHAIN, HIGH) pins `codewhale` >= 0.8.64 for **CVE-2026-75858** and **CVE-2026-75857**, whose `rlm_eval` and `exec_shell_interact` tools both return `ApprovalRequirement::Auto` and so skip the user's configured `--approval-policy` entirely. One rule for both, the CKAN precedent, since they share a package and a fix version and two rules would report one dependency twice. A second pin on the same rule covers `deepseek-tui`, the pre-rename name both advisories carry, whose remediation says migrate rather than upgrade because its line ends at the rename. The crates.io twin `codewhale-tui` has the identical defect and is deliberately not pinned: Cargo manifests are not in the detector's candidate set, so a finding there would be a claim the scanner cannot support. **CVE-2026-50143** moved the existing `AAK-MCP-APIFY-CVE-2026-46341-001` floor from 0.9.21 to 0.10.11 and raised it MEDIUM to HIGH, the stata-mcp precedent, since the higher floor already covers the lower one.
- Three out-of-scope dispositions, written out separately because they are three different facts rather than one precedent applied three times. **CVE-2026-75845** (ArcadeDB) does name a pinnable artifact, but a Maven one, and `_CANDIDATE_NAMES` holds no `pom.xml` or `build.gradle`, so a pin would be inert rather than wrong. **CVE-2026-34884** (Apache SkyWalking MCP) is Go, released as a source tarball and a container image, and `go.mod` is not in the candidate set either. **CVE-2026-75130** (Context7, CVSS 9, the batch's most severe) has no client version boundary at all: Custom AI Instructions are authored and stored in the hosted service and the npm client only fetches them, which is consistent with NVD carrying no CPE range and no vendor patch reference, VulnCheck naming no fixed version, `upstash/context7` publishing no advisory, and releases continuing from 2.1.3 to 4.0.2 under none. So it is neither a floor pin, because no boundary exists, nor a presence-only pin, which would fire on every Context7 user for a defect in a component they do not run. All three are covered for exposure by `AAK-MCP-001`, and `tests/test_cve_triage_2026_08_19.py` holds every disposition, that no pin is keyed on a bare product name, that no ledger row implies AAK can see a version it cannot, and that the three reasons stay distinct.

### Fixed

- The category count was unguarded, and had already drifted in three directions. `scripts/check_counts.py` matches counts by phrase, so a phrasing absent from `PATTERNS` is never looked at and rots while `make count-check` reports clean. This is the third instance of that blind spot after `N existing rules` in v0.3.72 and `N registered scanners` in v0.3.81, and by the time a pattern existed the tree simultaneously claimed 10, 11 and 12 categories. The new pattern is anchored on the headline `rules ... across N categories` form rather than a bare `N categories`, because the broad version matches "AAK covers 10/10 categories" in the OWASP coverage pages, where that 10 is the size of the OWASP taxonomy and not of AAK's category list. A guard that had been allowed to "fix" those would have turned three true statements into false ones, so `test_category_pattern_does_not_match_the_owasp_taxonomy_size` holds the distinction. Counts now move to 313 rules, 93 scanners and 13 categories.
- Two coverage claims that were wrong before this release and were found while wiring that guard. `examples/README.md` said its 11 vulnerable configurations covered "all 11 security categories"; scanning them shows they cover 10, and the registry now has 13. The `damn-vulnerable-mcp` case study said AAK detects across "9 of 11 security categories" while the table directly beneath it lists 7 rows. Both now state their measured values.

## [0.3.83] - 2026-08-18

### Fixed

- A git tag could ship without its changelog entry, and nothing checked. v0.3.82 was tagged, published to PyPI on 2026-08-17, and its notes stayed under `[Unreleased]`, so the public record said "unreleased" for a version anyone could already install. The release flow compares the pyproject version against `__init__`, the README pins and the newest tag, but never against `CHANGELOG.md`. This is the 0.3.81 rule-count failure one level up: that guard matches counts by phrase, so a count written in an uncovered phrasing was never looked at and rotted while `make count-check` reported clean. Here the uncovered surface was a whole document. `tests/test_changelog_tags_agree.py` now holds tag to dated heading for every semver tag, reading tags with `git tag --list 'v*'` so it needs no network. It also holds that version headings carry a date rather than just a version, that `[Unreleased]` exists and sits above the newest release, and that its own exemption list stays honest in both directions. Checking the tags surfaced more than 0.3.82: 41 of 61 semver tags had no dated heading in `CHANGELOG.md`, 30 of them recorded in `docs/changelog/archive`, which the guard also reads. The remaining 11 predate the guard, are listed in `KNOWN_UNRECORDED` so it fails closed on anything new, and are deliberately not backfilled, because those notes were never written and inventing them now would put unsourced content in the audit trail. v0.3.82 was not exempted: it failed, its three entries moved into a dated `## [0.3.82] - 2026-08-17` section, and it passes.

### Added

- Triaged the 2026-08-17 CVE pair. Both are out of scope, and neither needed a new rule. **CVE-2026-71424** (Onyx, CVSS 3.1 9.6) leaks one user's OAuth Authorization header to another through a shared admin `MCPConnectionConfig` row. It names fix versions, which normally means a pin, but the Onyx AI platform publishes no PyPI or npm distribution: `onyx` on PyPI is an unrelated trading framework and `onyx` on npm is a static file server, and neither shares the 3.1.x, 3.2.x or 4.0 version lines the advisory names, which is what confirms they are different projects. A pin keyed on that name would fire on two innocent packages and never once on the vulnerable platform, the same collision the `@adenot/mcp-google-search` pin comment already documents. **CVE-2026-75060** (JetBrains PyCharm, CVSS 3.1 8.4, code execution via unauthenticated Jupyter MCP tools) is the settled desktop-app shape, the basis used for SiYuan CVE-2026-66012 (#499), ArcadeDB CVE-2026-68578 (#528) and SiYuan CVE-2026-74798 in 0.3.81: an IDE installed from vendor builds has no version a static config scan can see. Both are covered for exposure by `AAK-MCP-001`, since each advisory's precondition is a reachable MCP surface without authentication. `tests/test_cve_triage_2026_08_18.py` pins both dispositions, including that no pin is ever keyed on the bare names `onyx` or `pycharm`, and that neither ledger row implies AAK can detect the version.
- The State of MCP Security 2026 report is now cited from outside itself. It reached v1.0 with a methods block, a published date and a `CITATION.cff` pointing `preferred-citation` at it, and nothing linked to it. `README.md` gains a "cite" badge next to the existing badges, pointing at the report's citation section, and a three line block of its headline numbers in the opening section: 2,303 distinct public MCP configs scanned, 0 serving RFC 9728 discovery, 52.3% (1,205) declaring a remote server with no authentication, and 100% (421 of 421) of inline-auth remote configs hardcoding a static credential. Quoting a number creates a second copy of it, which is how a rule count drifts, so each figure is wrapped in the same HTML comment markers `scripts/sync_rule_count.py` already uses for the rule and scanner counts, and that script now owns them. They are rendered from `research/state-of-mcp-2026/results.json`, which `make report` regenerates deterministically and `make report-check` already guards. `tests/test_report_headline_numbers.py` asserts the README figures against that data and also asserts the report's own prose against it, so the document being cited cannot disagree with the README quoting it. Comparison is on parsed numbers, so the README writing `1,205` and the report writing `1205` is not a failure.

## [0.3.82] - 2026-08-17

### Fixed

- The JSON report's own numbers disagreed and nothing in the document said why. `summary.total` and the severity histogram counted every finding; `findings` held only what cleared `min_severity`, which defaults to LOW. Scanning the 748-config corpus therefore emitted `"total": 370`, `"info": 1`, and 369 entries — so anything counting the array silently disagreed with the summary by one, and a histogram claiming an INFO finding sat beside an array containing none. The filtering is deliberate; the silence was not. `summary` now also carries `reported` (always equal to `len(findings)`) and `minSeverity` (the threshold actually applied), so the gap is self-explaining. No existing field changed meaning, so consumers reading `total` are unaffected. `tests/test_json_report_counts.py` holds the invariant in both directions, including that `total - reported` always equals exactly the count below the threshold — if that stops holding, the two numbers differ for some other reason and `minSeverity` no longer explains the document.
- `AAK-MCP-CLINE-CVE-2026-59723-001` fired on ordinary English. `_mk_re` anchors on neither side, so the unbounded pattern matched the substring in "declined", "declines", "inclined" and "recline": any prose file containing one reported a CVE pin for a package the project does not depend on. Found while writing fixtures for the mcp-florence2 pin, whose comment used the word "declined". Now uses a bounded `_CLINE_RE`, the same shape the `letta` and `n8n` pins already carried for this exact class of collision — and it also stops matching the distinct `cline-utils` package. Every true positive is preserved (pip pin below floor, npm caret, unpinned MCP config, quiet at the fix floor), and a test asserts the pin carries an explicit regex so a future edit cannot silently revert to the substring match.
- `vscode-extension/CLAUDE.md` described `src/sarifReader.ts` as if it ran. It does not: `extension.ts` imports only `vscode`, `child_process` and `path`, never calls `registerSarifCommands`, and `package.json` declares no `contributes.commands`, so the module is unreachable from code and from the UI. The subtree memory now says so explicitly, along with what wiring it up would actually require, rather than documenting a workflow that does not exist. Also corrected: the architecture tree omitted `sarifReader.ts`, `README.md` and `.vscodeignore`, and the `npm run lint` script needs an `eslint` that is not in `devDependencies`.

## [0.3.81] - 2026-08-17

### Added

- Triaged the 2026-08-17 CVE pair: one pin, one repeat of a settled disposition. `AAK-MCP-FLORENCE2-CVE-2026-19984-001` (SUPPLY_CHAIN, MEDIUM) covers `mcp-florence2` <= 0.3.13, whose `get_images` fetches the caller-supplied `src` with no host or scheme validation (CVE-2026-19984, CVSS 3.1 6.3, public exploit). It is presence-only for a reason the other no-fix pins do not share: upstream has ruled out a source change and states the mitigation is an SSRF-safe egress proxy "without requiring changes to the mcp-florence2 source code". There is therefore no fix floor to wait for, a newer release must still fire, and the remediation names egress control instead of an upgrade — telling users to upgrade would be exactly the do-nothing advice the remediation-key guard in this release exists to stop. Two tests hold that shape. **CVE-2026-74798** (SiYuan kernel < v3.7.4, CVSS 8.7, path traversal in the `database_clean` MCP tool) is **out of scope** on the basis already settled for SiYuan CVE-2026-66012 (#499) and reused for ArcadeDB CVE-2026-68578 (#528): a desktop app referenced by URL is not a pinnable artifact, so a static config scan cannot see its kernel version. The reachable posture is flagged by `AAK-MCP-001`. Both dispositions are recorded in `CHANGELOG.cves.md`.

### Fixed

- Remediation advice could name a config key nothing reads, and nothing checked. v0.3.78 corrected two rules by hand — both told users to set `"deny_stdio_transport": true` / `"allowed_transports": ["sse"]`, keys that appear in 0 of the 748 public configs in `benchmarks/data` — but the fix was rule-specific, so the next invented key would have shipped the same way. That failure mode is worse than silence: the user edits their config, the finding goes away, and they are left believing they are protected by a key their MCP client ignores. `tests/test_remediation_keys_are_real.py` now asserts every config key any remediation names is either attested in `remediation-key-corpus.json` — 1,452 distinct keys harvested from all 748 corpus configs, plus 17 specification field names each carrying its citation — or listed in `AAK_OWN_CONVENTIONS` with a one-line reason. The allow-list enumerates **exemptions, not obligations**, so a new rule with a new invented key fails closed, and a companion test proves each exemption is genuinely read by a scanner, so the allow-list cannot become where bad advice goes to survive. Running it found two more: `AAK-AGENT-SHARED-RES-AUTHZ-001` and `AAK-MCP-SANDBOX-SELFDISABLE-001` both name `x-aak-*` annotations. Those are legitimate — their stated purpose is to record a decision *for AAK* and suppress a finding, not to configure a client — so they are exempted rather than rewritten. The transport-flip keys are deliberately **not** exempted: recommending those is the defect. The corpus is committed and regenerated by `scripts/gen_remediation_key_corpus.py`, offline and deterministic with no timestamp, so the staleness check is byte-stable. Fixing the BOM-prefixed config the old harvest silently skipped took corpus coverage from 747/748 to 748/748.
- Three of the nine `AUTO_PR_ALLOWLIST` entries were dead, so `suggest --auto-pr` advertised rules it could never act on. `plan_auto_pr` sources candidates from `run_fixes` → `_apply_fix`, which returned `None` for `AAK-FLOWISE-001` and `AAK-NEO4J-001` (no recipe existed at all) and for `AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001` (the codemod existed in `autofix/langgraph_toolnode.py` but only `suggest --apply-trivial` could reach it). All three now dispatch: the two CVE pins share a `_fix_dependency_floor` helper that rewrites `requirements*.txt` and `package.json` dependency maps — same posture as the existing langchain bump, refusing lockfiles and poetry's `pyproject.toml` whose locking semantics make a naive text bump unsafe — and the ToolNode codemod is wired into `run_fixes`. `tests/test_fix_recipe_coverage.py` now asserts `auto_fixable` implies a recipe that actually runs and that every allow-list entry is reachable, so the flag cannot advertise a fix that does nothing again.
- The `registered scanners` count in `CLAUDE.md` had drifted while `make count-check` reported clean. The guard matches counts by *phrase*, and `scripts/check_counts.py` had no pattern for that wording, so the number was never looked at — the same way `"N existing rules"` rotted to 289 after the v0.3.72 sweep. Added the pattern (narrowly, requiring the `registered` qualifier so README's per-language `2 scanners` stays out of scope) and documented in the module that the guard is phrase-based, because that property is what makes a clean run misleading.

### Added

- Fix-recipe coverage is now a published number, computed from the registry rather than asserted. Issue #607 reports 10 of 308 rules carrying a recipe against a ~30% auto-PR target; that 10 counted the `auto_fixable` flag, which overstated it, because three flagged rules had no reachable recipe. The README carries `<!-- fix-recipe-coverage:count -->` / `:pct` markers driven by `scripts/sync_rule_count.py` and verified by `test_fix_recipe_coverage_is_canonical`, in the same style as the rule-count anchors, so it regenerates instead of rotting. The number is pinned as a ratio of the whole registry so coverage can never be made to look better by shrinking the denominator.
- `AAK-SECRET-007` gained a fix recipe, the first added from measured frequency: it is the most common finding across `benchmarks/data` at 170 of 369. The substitution is the exact inverse of the detection predicate — it imports the scanner's own `MCP_ENV_SECRET_KEYS` rather than restating it — so the rule stops firing because the literal is genuinely gone, which is the opposite shape to the v0.3.78 defect. The `${VAR}` form is attested rather than invented: 158 env values across the 748 corpus configs already use it, overwhelmingly as `KEY = ${KEY}`. Deliberately excluded from `AUTO_PR_ALLOWLIST`, because the server will not start until the operator exports the variable and whether that is a fix or an outage is a deployment fact AAK cannot see — the same reason the bind-address swap sits in `NON_MECHANICAL`.
- **Where the auto-fix work stopped, and why.** Coverage moved from 10 to 11 rules (3.6%), not toward 30%. Of the 15 rules that fire across the corpus, only `AAK-SECRET-007` clears this project's own mechanical bar — "exactly one correct form, confirmable from the diff". The next four by frequency each fail it for a specific reason, not for lack of effort: `AAK-MCP-STDIO-LAUNCHER-INJECT-001` (98 findings) is the shell-string-to-argv rewrite already listed in `NON_MECHANICAL`; `AAK-OAUTH-008` (36) needs a metadata endpoint stood up and an authorization server named, which is infrastructure, not a config edit; `AAK-TRANSPORT-003` (34) would flip a declared transport whose replacement the server may not speak; and `AAK-TRANSPORT-001` (5) would rewrite `http` to `https` for an endpoint that may not serve TLS on that host and port. The last two are mechanical to *write* and unsafe to *apply* — exactly the bind-address case. Reaching 30% from here would mean shipping recipes that need judgement, so the number is reported as it is.
- The State of MCP Security report has a citable identity. It carried the strongest evidence in the project — 2,303 distinct public MCP configs, 0 serving RFC 9728 discovery, 52.3% (1,205) declaring a remote server with no authentication, 100% (421/421) of inline-auth remote configs hardcoding a static credential — and no stable identifier, so none of it could be referenced. `REPORT.md` is now **version 1.0** with a published date, a one-paragraph methods block naming the corpus size, the 2026-07-26 collection date and the `make report` command that reproduces it, and a "How to cite this report" section with plain-text and BibTeX forms. `CITATION.cff` at the repo root points `preferred-citation` at the report rather than the software, since the report is what carries the measurements, and repeats the same version and corpus size so the two identities cannot disagree. Cross-linked from the README and from the NSA-CSI / OWASP-Agentic crosswalk — the crosswalk says what the controls are, the report says how often they are met — with the link added to `output/crosswalk.py` as well, so a regeneration of that page keeps it.

## [0.3.80] - 2026-08-16

### Added

- Added detection for MCP servers that ship an unauthenticated sidecar dashboard, which was three of the seven advisories published this week. Also tightened the shell-interpolation rule, because double quotes do not stop command substitution and two CVEs this week relied on exactly that.
- `AAK-MCP-SIDECAR-NOAUTH-001` (MCP_CONFIG, HIGH) — a process that registers MCP tools also binds an HTTP listener whose routes carry no auth dependency or middleware. Distinct from `AAK-MCP-HTTP-NOAUTH-SERVER-001`, which requires a non-loopback bind or wildcard CORS: this is the *second* listener, on loopback, that the threat model forgot. AAK already carried four package-specific pins of this exact shape (Serena CVE-2026-49471, Cline CVE-2026-59723, claude-code-templates CVE-2026-73222, Penpot CVE-2026-45805) — this detects the pattern, so the next one does not need a pin. Anchors: CVE-2026-55156 / GHSA-76pc-mqxp-3rq5 (`@ooples/token-optimizer-mcp` < 5.1.0) and GHSA-rm43-82j9-r4mj (`atomic-agents-stack` <= 1.0.0).
- `AAK-MCP-SIDECAR-REBIND-001` (TRANSPORT_SECURITY, HIGH) — a loopback bind used as the access control with no Host-header allow-list, which is the DNS-rebinding precondition. Suppressed by request-borne credentials (bearer, API key), which a rebinding attacker cannot supply; **not** suppressed by cookie or session auth, which the browser attaches on the attacker's behalf. Stands down on the MCP SDK's own StreamableHTTP transport, which `AAK-DNS-REBIND-001` owns.
- `AAK-SHELL-QUOTED-INTERP-001` (TAINT_ANALYSIS, HIGH) — a tool argument reaching a shell sink through an interpolated command string, including through a local variable and including when the site is quoted. `AAK-TAINT-001` only matched a bare parameter handed straight to the sink, so it saw neither August CVE: both build a string first, and both quote it. Covers the argv-behind-an-eval-flag form too, since a list stops shell metacharacters but not injection into an interpreter you invoked yourself. Anchors: CVE-2026-55157 (CVSS 3.1 8.4) and CVE-2026-55071 (CVSS 3.1 8.4).
- `AAK-SHELL-DEFAULT-PROFILE-001` (MCP_CONFIG, HIGH) — a command-executing tool exposed in the default profile with no opt-in flag, env gate, or profile membership. This is what the `PR:N` in both CVSS vectors records, and what moved both advisories from "reachable if you enabled the risky profile" to "reachable out of the box". Fires only for tools that already reach a command sink.
- `agent-audit-kit suggest --auto-pr` applies allow-listed mechanical fixes on a new branch and opens a **draft** PR. Off by default; refuses if any pending fix is for a rule outside `AUTO_PR_ALLOWLIST`, or if the working tree is dirty. Delivery runs through the `gh` CLI under the operator's own auth, so AAK never asks for, stores, or reads a token. Closes #68.

### Fixed

- `AAK-SSRF-TOCTOU-001` recognised SSRF guards from a closed list of seven names borrowed from langchain-openai, so it missed CVE-2026-53708 (`mcp-contextforge-gateway` < 1.0.3, GHSA-9hgc-g3w5-67cm) — the same resolve-then-connect defect, reached through a guard named `validate_gateway_test_url` after the endpoint it protects rather than after the check it performs. Guard recognition is now two-track: the name reads like a URL/host check, or the body in that file both resolves a name and range-checks the result. No new findings on the existing corpus.
- `AAK-MCP-STATA-CVE-2026-47708-001` pinned `mcp-for-stata`, which is a 404 on PyPI — the GHSA title is the project name and the distribution is `stata-mcp`, so the rule had not matched a real manifest since it landed. Name corrected and the floor moved 1.17.3 → 1.19.0 for CVE-2026-55071, which 1.18.x otherwise cleared while still being vulnerable.

## [0.3.79] - 2026-08-15

### Fixed

- `docs/cve-latency.md` now reports response and backlog as separate populations. Pinning four old Letta CVEs in one sitting moved the mixed p90 from 2 days to 122 while the actual response time to fresh disclosures had not changed — the headline described neither population. The summary now covers only rows shipped within 30 days of publication (median 1.0d, p90 2d over 35), with the 5 deferred roadmap rows disclosed separately with their own range.

### Added

- `AAK-MCP-LETTA-CVE-2025-51482-001` (SUPPLY_CHAIN, HIGH) — Letta (formerly MemGPT) carried four disclosed CVEs across its 0.4–0.16 line that AAK covered none of, including remote code execution through `/v1/tools/run` (CVE-2025-51482) and an incomplete-fix follow-up (CVE-2026-4965). Floor `letta >= 0.16.5` — an inference from release ordering, since no vendor fix is named in any of the four and all four GHSA records are unreviewed. Closes the pin arm of #161; the transport-flip arm stays blocked with no CVE assigned.
- `agent-audit-kit suggest --apply-trivial` now applies fixes instead of printing that it is unimplemented. The flag shipped in v0.3.8 saying "scaffolded but not yet implemented (queued for v0.3.9)" and was still saying it at v0.3.78 — seventy releases later — while `agent-audit-kit fix` had been applying exactly these fixes the whole time. It now delegates to the same `run_fixes` engine, so there is one fixer with two entry points. Adds `--project` (where to apply; the SARIF argument says what was found) and `--dry-run`.

## [0.3.78] - 2026-08-15

### Fixed

- The CVE watcher no longer files CVEs from outside the ecosystem it tracks. NVD's `keywordSearch` matches indexed fields rather than only the description, and two of the watcher's keywords are short enough to hit unrelated CVEs: `mcp` (NVIDIA nForce parts are literally "MCP", so kernel CVEs match) and `claude` (increasingly appears in commit messages crediting the model for writing a patch). CVE-2026-68456 arrived via both at once — a `ueagle-atm` USB driver race whose description contains "mcp" zero times and ends "(The latter two were written by Claude...)". Every filed CVE opens a `cve-response` issue and the release gate blocks any tag while one is open, so an unrelated kernel CVE stopped a publish. Results are now corroborated against the description before filing.

### Changed

- `AAK-MCP-STDIO-CMD-INJ-002` now decides by data flow instead of proximity (#22). It previously fired when a network-controlled marker appeared anywhere in the 1024 characters before a `new StdioClientTransport({...})`, which both over-fires (an unrelated source that happens to sit nearby) and under-fires (a real source reaching the sink from beyond the window). A tree-sitter pass now traces the `command`/`args` value back to its source through assignment, destructuring, template literals and single-hop helper returns. **What the rule reports is unchanged** — same rule_id, severity and framework mappings; only the decision moved. `tree-sitter` and `tree-sitter-typescript` are a new **optional** extra (`pip install "agent-audit-kit[taint]"`), lazy-imported, with the proximity heuristic retained as the fallback when the grammar is absent — so the default install stays dependency-light and fully offline.

### Fixed

- Corrected the remediation on `AAK-DOCSGPT-MCP-STDIO-MITM-001` and `AAK-GPTRESEARCHER-MCP-STDIO-MITM-001`. Both told users to set `"deny_stdio_transport": true` or `"allowed_transports": ["sse"]` "so a MITM cannot flip the transport mid-session". Those keys are AgentAuditKit conventions, not MCP specification fields — they appear in **0 of the 748** public MCP configs in `benchmarks/data`, and searching the repo finds them only in AAK's own `rules.json`, tests and fixtures. Following that advice added a key the user's MCP client ignores, silenced the rule, and left them believing they were protected. The remediation now leads with the controls that work (the vendor version pin; TLS with certificate verification so the handshake cannot be rewritten) and states plainly what those keys are. Found while running the empirical false-positive study #162 asks for.

### Fixed

- `ssrf_patterns` (AAK-SSRF-001..005) now requires reachability instead of deciding file-wide. It previously reported CRITICAL when the word `fetch` appeared anywhere in a file and a user-input marker appeared anywhere else — neither had to be code, related, or nearby — so a match inside a comment, a rule title or a regex literal counted. Against AAK's own source that produced three findings, all prose, including one where the SSRF scanner flagged **its own detection pattern**. Each rule now hangs off a real outbound call site whose URL argument is traced: Python via `ast`, TS/JS via comment-stripped def-use. String literals are deliberately kept, since a genuine metadata URL lives in one. Measured across `agent_audit_kit/`, `tests/fixtures`, `benchmarks/data`, `examples` and `vscode-extension`: **3 false positives removed, all 4 true positives preserved**. Closes #593.

## [0.3.77] - 2026-08-15

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
