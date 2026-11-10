# AAK-KNOWN-VULN-001

**A locked, pinned or installed release is affected by a published advisory**

| Field | Value |
|---|---|
| Severity | The advisory's: CRITICAL from CVSS 9.0, HIGH from 7.0, MEDIUM below that; INFO for a range |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.29 |
| Scanner | `agent_audit_kit/scanners/known_vulns.py` |
| Feed | `agent_audit_kit/advisory_feed.py`, NVD's CNA records through `agent_audit_kit/nvd_feed.py` |
| OWASP MCP | MCP04:2025 (Software Supply Chain Attacks & Dependency Tampering) |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities) |

## Why it exists

On 26 and 27 Oct 2026 advisories were published against vLLM (below 0.32.0),
MLflow (3.12.0rc0 up to 3.17.0), the OpenHands Software Agent SDK (below 1.52.0)
and NVIDIA's NeMo Agent Toolkit. A project that locked one of those releases
passed every rule on 0.6.28, because AAK knew a vulnerable release only through
a hand-written pin. Meanwhile `aak update` was already downloading OSV's complete
PyPI and npm exports for the malicious-release feed, and discarding every record
that was not `MAL-`. This rule keeps those advisory records and checks every
release a scan resolves against them.

Two days later, on 28 and 29 Oct, IBM published CVEs against Langflow OSS 1.0.0
through 1.12.8, scored 9.8. OSV had no package record of them, so the feed knew
nothing, and a project that locked langflow 1.12.8 passed every rule on 0.6.29.
The one machine-readable range was IBM's own, in NVD's record of each CVE. The
feed now also reads those CNA records, for the CVEs OSV has no package record of
(see [Sources](#sources)).

## What it catches

A PyPI, npm, Go or crates.io release that an advisory lists as affected, wherever
the project resolves it:

- a lockfile that resolves it: `uv.lock`, `poetry.lock`, `Pipfile.lock`,
  `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1),
  `Cargo.lock` (a block with a `source` line: the root crate, path dependencies and
  workspace members have none and are the project's own code);
- a `go.mod` that requires it: every `require` line, direct or `// indirect`. A
  `replace` to another module and version is judged as that module, one to a local
  path drops the module, and `exclude` is ignored. `go.sum` is not read: it lists
  modules outside the build list. A `go.mod` older than `go 1.17`, or with no `go`
  line, lists only part of the build, and a finding on one says so;
- a declaration that pins it: `vllm==0.31.1` in `requirements.txt`, an exact
  version in `pyproject.toml`, `Pipfile` or `package.json`, or a launch such as
  `uvx pkg==1.2.3` or `npx -y pkg@1.2.3` in an MCP config;
- a range every release of which is affected, such as `vllm<0.32`;
- an installed `<name>-<version>.dist-info` in a site-packages directory, a
  project's `.venv` and an unpacked image root filesystem included;
- with `aak scan --include-user-config`, a release a launcher keeps on this host:
  a package in npm's npx cache (`<cache>/_npx/<hash>/node_modules/<name>`) or a
  dist-info in one of uv's tool environments (`<cache>/environments-v*/`), read
  as [AAK-MALICIOUS-RELEASE-001](AAK-MALICIOUS-RELEASE-001.md) reads them. The
  evidence names the cache path. Without the flag nothing outside the project is
  read.

A range that admits affected and unaffected releases, such as `vllm>=0.30`, is
one INFO finding naming the advisories it admits, so a CI gate on HIGH does not
fail on a range that may resolve to a fixed release. When a lockfile in the same
directory resolves the package, the range is not reported at all: the lockfile
says what is installed. A declaration without a version is not judged, except an
MCP config's launch: one that pins no release (no version, a tag or a range) is
[AAK-KNOWN-VULN-003](AAK-KNOWN-VULN-003.md).

The finding names the advisory, its CVE ids, its score, the release and the
release that fixes it; a sample is under [Related advisories](#related-advisories).
When the fix is on a date line npm has since deprecated, the finding says so, for the
packages `agent_audit_kit/data/date_line_packages.json` names: the four npm reference
servers went back to SemVer at 1.0.0 in October 2026, so 2025.7.1, the fix an older
advisory names for server-filesystem, is not where to go any more.

## The feed

A scan reads `~/.agent-audit-kit/advisories.json` when `aak update` has written
it, else the records bundled with AAK, and never touches the network. The SARIF
run's `properties.dataFeeds.knownVulnerabilities` and the console summary say
which copy was read and when it was generated.

- `aak update` builds the cached copy in the same pass that rebuilds the
  malicious-release feed, from the same four downloads (PyPI, npm, crates.io and
  Go, about 280 MB). It keeps
  every record that is not `MAL-`, not withdrawn, and has an `ECOSYSTEM` or
  `SEMVER` range or a list of affected versions. On 2026-10-29 that was 23,579
  package entries for 5,392 packages (PyPI 15,252, npm 8,327), 8.7 MB.
- A RustSec record marked informational (`unmaintained`, `unsound` or `notice`, 521
  of the 3,055 crates.io records on 2026-11-07) is left out: RustSec files those as
  notices and cargo-audit reports them as warnings.
- A cached copy over 60 MB would keep only HIGH and CRITICAL advisories, and
  `aak update` and the summary would say so. The feed is well under it today.
- The bundled copy holds four OSV records exactly as OSV returned them: on
  2026-10-29, GHSA-h3rc-j82p-2c3h (vLLM) and GHSA-26p8-2jq9-3vq9 (MLflow), and on
  2026-11-07, GHSA-82r6-8w77-94w6 and GHSA-5p39-cfhj-2xmp (anyio below 4.14.2). OSV
  had no record for the OpenHands SDK or the NeMo Agent Toolkit advisory that
  day, so neither is bundled; once OSV publishes one, `aak update` picks it up.
  It also holds the entries `nvd_feed` converts from NVD's records as NVD served
  them on 2026-10-30, 2026-10-31 for lmdeploy and 2026-11-07 for crates.io's
  surrealdb and Go's mcp-go and ChatCLI (saved
  unedited under `tests/fixtures/nvd_cna`, and listed under
  [Related advisories](#related-advisories)): three against langflow, one against
  lmdeploy, and one against the npm packages open,
  @modelcontextprotocol/inspector and opencode-ai. Every one of the five maps to a
  package, so none was left out. Without `aak update`, nothing else is known.

## Sources

The feed has two sources, and a finding says which one it came from.

**OSV**, read as above: every PyPI and npm advisory record in OSV's exports.

**NVD's records of CNA version data**, for the CVEs OSV has no package record
of. A CVE's CNA (IBM for Langflow, VulnCheck, GitHub) writes which product
versions are affected in its CVE record, and NVD's CVE API 2.0 carries that
data at `vulnerabilities[].cve.affected[].affectedData[]`: a vendor, a product,
sometimes a `packageURL`, a `collectionURL` and `packageName`, or a `repo`, and `versions[]` of `version`,
`lessThan` or `lessThanOrEqual`, `versionType` and `status`. NVD's own CPE
`configurations`, added once NVD has analysed a record, are not read: a CPE names
a vendor and product, not a package.

- **What `aak update` reads.** Every NVD record modified in the last 120 days,
  NVD's longest window (`aak update --nvd-days N` reads fewer; `--nvd-days 0`
  reads none), 2,000 a page, pausing between requests as NVD asks: six seconds
  without an API key, less with `NVD_API_KEY` in the environment, which is sent
  as a header and never printed. On 2026-10-30 a 120-day window held 100,047
  records, 51 pages of about 4 MB at about 20 seconds each: plan for 20 minutes
  and 200 MB. The entries read replace the NVD entries read before, so the feed
  holds the NVD records modified in that window.
- **Which package a record names**, in this order and never from a name alone:
  the CNA's `packageURL` when it is `pkg:pypi/...` or `pkg:npm/...` (a
  packageURL of another registry is not overridden); else its `collectionURL`
  when that is PyPI or npm: a package's own page (`https://pypi.org/project/<name>/`,
  `https://www.npmjs.com/package/<name>`, with a `packageName`, if any, naming
  the same package), or the registry's root as the CVE JSON 5 schema's examples
  write it (`https://pypi.python.org`, `https://registry.npmjs.org`) with the name
  in `packageName`. A page and a `packageName` that disagree map nothing, and the
  record is counted unmapped rather than guessed at; any other `collectionURL` (a
  GitHub URL, a vendor's site) is passed over. JFrog's prefab-ui record (in the
  table below) names its package this way and no other. Else a row of the reviewed
  map, `agent_audit_kit/data/cna_package_map.json`, whose repository is the
  CNA's `repo`, or whose vendor and product are the CNA's. A row is added only
  after checking that the package's own page on pypi.org or npmjs.com names the
  same repository. On 2026-11-02 the map has four rows: IBM's "Langflow OSS" is
  PyPI `langflow`, the repositories sindresorhus/open and
  modelcontextprotocol/inspector are npm `open` and
  `@modelcontextprotocol/inspector`, and VulDB's "samanhappy MCPHub" is npm
  `@samanhappy/mcphub`. A record that maps to no package is
  counted and dropped, and `aak update` prints how many and the ten
  (vendor, product) pairs that most often mapped to nothing. A record for
  software on neither registry can map to a launch row of the same map instead,
  which [AAK-KNOWN-VULN-002](AAK-KNOWN-VULN-002.md) reads.
- **Which versions.** Only `status: affected` entries, read on the registry's
  order whatever `versionType` says of `semver`, `custom` or `python` (a git
  commit is not read): `version` with `lessThan` is affected up to, not
  including, that release; with `lessThanOrEqual`, up to and including it, which
  is how IBM wrote "1.0.0 through 1.12.8". A `version` with neither is one
  release when it is one, and otherwise read as GitHub's advisory grammar, the
  only way GitHub's CNA writes a range: `< 0.5.0` is affected below 0.5.0,
  `>= 2.2.0, < 3.0.1` from 2.2.0 below 3.0.1, `<= 1.2` up to and including 1.2,
  `>= 1.0.0` from 1.0.0 on, and `= 1.4.2` that release alone. `> x` starts at the
  first version after x, which semver has (3.0.1-0 after 3.0.0) and PEP 440 does
  not, so on a PyPI package it is not read. Other text (`1.0 to 1.8.0`, two
  clauses with no comma) is not read, and a record left with no range is
  counted. `changes` split a range where the
  status moves. `defaultStatus: affected` makes every release affected but those
  the entries exclude, read only when each exclusion is a range ending before a
  release or open-ended; a record whose exclusions no interval can state is not
  read rather than reported wider than the CNA wrote it.
- **Severity.** The record's CVSS 3.x base score, computed from its vector, NVD's
  own (Primary) metric before the CNA's; without one, the CVSS 4.0 metric's
  label; without either, MEDIUM. The finding says "NVD CNA record" and links the
  record on nvd.nist.gov.
- **OSV wins.** An NVD entry is dropped when an OSV entry for the same package
  names its CVE, as its id or an alias, so a CVE is reported once, with OSV's
  ranges, as soon as OSV has a record of it.
- **When NVD cannot be read**, `aak update` rebuilds the OSV half, keeps the NVD
  entries scans read before (the cached feed's, else the bundled ones), says so,
  and exits non-zero. A scan never reads NVD.

## How a release matches

- In the order its registry uses: PEP 440 for PyPI, so MLflow's
  `>=3.12.0rc0, <3.17.0` takes 3.12.0rc0 and 3.17.0rc1 and leaves 3.17.0, and
  semver for npm.
- Against the record's ranges, read in version order as OSV's specification
  evaluates them, and its listed versions. A git range, which names commits, is
  not read.
- A PYSEC record and its GHSA twin are one advisory, reported once under the
  GHSA id with both ids named. Two GHSA records are never merged, even when a
  PYSEC record names both.
- One finding per file, package and advisory, at the first entry that resolves
  an affected release. A lockfile is read for its first 64 distinct releases of a
  package.

## Severity

The severity is the advisory's, not the rule's: CRITICAL from a CVSS 3.x base
score of 9.0, HIGH from 7.0, MEDIUM below that. The score is computed from the
record's CVSS 3.x vector. Without one, GitHub's label decides (CRITICAL and HIGH
as they are, MODERATE and LOW as MEDIUM), and a record with neither is MEDIUM.
A CVSS 4.0 vector is not scored. An NVD entry is scored as [Sources](#sources)
says: its CVSS 3.x vector, else its CVSS 4.0 label, else MEDIUM.

The score is the record's own. vLLM's record carries GitHub's vector
(`AV:N/AC:H/...`, 8.1), so vLLM 0.31.1 is HIGH, although NVD scored the same flaw
9.8.

## Version pins

A hand-written pin is a judgement someone read the advisory for. Where another
rule reports every CVE id of the advisory on the same line of the same file (the
declaration or lockfile entry both point at) at or above this finding's
severity, only that rule's finding is kept: on 2026-10-29, 82 of the 134
pin-table rows named a CVE that OSV also lists. Elsewhere this rule still
reports, for instance in a lockfile below the root, which the pin table does not
read, in an installed `dist-info`, which no pin reads, or where a configuration
rule cites the CVE on another line of the file.

## How to fix

Upgrade to the release the finding names as fixed on that line, re-lock, and
rebuild the environment or image. For a manifest range, raise its lower bound
past the fix. Where the advisory lists no fixed release, remove or replace the
package, or keep the component the advisory names unreachable until one ships.
Run `aak update` so the scan reads the current advisories rather than the
bundled few.

## Related advisories

The advisories that showed the gap, as NVD and OSV listed them on 2026-10-29
(the first four), 2026-10-30 (the Langflow and open records) and 2026-10-31
(lmdeploy). They are context, not this rule's
references: the rule reports whatever advisory the feed holds.

| Product | CVE | OSV record | In the bundled feed |
|---|---|---|---|
| vLLM below 0.32.0 | CVE-2026-115915 | GHSA-h3rc-j82p-2c3h (CVSS 3.x 8.1) | yes |
| MLflow 3.12.0rc0 up to 3.17.0 | CVE-2026-116692 | GHSA-26p8-2jq9-3vq9 (CVSS 3.x 9.8) | yes |
| anyio below 4.14.2, TLS host names | CVE-2026-63374 | GHSA-82r6-8w77-94w6 (GitHub rates it CRITICAL, CVSS 4.0 only) | yes |
| anyio below 4.14.2, process-pool workers | CVE-2026-64847 | GHSA-5p39-cfhj-2xmp (GitHub rates it MODERATE, CVSS 4.0 only) | yes |
| OpenHands Software Agent SDK below 1.52.0 | CVE-2026-112346 | none yet | no; [AAK-AGENT-SERVER-NOAUTH-001](AAK-AGENT-SERVER-NOAUTH-001.md) reads its launchers |
| NVIDIA NeMo Agent Toolkit | CVE-2026-65145 | none yet | no |
| Langflow OSS 1.0.0 through 1.12.8 | CVE-2026-110186 | none | yes, from IBM's record in NVD (CVSS 3.x 9.8) |
| Langflow OSS 1.0.0 through 1.12.8 | CVE-2026-93680 | none | yes, from IBM's record in NVD (CVSS 3.x 9.8) |
| Langflow OSS 1.0.0 through 1.12.3 | CVE-2026-104339 | none | yes, from IBM's record in NVD (CVSS 3.x 9.8) |
| npm open 7.2.0 up to 11.0.0, @modelcontextprotocol/inspector 2.0.0 up to 2.12.0, opencode-ai 1.0.137 up to 1.18.33 | CVE-2026-119025 | none | yes, from VulnCheck's record in NVD, which names each package by packageURL (CVSS 3.x 7.5) |
| prefab-ui 0.14.0 up to 0.21.0, the Generative UI sandbox FastMCP's `generate_prefab_ui` runs | CVE-2026-120338 | none (GHSA-595q-jv4r-q7j9 is a repository advisory only) | yes, from JFrog's record in NVD, which names the package by `collectionURL` and `packageName` (CVSS 3.x 10.0) |
| @samanhappy/mcphub 1.0.0 through 1.0.45 and 1.1.0 through 1.1.7, fixed in 1.1.8 | CVE-2026-120323 | none | yes, from VulDB's record in NVD, which lists each release and maps by the reviewed row (CVSS 3.x 4.3); AAK-MCP-MCPHUB-CVE-2026-79748-001's floor reports the same releases, so its finding is the one kept |
| Go github.com/mark3labs/mcp-go v0.48.0 up to v1.2.1, a malicious MCP server gets the user's token minted for another resource | CVE-2026-123272 | none (GHSA-xf6j-693p-wqxx is a repository advisory only) | yes, from VulnCheck's record in NVD (CVSS 3.x 8.0), read 2026-11-07 |
| Go github.com/diillson/chatcli v1.159.0 up to v1.215.2, the same flaw in ChatCLI's MCP OAuth login | CVE-2026-123271 | none (GHSA-95vg-3r9c-2v5q is a repository advisory only) | yes, from VulnCheck's record in NVD (CVSS 3.x 8.0), read 2026-11-07 |
| crates.io surrealdb 3.1.0 up to 3.3.0, an MCP session takeover with a low-privilege token | CVE-2026-121419 | none (GHSA-pgh9-49q4-hqcx is a repository advisory only) | yes, from VulnCheck's record in NVD (CVSS 3.x 8.1), read 2026-11-07 |
| InternLM LMDeploy 0.9.0 through 0.18.0, no fixed release | CVE-2026-119706 | a git commit-range record only, none for PyPI `lmdeploy` | yes, from VulnCheck's record in NVD, which names the package by packageURL (CVSS 3.x 9.8) |

A finding on the vLLM one reads:

```text
uv.lock resolves vllm 0.31.1, which GHSA-h3rc-j82p-2c3h (CVE-2026-115915, CVSS 3.x 8.1)
lists as affected; it is fixed in 0.32.0 (https://osv.dev/vulnerability/GHSA-h3rc-j82p-2c3h).
```

and one on a Langflow record NVD carries:

```text
uv.lock resolves langflow 1.12.8, which CVE-2026-110186 (NVD CNA record, CVSS 3.x 9.8)
lists as affected; the advisory lists no fixed release, and 1.12.8 as the last affected
one (https://nvd.nist.gov/vuln/detail/CVE-2026-110186).
```
