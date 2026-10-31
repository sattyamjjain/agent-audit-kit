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

A PyPI or npm release that an advisory lists as affected, wherever the project
resolves it:

- a lockfile that resolves it: `uv.lock`, `poetry.lock`, `Pipfile.lock`,
  `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1);
- a declaration that pins it: `vllm==0.31.1` in `requirements.txt`, an exact
  version in `pyproject.toml`, `Pipfile` or `package.json`, or a launch such as
  `uvx pkg==1.2.3` or `npx -y pkg@1.2.3` in an MCP config;
- a range every release of which is affected, such as `vllm<0.32`;
- an installed `<name>-<version>.dist-info` in a site-packages directory, a
  project's `.venv` and an unpacked image root filesystem included.

A range that admits affected and unaffected releases, such as `vllm>=0.30`, is
one INFO finding naming the advisories it admits, so a CI gate on HIGH does not
fail on a range that may resolve to a fixed release. When a lockfile in the same
directory resolves the package, the range is not reported at all: the lockfile
says what is installed. A declaration without a version is not judged.

The finding names the advisory, its CVE ids, its score, the release and the
release that fixes it; a sample is under [Related advisories](#related-advisories).

## The feed

A scan reads `~/.agent-audit-kit/advisories.json` when `aak update` has written
it, else the records bundled with AAK, and never touches the network. The SARIF
run's `properties.dataFeeds.knownVulnerabilities` and the console summary say
which copy was read and when it was generated.

- `aak update` builds the cached copy in the same pass that rebuilds the
  malicious-release feed, from the same two downloads (about 260 MB). It keeps
  every record that is not `MAL-`, not withdrawn, and has an `ECOSYSTEM` or
  `SEMVER` range or a list of affected versions. On 2026-10-29 that was 23,579
  package entries for 5,392 packages (PyPI 15,252, npm 8,327), 8.7 MB.
- A cached copy over 60 MB would keep only HIGH and CRITICAL advisories, and
  `aak update` and the summary would say so. The feed is well under it today.
- The bundled copy holds two OSV records exactly as OSV returned them on
  2026-10-29: GHSA-h3rc-j82p-2c3h (vLLM) and GHSA-26p8-2jq9-3vq9 (MLflow). OSV
  had no record for the OpenHands SDK or the NeMo Agent Toolkit advisory that
  day, so neither is bundled; once OSV publishes one, `aak update` picks it up.
  It also holds the seven entries `nvd_feed` converts from NVD's records of five
  CVEs as NVD served them on 2026-10-30 and, for lmdeploy, 2026-10-31 (saved
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
sometimes a `packageURL` or a `repo`, and `versions[]` of `version`,
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
  packageURL of another registry is not overridden); else a row of the reviewed
  map, `agent_audit_kit/data/cna_package_map.json`, whose repository is the
  CNA's `repo`, or whose vendor and product are the CNA's. A row is added only
  after checking that the package's own page on pypi.org or npmjs.com names the
  same repository. On 2026-10-30 the map has three rows: IBM's "Langflow OSS" is
  PyPI `langflow`, and the repositories sindresorhus/open and
  modelcontextprotocol/inspector are npm `open` and
  `@modelcontextprotocol/inspector`. A record that maps to no package is
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
| OpenHands Software Agent SDK below 1.52.0 | CVE-2026-112346 | none yet | no; [AAK-AGENT-SERVER-NOAUTH-001](AAK-AGENT-SERVER-NOAUTH-001.md) reads its launchers |
| NVIDIA NeMo Agent Toolkit | CVE-2026-65145 | none yet | no |
| Langflow OSS 1.0.0 through 1.12.8 | CVE-2026-110186 | none | yes, from IBM's record in NVD (CVSS 3.x 9.8) |
| Langflow OSS 1.0.0 through 1.12.8 | CVE-2026-93680 | none | yes, from IBM's record in NVD (CVSS 3.x 9.8) |
| Langflow OSS 1.0.0 through 1.12.3 | CVE-2026-104339 | none | yes, from IBM's record in NVD (CVSS 3.x 9.8) |
| npm open 7.2.0 up to 11.0.0, @modelcontextprotocol/inspector 2.0.0 up to 2.12.0, opencode-ai 1.0.137 up to 1.18.33 | CVE-2026-119025 | none | yes, from VulnCheck's record in NVD, which names each package by packageURL (CVSS 3.x 7.5) |
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
