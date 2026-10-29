# AAK-KNOWN-VULN-001

**A locked, pinned or installed release is affected by a published advisory**

| Field | Value |
|---|---|
| Severity | The advisory's: CRITICAL from CVSS 9.0, HIGH from 7.0, MEDIUM below that; INFO for a range |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.29 |
| Scanner | `agent_audit_kit/scanners/known_vulns.py` |
| Feed | `agent_audit_kit/advisory_feed.py` |
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
  Without `aak update`, nothing else is known.

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
A CVSS 4.0 vector is not scored.

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
bundled two.

## Related advisories

The advisories that showed the gap, as NVD and OSV listed them on 2026-10-29.
They are context, not this rule's references: the rule reports whatever advisory
the feed holds.

| Product | CVE | OSV record | In the bundled feed |
|---|---|---|---|
| vLLM below 0.32.0 | CVE-2026-115915 | GHSA-h3rc-j82p-2c3h (CVSS 3.x 8.1) | yes |
| MLflow 3.12.0rc0 up to 3.17.0 | CVE-2026-116692 | GHSA-26p8-2jq9-3vq9 (CVSS 3.x 9.8) | yes |
| OpenHands Software Agent SDK below 1.52.0 | CVE-2026-112346 | none yet | no; [AAK-AGENT-SERVER-NOAUTH-001](AAK-AGENT-SERVER-NOAUTH-001.md) reads its launchers |
| NVIDIA NeMo Agent Toolkit | CVE-2026-65145 | none yet | no |

A finding on the vLLM one reads:

```text
uv.lock resolves vllm 0.31.1, which GHSA-h3rc-j82p-2c3h (CVE-2026-115915, CVSS 3.x 8.1)
lists as affected; it is fixed in 0.32.0 (https://osv.dev/vulnerability/GHSA-h3rc-j82p-2c3h).
```
