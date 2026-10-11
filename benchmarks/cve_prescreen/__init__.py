"""CVE pre-screen: a candidate disposition for each `cve-response` issue.

The CVE watcher opens one release-gating issue per matching NVD record, a mean
of four a day in bursts of thirteen, and a share of every burst is keyword
noise. This package drafts the first read so the maintainer starts from a
candidate instead of a blank issue:

* `retrieval` fetches NVD, the GitHub advisory (REST) and OSV for a CVE, with
  NVD's public rate limit enforced, and caches the raw responses on disk.
  Deterministic, no model.
* `context` compacts them into one small JSON object whose structured fields
  the classifier must cite.
* `prompts` holds the two prompts and their JSON schemas: a noise filter, and
  the full classification (disposition, affected packages copied from the
  structured data with the field each value came from, a one-line rationale).
* `runner` invokes `claude -p` on the Claude subscription, one isolated call
  per record, and records the model that actually answered.
* `ground_truth` and `backtest` measure the classifier against what the
  maintainer actually decided, from `CHANGELOG.cves.md` and the closed issues.

Model output is a candidate. Nothing here closes, labels or comments on an
issue; the maintainer decides. See README.md in this directory.
"""

from __future__ import annotations

DISPOSITIONS = ("version-pin", "new-detection", "out-of-scope", "needs-human")
