# AgentAuditKit task runner.
#
# The State of MCP report is a build artifact: `make report` regenerates
# results.json from the committed corpus manifest, deterministically and
# offline, so the numbers in research/state-of-mcp-2026/REPORT.md cannot drift
# from the code. `make corpus` is the single network step (refreshes the
# manifest from the MCP Registry); it is intentionally separate from `report`.

RESEARCH := research/state-of-mcp-2026
CORPUS   := benchmarks/data
MANIFEST := $(RESEARCH)/corpus/registry-manifest.json
RESULTS  := $(RESEARCH)/results.json

.PHONY: report corpus report-check count-check test lint typecheck repo-description \
        cve-latency cve-latency-check cve-latency-refresh

## report: regenerate results.json from the corpus + manifest (offline, deterministic)
report:
	python $(RESEARCH)/run_report.py \
	  --corpus $(CORPUS) \
	  --registry-manifest $(MANIFEST) \
	  --out $(RESULTS)

## corpus: refresh the MCP Registry corpus manifest (the one network step)
corpus:
	python $(RESEARCH)/fetch_registry.py --target 5000

## report-check: fail if results.json is not byte-identical to a fresh run (drift guard)
report-check:
	@python $(RESEARCH)/run_report.py --corpus $(CORPUS) --registry-manifest $(MANIFEST) --out /tmp/aak-report-check.json >/dev/null
	@diff -q $(RESULTS) /tmp/aak-report-check.json >/dev/null && echo "report is up to date" \
	  || (echo "results.json is stale — run 'make report' and commit" && exit 1)

## count-check: fail if any tracked markdown carries a stale rule/scanner count (repo-wide, minus changelogs + dated artifacts)
count-check:
	@PYTHONPATH=. python scripts/check_counts.py

## cve-latency: regenerate docs/cve-latency.md from the ledger (offline, deterministic)
cve-latency:
	python scripts/cve_latency.py

## cve-latency-check: fail if docs/cve-latency.md is stale vs the ledger (drift guard, runs on tag)
cve-latency-check:
	@python scripts/cve_latency.py --check

## cve-latency-refresh: top up docs/data/cve-published.json from NVD (the one network step)
cve-latency-refresh:
	python scripts/cve_latency.py --refresh

## test: run the test suite
test:
	python -m pytest -q

## lint: ruff
lint:
	ruff check .

## typecheck: mypy the package
typecheck:
	mypy agent_audit_kit

## repo-description: print the GitHub "About" description, rendered from RULE_COUNT.
## Paste the output into repo Settings > About when RULE_COUNT changes — GitHub's
## description field is not writable from a CI token (see docs/RELEASING.md).
repo-description:
	@PYTHONPATH=. python scripts/render_repo_metadata.py
