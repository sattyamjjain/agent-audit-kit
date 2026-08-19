# Releasing agent-audit-kit

This file documents the manual + automated steps for cutting a release.
The atomic claims-vs-code chain is enforced by `scripts/sync_*.py` (run
by `.github/workflows/sync-rule-count.yml` and the local pre-commit
hook). Most surfaces are anchor-pinned. **One surface is not** — see §3.

## 1. Pre-tag

- Bump `pyproject.toml` `version`.
- Bump `agent_audit_kit/__init__.py` `__version__` (and re-Read after the bump
  per the v0.3.11 lesson — the on-disk grep is the authoritative pin).
- Bump `tests/test_phase5.py` version assertion.
- Run `python3 scripts/sync_rule_count.py --regenerate`.
- Run `python3 scripts/sync_scanner_count.py`.
- Run `python3 scripts/sync_repo_metadata.py --write`.
- Re-grep `pyproject.toml` `^version` and `__init__.py` `__version__`. Both must read the new version.
- `pytest -q && ruff check . && mypy agent_audit_kit/ && agent-audit-kit rule lint`.
- Update `CHANGELOG.md` and `CHANGELOG.cves.md`.

## 2. Tag

- `git tag vX.Y.Z <merge-commit>` after the PR is squash-merged.
- `git push origin vX.Y.Z` triggers `release.yml`.
- Watch the 5 release jobs: CVE-response gate, Publish to PyPI, Push Docker image to GHCR, Rule bundle + SBOM (Sigstore), Create GitHub Release.

## 3. Post-tag — re-PATCH the GitHub repo description

> The GitHub repo `description` field is the highest-leverage marketing
> surface (procurement reviewers read it first) and is **not** wired into
> the sync scripts. It is a one-time-set field unless we re-set it on
> every release.

After every tag push, re-PATCH the description so it matches the live
RULE_COUNT and the canonical framework count — both read from code, never
laundered from the README's own claim:

```bash
RULES=$(python3 -c "from agent_audit_kit import RULE_COUNT; print(RULE_COUNT)")
# Two distinct framework surfaces — do not confuse them:
#   12 = `report --framework` PDF/text evidence packs
#        (agent_audit_kit.output.pdf_report._FRAMEWORK_TITLES). This is the
#        "N compliance frameworks" number the description should carry, and it
#        is fenced against README/CLAUDE/docs prose in test_rule_count_sync.py.
#    8 = agent_audit_kit.output.compliance.FRAMEWORKS — the smaller,
#        control-mapped table behind `scan --compliance`. Do NOT use it here.
FRAMEWORKS=$(python3 -c "from agent_audit_kit.output.pdf_report import _FRAMEWORK_TITLES; print(len(_FRAMEWORK_TITLES))")
gh repo edit sattyamjjain/agent-audit-kit \
  --description "Static scanner for MCP-connected AI agent pipelines — ${RULES} rules across 13 categories, ${FRAMEWORKS} compliance frameworks, OWASP Agentic 10/10 + MCP 10/10, GitHub Action, SARIF, public CVE-to-rule ledger."
```

This drift was observed at v0.3.15 ship time: the description still
read "77 rules, 13 scanners" when the live RULE_COUNT was 193. Closing
it requires either this manual step on every release or wiring it
into `release.yml` as a post-publish job. Manual is acceptable until
v0.4.0; wire it then.

**v0.3.16 self-bug:** the original `len(FRAMEWORKS)` form shipped here
on 2026-05-09 returned 6 (dict size), not 12 (README claim). Fixed
inline above; `gh repo edit` re-PATCH was redone post-tag with the
correct number. Future releases use the README-grep form.

## 4. Verify

- PyPI index shows new version as `latest`. Index can lag the workflow's `Publish to PyPI: success` by 1–2 minutes; poll until propagated.
- GitHub Release published, non-draft, non-prerelease.
- GHCR Docker image pushed.
- Sigstore SBOM + bundle uploaded.
- README badges (rule count, framework count, version pin) all atomic.
- GitHub repo description re-PATCHED per §3.

## 5. CVE-gate hygiene

Before tagging, close every open `cve-response` issue (the `sla-48h`
label was retired with the 48h SLA in PR #432). The release workflow's
**CVE-response gate** blocks the tag-push pipeline until they are all
closed. Most are class-coverage dups of an earlier batch — close with the
standard citation template (`CHANGELOG.cves.md` / class-detector path).
Net-new shapes get a v(N+1) deferral comment with the rule-name pre-allocated.

The cve-watcher dedup bug (issue #163) re-fires closed CVE IDs across
daily cycles. Fix queued for v0.3.17.
