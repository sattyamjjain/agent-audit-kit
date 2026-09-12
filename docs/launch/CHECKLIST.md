# Launch checklist — things only you can do

Everything that does not need your identity or credentials is already done. This
file lists what is left, with the exact commands, and is written against the
**current** state of the repository rather than the state it had when the
original was drafted.

> **Rewritten 2026-09-12.** The previous version was titled "v0.3.0 launch
> checklist" and was never executed; the repository is now at v0.6.1. Several of
> its steps had since been completed by other work and are marked done below
> rather than left as open boxes, because a checklist that asks you to redo
> finished work is one you stop reading.

## Current state, for the copy you will write

| | |
|---|---|
| Version | v0.6.1 (PyPI, GHCR, GitHub Releases, Sigstore-signed bundle) |
| Rules / scanners | **348** rules, **103** scanners, 14 categories |
| Compliance frameworks | **14** |
| CVE-to-rule latency | median **1.0 day**, p90 **4 days**, measured over 77 CVEs |
| Stars | 13 |
| Licence | Apache-2.0 |

Regenerate these before posting rather than trusting the table:

```bash
python -c "import agent_audit_kit as a; print(a.RULE_COUNT, a.SCANNER_COUNT)"
python -c "from agent_audit_kit.output.pdf_report import _FRAMEWORK_TITLES as F; print(len(F))"
grep -A4 '| Median |' docs/cve-latency.md
```

## Already done — no action needed

- [x] PyPI Trusted Publisher (OIDC) — releases publish without a token
- [x] GitHub Pages live at https://sattyamjjain.github.io/agent-audit-kit/ (HTTP 200)
- [x] MCP Security Index publishing on schedule
- [x] Sigstore-signed rule bundle + CycloneDX/SPDX SBOM on every release
- [x] Docker image to GHCR, nightly rebuild
- [x] Release workflow green end to end
- [x] The repo `description` is set by the release job (needs `REPO_ADMIN_TOKEN`, see below)

## 1. One secret, once

Create a fine-grained PAT with **Administration: write** on this repository and
save it as the `REPO_ADMIN_TOKEN` secret. The release job then sets the GitHub
"About" description from `RULE_COUNT` and verifies it. Without the secret the job
prints the line for you to paste and the release still succeeds.

Settings → Secrets and variables → Actions → New repository secret.

## 2. VS Code Marketplace + Open VSX

The extension compiles clean (`npm install && npm run compile` verified
2026-09-12). It is at its own version, `0.3.3`, versioned independently of the
Python package on purpose.

You need a Marketplace publisher account (`sattyamjjain`) and an Open VSX token.

```bash
cd vscode-extension
npm install && npm run compile
npx @vscode/vsce package            # produces a .vsix you can install locally to smoke-test
npx @vscode/vsce login sattyamjjain # one time
npx @vscode/vsce publish
npx ovsx publish -p "$OPEN_VSX_TOKEN"
```

Smoke-test the `.vsix` in a scratch window before publishing: open a folder
containing an `.mcp.json` with a known-bad server and confirm the diagnostics
appear.

## 3. GitHub Marketplace listing for the Action

From the release page for the newest tag, use "Publish this Action to the GitHub
Marketplace". `action.yml` already carries the required `name`, `description`,
`branding.icon` and `branding.color`.

## 4. The posts

Drafts are in `docs/launch/`: `hn.md`, `reddit.md`, `x-thread.md`, `press.md`.
Their figures are kept in sync by `scripts/check_counts.py`, so they are current
as of this commit, but re-read them for voice before posting — they were written
in April and the project has changed shape since.

Suggested order, spaced so moderators do not auto-flag:

1. Show HN (Tue/Wed, 08:00–09:00 ET). Post the canned first comment immediately.
2. `/r/netsec`, then `/r/mcp`, then `/r/ClaudeAI`, `/r/LocalLLaMA`, ~15 min apart.
3. X thread.
4. Press emails from `press.md`.

Stay in the HN thread for the first three hours and answer every top-level
comment.

## 5. Outreach that is drafted and unsent

- `launch/owasp-outreach.md` — OWASP MCP Top 10 / Agentic Security Initiative
- `launch/awesome-list-prs/` — PR bodies for the awesome-* lists
- `research/state-of-mcp-2026/blackhat-arsenal-abstract.md` and
  `blackhat-briefings-abstract.md` — check the current CFP deadlines before
  submitting; both were written against an earlier cycle

## What to lead with

The honest differentiators, in the order they hold up to scrutiny:

1. **Compliance-evidence output.** 14 frameworks including two that are already
   in force and that competing scanners do not map: EU AI Act Article 50
   (transparency, live since 2026-08-02) and Colorado SB 26-189 ADMT
   (effective 2027-01-01). Every control row cites a real paragraph, and rows
   that cannot be evidenced say so instead of printing a tick.
2. **A published CVE-to-rule latency number** — median 1.0 day — generated from
   the ledger rather than asserted, with a guard that fails if the doc drifts.
3. **Pin and verify.** Nobody else fingerprints a tool surface at approval and
   re-verifies it afterwards. See
   `examples/case-studies/deadbugz-delayed-metadata/`.
4. **SBOM + VEX as a pair**, joined on purl, with the VEX emitter refusing to
   claim `not_affected` because a static scan cannot establish it.

Do not lead with the rule count. Every scanner has one and it invites a
comparison that is not the interesting argument.
