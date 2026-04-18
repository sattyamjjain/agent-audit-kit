# v0.3.0 launch checklist — things YOU do

Work items that require your identity or credentials. I've prepared
everything else; these steps are for you.

## Pre-launch (T-48h)

- [ ] Review `docs/launch/release-notes-v0.3.0.md` and approve.
- [ ] Review `docs/launch/hn.md`, `reddit.md`, `x-thread.md`,
      `press.md`. Adjust voice if anything sounds too synthetic.
- [ ] Review `docs/disclosure-policy.md`. Confirm you're comfortable
      being named as the security-contact address.
- [ ] Push commits + tags to GitHub:
      ```
      git push origin main --follow-tags
      ```
- [ ] Confirm PyPI Trusted Publisher config is set up for the `pypi`
      environment. (GitHub Settings → Environments → `pypi`.)
- [ ] Decide whether to route the MCP Security Index domain
      `mcp-security-index.com` through Cloudflare Pages or GitHub Pages.
      Either works. For GH Pages: enable Pages, source = `gh-pages`
      branch. For CFP: add a CNAME record pointing at the GH Pages URL.
- [ ] Send press emails (from `docs/launch/press.md`) with the Tuesday
      13:00 UTC embargo.

## Launch day (Tuesday, T=0)

- [ ] 10:00 UTC: run one final `agent-audit-kit scan .` on the repo
      itself. Tree must be clean.
- [ ] 11:00 UTC: `git tag -s v0.3.0 -m "Phase 1–5"` then `git push
      origin v0.3.0`. This triggers `.github/workflows/release.yml`.
- [ ] 11:30 UTC: watch the `release.yml` run. Expected jobs: `pypi`,
      `docker`, `bundle-and-sign`, `github-release`. All must be
      green before the public post.
- [ ] 12:00 UTC: `cd vscode-extension && npm install && npm run
      compile && npx @vscode/vsce publish`. (You need a VS Code
      publisher account pre-created.)
- [ ] 12:00 UTC: `npx ovsx publish -p $OPEN_VSX_TOKEN` to mirror on
      Open VSX.
- [ ] 12:30 UTC: submit `action.yml` to the GitHub Marketplace from
      the release UI.
- [ ] 13:00 UTC: submit HN post (exact text in `hn.md`). Post the
      canned first-comment immediately.
- [ ] 13:30 UTC: post the X thread.
- [ ] 14:00 UTC: post to `/r/netsec`, `/r/ClaudeAI`, `/r/LocalLLaMA`,
      `/r/mcp` (in that order, spaced ~15 min apart so moderators
      don't auto-flag).
- [ ] 14:00–18:00 UTC: stay in the HN thread. Answer every top-level
      comment.

## Post-launch (T+24h)

- [ ] Update `docs/metrics.md` with day-1 numbers.
- [ ] Write the first `docs/blog/state-of-mcp-security-2026-wNN.md`
      post from the template. Publish it Thursday, not Wednesday —
      give the index snapshot 48h to settle before commenting on it.

## If things go wrong

- Release pipeline fails on Sigstore step: the wheel is already on
  PyPI (the `pypi` job runs first). Sigstore signature can be added
  later via `sigstore sign rules.json` locally.
- VS Code publish fails auth: the extension is optional for launch.
  Skip it and retry after launch. Reddit / HN / X don't depend on it.
- HN thread gets flagged: don't re-submit. It will re-surface after
  mod review. Submit to `/r/netsec` and X in the meantime.
- A reporter embargoes breaks early: acknowledge it, don't complain
  publicly. The story running 2 hours early doesn't matter.

## What NOT to do

- Do NOT launch on a Friday.
- Do NOT submit to HN before the PyPI/Docker jobs are green.
- Do NOT name vulnerable public servers in any post. The 90-day
  window is absolute.
- Do NOT claim "more accurate than Snyk." Verifiable claims only.
- Do NOT offer paid tiers, accounts, or "premium" features at launch.
  Zero-friction install is the wedge.
