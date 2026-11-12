# AAK-GHA-PUBLISH-GATE-001

**Workflow job publishes a package with no environment approval gate**

| Field | Value |
|---|---|
| Severity | HIGH |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.36 |
| Scanner | `agent_audit_kit/scanners/gha_hardening.py` |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities) |
| Incident | [GHSA-hh7j-5m3j-23pf](https://github.com/advisories/GHSA-hh7j-5m3j-23pf), @ethersphere/bee-js 13.3.0 (2026-11-09) |

## What it catches

A job that publishes a package and names no GitHub environment runs as soon as
its trigger fires. Whoever can fire the trigger, or holds a token that can,
ships a release nobody approved:

```yaml
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - run: npm publish --provenance --access public
```

That is how @ethersphere/bee-js 13.3.0 shipped malware: stolen CI credentials
created a GitHub release, the release started the npm publish workflow, and the
job published with no approval in 73 seconds. The package carried valid
provenance, because provenance records where a package was built, not that
anyone reviewed the release.

The rule reads every job in the files directly inside `.github/workflows` and
reports a job, once, at its first step that publishes, when the job names no
`environment:`. A step publishes when it:

- uses `pypa/gh-action-pypi-publish`, `JS-DevTools/npm-publish` or
  `rubygems/release-gem`, at any ref;
- runs `npm`, `pnpm`, `yarn`, `yarn npm`, `bun`, `uv`, `poetry`, `hatch`,
  `flit`, `pdm`, `cargo`, `vsce` or `ovsx publish`, `twine upload`, `gem push`,
  `nuget push` or `dotnet nuget push`, directly or behind `npx`, `uvx`,
  `pipx run`, `python -m`, `sudo`, `env` or `VAR=value` words, with only option
  words between the program and its subcommand (`pnpm -r publish`).

The evidence names the job, the command or action, the workflow's triggers and
whether the job has the `id-token` permission set to `write`. When a release or
a tag push starts the workflow, it says so: anyone who can create a release or
push a tag publishes with no human in the loop.

## What it leaves alone

```yaml
jobs:
  publish:
    runs-on: ubuntu-latest
    environment:
      name: npm-release
      url: https://www.npmjs.com/package/example
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - run: npm publish --provenance --access public
```

- A job that names an environment, as a string or as a mapping with a `name`.
- A command with `--dry-run`, `npm pack`, `npm run publish`, `git push` and
  `docker push`.
- An upload to TestPyPI or to a registry on the runner (`localhost`,
  `127.0.0.1`), named in the command, in the action's `with:` inputs or in an
  `env:` value whose name says it sets the registry.

## Limitations

- A named environment counts as the gate. Whether it has required reviewers,
  or any protection rule, is a repository setting, not in the checkout, so check
  it in Settings > Environments.
- A job that calls a reusable workflow (`uses:` on the job) is not read, nor is
  a composite action or a script the step runs (`./release.sh`,
  `npm run release`).
- A release tool that publishes for you (`changesets/action`,
  `semantic-release`) is not read.
- An option with a value between a program and its subcommand stops the match:
  `pnpm --filter pkg publish` is not read.

## How to fix

Put the publishing job behind a GitHub environment and give that environment
required reviewers in Settings > Environments, so a release waits for a person
before it publishes. Keep the release trigger. For trusted publishing, name the
same environment in the PyPI or npm trusted-publisher configuration, so a
token is minted only for a run that passed the gate.
