# AAK-GHA-SECRET-DUMP-001

**Workflow step prints secrets through an encoder**

| Field | Value |
|---|---|
| Severity | HIGH; CRITICAL when the workflow carries a published Gheist marker |
| Category | `SECRET_EXPOSURE` |
| Shipped | v0.6.28 |
| Scanner | `agent_audit_kit/scanners/gha_hardening.py` |
| OWASP MCP | MCP01:2025 (Token Mismanagement & Secret Exposure) |
| OWASP Agentic | ASI03 (Identity and Privilege Abuse), ASI04 (Agentic Supply Chain Vulnerabilities) |
| Incident | [Gheist](https://www.wiz.io/blog/gheist-attempted-scaled-abuse-of-stolen-github-tokens-stumbles) (Wiz, 2026-10-25) |

## What it catches

GitHub masks a secret in a job log only where its exact value appears. Pass it
through an encoder first and the log prints it in full:

```yaml
- run: |
    env | base32 -w 120
    echo -n '${{ toJSON(secrets) }}' | base32 -w 120
```

That is the step the Gheist campaign planted with stolen tokens: a branch named
`ci-sync-` plus six characters, adding `.github/workflows/sync-check.yml` with the
commit message `ci: sync config`. The push ran the workflow, the tool downloaded
the log through the API, and deleted the run seconds later.

The rule reports a `run:` command that expands the secrets context
(`toJSON(secrets)`, `secrets.X`, or an env var set from a secret) or the whole
environment (`env`, `printenv`, `set`, `export -p`, `declare -p`) and feeds it to
an encoder or transformer (base32, base64, xxd, od, rev, gzip, `openssl enc` and
the like) whose output reaches the log. It is raised to CRITICAL when the
workflow carries one of Wiz's published markers: the file `sync-check.yml` with
the step `toJSON(secrets) }}' | base32 -w 120`, or the string `===== gdmp-pivot:`.

## What it leaves alone

- A secret given to a tool as an env var or on stdin.
- A secret decoded into a file (`echo "${{ secrets.CERT }}" | base64 -d > cert.p12`)
  or piped into a program that consumes it (`docker login --password-stdin`,
  `gpg --import`).
- An encoder that reads no secret (`base64 -d assets/logo.b64 > logo.png`).

## Hunt

The rule reads the workflows in your checkout. A planted workflow lives on its
own branch, and its run is usually deleted, so look on GitHub as well:

- **Branches.** List remote branches named like the campaign's:
  `git ls-remote --heads origin 'refs/heads/ci-sync-*'`. Wiz's pattern is
  `^ci-sync-[0-9a-z]{6}$`; the only change on one is a new
  `.github/workflows/sync-check.yml`, committed as `ci: sync config`.
- **Deleted runs.** In the organization or enterprise audit log, look for
  `workflows.delete_workflow_run` on `ci-sync-*` branches soon after a
  `workflows.completed_workflow_run`, and for requests with the user agent
  `gheist`. `workflows.prepared_workflow_job` lists the secrets each job was
  given, which tells you what to rotate.
- **Cloud credentials.** If your workflows authenticate to a cloud with OIDC,
  look for role assumptions or token exchanges whose subject names a `ci-sync-`
  branch.
- **Self-hosted runners.** Look for the files `.gdmp_pat`, `.gdmp_patg` and
  `.gdmp_sweep`, and for `gdmp-pivot` in job logs.

## How to fix

Remove the step. If you did not write it, rotate every repository,
organization and environment secret the workflow could read, revoke the token
that pushed the commit, and check its owner's machine. Require reviewers on
environments that hold production secrets.
