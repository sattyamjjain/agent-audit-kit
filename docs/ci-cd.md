# CI/CD Integration

## GitHub Actions

```yaml
name: MCP Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sattyamjjain/agent-audit-kit@v0.5.1
        with:
          severity: low
          fail-on: high
```

## Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/sattyamjjain/agent-audit-kit
    rev: v0.5.1
    hooks:
      - id: agent-audit-kit
      # Or strict mode:
      - id: agent-audit-kit-strict
```

## GitLab CI

```yaml
agent-audit:
  image: python:3.12
  script:
    - pip install agent-audit-kit
    - agent-audit-kit scan . --ci --severity high --format sarif -o gl-agent-audit.sarif
  artifacts:
    reports:
      sast: gl-agent-audit.sarif
```

## Jenkins

```groovy
stage('MCP Security') {
    sh 'pip install agent-audit-kit'
    sh 'agent-audit-kit scan . --ci --severity high --format sarif -o report.sarif'
    recordIssues tool: sarif(pattern: 'report.sarif')
}
```

## Evidence Artifacts

Generate the SBOM and its companion exploitability document in the same job.
Both are offline and deterministic, so re-running does not churn the artifact:

```yaml
      - name: Evidence bundle
        run: |
          pip install agent-audit-kit
          agent-audit-kit sbom . --format cyclonedx -o sbom.cdx.json
          agent-audit-kit vex  .                    -o vex.openvex.json
      - uses: actions/upload-artifact@v4
        with:
          name: supply-chain-evidence
          path: |
            sbom.cdx.json
            vex.openvex.json
```

The two documents identify products by the same purl, so consumers join them
without a mapping table. `vex` is an evidence command, not a gate: it exits 0
on a clean emit regardless of findings. See [VEX and SBOM](vex.md).

## Diff-Aware Scanning

Only scan files changed in a PR:
```bash
agent-audit-kit scan . --diff origin/main
```
