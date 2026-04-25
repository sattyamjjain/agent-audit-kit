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
      - uses: user/agent-audit-kit@v0.2.0
        with:
          severity: low
          fail-on: high
```

## Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/sattyamjjain/agent-audit-kit
    rev: v0.3.5
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

## Diff-Aware Scanning

Only scan files changed in a PR:
```bash
agent-audit-kit scan . --diff origin/main
```
