# CI/CD Integration Examples

Copy-paste-ready configurations for integrating AgentAuditKit into your CI/CD pipeline.

## GitHub Actions (Recommended)

See [github-actions-sarif.yml](github-actions-sarif.yml) — scans on every push/PR and uploads findings to GitHub's Security tab as inline PR annotations.

## GitLab CI

See [gitlab-ci-scan.yml](gitlab-ci-scan.yml) — adds a security scan stage to your GitLab pipeline.

## Pre-commit Hook

See [pre-commit-config.yaml](pre-commit-config.yaml) — scans MCP configs before every commit.

## Docker

See [docker-one-liner.sh](docker-one-liner.sh) — scan any directory with a single Docker command.
