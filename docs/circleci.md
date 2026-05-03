# CircleCI Integration

Run AgentAuditKit on every push by adding a `.circleci/config.yml`
job. Mirrors the [GitHub Actions](ci-cd.md) and
[GitLab CI](gitlab-ci.md) integrations — same scanner, same exit
codes, same SARIF output.

## Basic setup

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  agent-audit:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run:
          name: Install agent-audit-kit
          command: pip install agent-audit-kit
      - run:
          name: Scan MCP agent configurations
          command: agent-audit-kit scan . --ci --severity high --fail-on high

workflows:
  test-and-scan:
    jobs:
      - agent-audit
```

## With SARIF artifact upload

CircleCI's free [`store_artifacts`](https://circleci.com/docs/configuration-reference/#storeartifacts)
step archives the SARIF report so any human reviewer can download it.
Pair with a [`store_test_results`](https://circleci.com/docs/configuration-reference/#storetestresults)
upload if you want CircleCI's UI to surface findings as test failures.

```yaml
jobs:
  agent-audit:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run: pip install agent-audit-kit
      - run:
          name: Scan and emit SARIF
          command: |
            agent-audit-kit scan . \
              --ci \
              --format sarif \
              -o agent-audit.sarif \
              --fail-on high
      - store_artifacts:
          path: agent-audit.sarif
          destination: agent-audit.sarif
```

## Diff-aware scanning on pull requests

CircleCI exposes the base branch via `CIRCLE_PR_BASE_BRANCH` (or
`main` when not set). Scan only the diff to keep PR runs fast:

```yaml
      - run:
          name: Diff-aware MCP security scan
          command: |
            BASE="${CIRCLE_PR_BASE_BRANCH:-main}"
            git fetch origin "$BASE"
            agent-audit-kit scan . --diff "origin/$BASE" --fail-on high
```

## Scheduled nightly compliance scan

```yaml
workflows:
  nightly-compliance:
    triggers:
      - schedule:
          cron: "23 6 * * *"
          filters:
            branches:
              only: main
    jobs:
      - agent-audit
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No findings at or above `--fail-on` threshold |
| `1`  | Findings found (build fails) |
| `2`  | Scanner error (config / parse / I/O failure) |

Closes [#10](https://github.com/sattyamjjain/agent-audit-kit/issues/10).
