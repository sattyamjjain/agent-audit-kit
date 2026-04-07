# GitLab CI Integration

Add AgentAuditKit to your `.gitlab-ci.yml` to scan MCP agent configurations on every push.

## Basic Setup

```yaml
# .gitlab-ci.yml
agent-security-scan:
  stage: test
  image: python:3.11-slim
  script:
    - pip install agent-audit-kit
    - agent-audit-kit scan . --fail-on high --format json
  rules:
    - changes:
        - "*.mcp.json"
        - "**/mcp*.json"
        - ".claude/**"
        - "package.json"
        - "pyproject.toml"
```

## With SARIF Output

```yaml
agent-security-scan:
  stage: test
  image: python:3.11-slim
  script:
    - pip install agent-audit-kit
    - agent-audit-kit scan . --ci
  artifacts:
    reports:
      sast: agent-audit-results.sarif
    paths:
      - agent-audit-results.sarif
    when: always
```

GitLab automatically parses SARIF artifacts and shows findings in the **Security Dashboard** and **Merge Request widget**.

## With Security Score

```yaml
agent-security-scan:
  stage: test
  image: python:3.11-slim
  script:
    - pip install agent-audit-kit
    - agent-audit-kit scan . --fail-on high --score
    - agent-audit-kit scan . --format sarif -o agent-audit-results.sarif --fail-on none
  artifacts:
    reports:
      sast: agent-audit-results.sarif
```

## Compliance Scanning

```yaml
agent-compliance:
  stage: test
  image: python:3.11-slim
  script:
    - pip install agent-audit-kit
    - agent-audit-kit scan . --compliance eu-ai-act
    - agent-audit-kit scan . --compliance soc2
  only:
    - main
    - merge_requests
```

## Using Docker Image

```yaml
agent-security-scan:
  stage: test
  image: ghcr.io/sattyamjjain/agent-audit-kit:0.2.0
  script:
    - agent-audit-kit scan . --ci
  artifacts:
    reports:
      sast: agent-audit-results.sarif
```

## Exit Codes

| Code | Meaning |
|:----:|---------|
| 0 | Scan passed |
| 1 | Findings exceed `--fail-on` threshold (pipeline fails) |
| 2 | Error (invalid config, etc.) |
