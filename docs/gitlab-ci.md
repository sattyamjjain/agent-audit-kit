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
agent-security-report:
  stage: test
  image: python:3.11-slim
  script:
    - pip install agent-audit-kit
    - agent-audit-kit scan . --format sarif -o agent-audit-results.sarif --fail-on none
  artifacts:
    reports:
      sarif: agent-audit-results.sarif
    paths:
      - agent-audit-results.sarif
    when: always
```

`artifacts:reports:sarif` puts the findings in the pipeline's **Security** tab,
the vulnerability report, the security dashboard and the merge request security
widget. It needs GitLab Ultimate 19.1 or later, where it is on by default (18.11
and 19.0 have it behind the `sarif_ingestion` feature flag). `reports:sast` is for
GitLab's own SAST report format and does not read SARIF. On other tiers the
`paths:` entry still keeps the file as a job artifact.

GitLab ingests SARIF only from a job that succeeds, and `allow_failure` does not
change that, so this job reports with `--fail-on none` and leaves the gate to a
separate job such as [Basic Setup](#basic-setup). See GitLab's
[SARIF reports](https://docs.gitlab.com/user/application_security/detect/sarif/).

## With Security Score

```yaml
agent-security-scan:
  stage: test
  image: python:3.11-slim
  script:
    - pip install agent-audit-kit
    - agent-audit-kit scan . --fail-on high --score
```

`--score` prints the grade in the job log. Run the SARIF job above beside it to
publish the findings: this one fails on them, so GitLab would not ingest its
report.

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
  image:
    name: ghcr.io/sattyamjjain/agent-audit-kit:0.6.9
    entrypoint: [""]
  script:
    - agent-audit-kit scan . --fail-on high
```

`entrypoint: [""]` lets GitLab start its shell in the image; without it the
runner's `sh -c` reaches the image's entrypoint as arguments. Image tags are the
release version without the `v`. Pin one: `latest` is rebuilt nightly and carries
no provenance attestation.

## Exit Codes

| Code | Meaning |
|:----:|---------|
| 0 | Scan passed |
| 1 | Findings exceed `--fail-on` threshold (pipeline fails) |
| 2 | Error (invalid config, etc.) |
