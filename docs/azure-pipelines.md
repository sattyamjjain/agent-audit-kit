# Azure Pipelines Integration

Add AgentAuditKit to your `azure-pipelines.yml` to scan MCP agent
configurations on every push or pull request. Mirrors the
[GitHub Actions](ci-cd.md), [GitLab CI](gitlab-ci.md), and
[CircleCI](circleci.md) integrations — same scanner, same exit codes,
same SARIF output.

## Basic setup

```yaml
# azure-pipelines.yml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'
      addToPath: true

  - script: pip install agent-audit-kit
    displayName: 'Install agent-audit-kit'

  - script: agent-audit-kit scan . --ci --severity high --fail-on high
    displayName: 'Scan MCP agent configurations'
```

## With SARIF + Azure DevOps Code-Scanning artifact

Azure DevOps does not natively render SARIF, but the SARIF artifact
can be consumed by the
[Microsoft Security DevOps task](https://marketplace.visualstudio.com/items?itemName=ms-securitydevops.microsoft-security-devops-azdevops)
or any third-party SARIF viewer:

```yaml
steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'

  - script: pip install agent-audit-kit

  - script: |
      agent-audit-kit scan . \
        --ci \
        --format sarif \
        -o $(Build.ArtifactStagingDirectory)/agent-audit.sarif \
        --fail-on high
    displayName: 'Scan and emit SARIF'

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)/agent-audit.sarif'
      artifactName: 'AgentAuditSarif'
    condition: succeededOrFailed()
```

## Pull-request gating

```yaml
trigger: none

pr:
  branches:
    include:
      - main
      - develop

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'
  - script: pip install agent-audit-kit
  - script: |
      git fetch origin $(System.PullRequest.TargetBranch)
      agent-audit-kit scan . \
        --diff origin/$(System.PullRequest.TargetBranch) \
        --fail-on high
    displayName: 'Diff-aware MCP security scan'
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No findings at or above `--fail-on` threshold |
| `1`  | Findings found (build fails) |
| `2`  | Scanner error (config / parse / I/O failure) |

Closes [#11](https://github.com/sattyamjjain/agent-audit-kit/issues/11).
