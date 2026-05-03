# Getting Started

## Installation

```bash
pip install agent-audit-kit
```

## Basic Usage

Scan the current directory:
```bash
agent-audit-kit scan .
```

Scan with SARIF output for CI/CD:
```bash
agent-audit-kit scan . --format sarif -o report.sarif
```

Only show critical and high findings:
```bash
agent-audit-kit scan . --severity high
```

Show security score:
```bash
agent-audit-kit scan . --score
```

OWASP coverage matrix:
```bash
agent-audit-kit scan . --owasp-report
```

Compliance check:
```bash
agent-audit-kit scan . --compliance eu-ai-act
```

## CI/CD Mode

Exit with code 1 if any finding at or above threshold:
```bash
agent-audit-kit scan . --ci --severity high
```

## Pre-commit

Add to `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/sattyamjjain/agent-audit-kit
    rev: v0.3.13
    hooks:
      - id: agent-audit-kit
```

## GitHub Action

```yaml
- uses: user/agent-audit-kit@v0.2.0
  with:
    severity: low
    fail-on: high
```
