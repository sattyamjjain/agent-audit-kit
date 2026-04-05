# Contributing to AgentAuditKit

Thank you for your interest in making AI agent pipelines safer. This guide covers everything you need to start contributing.

## Development Setup

**Prerequisites:** Python 3.9+ and Git.

```bash
git clone https://github.com/sattyamjjain/agent-audit-kit.git
cd agent-audit-kit
pip install -e ".[dev]"
```

This installs AgentAuditKit in editable mode along with testing, linting, and type-checking tools.

Verify the install:

```bash
agent-audit-kit scan .
```

## Running Tests

```bash
pytest -v
```

With coverage:

```bash
pytest -v --cov=agent_audit_kit --cov-report=term-missing
```

## Linting

```bash
ruff check .
```

Auto-fix issues:

```bash
ruff check . --fix
```

## Type Checking

```bash
mypy agent_audit_kit
```

## Code Conventions

- **Python 3.9+** compatibility is required. Do not use features exclusive to 3.10+.
- Add `from __future__ import annotations` at the top of every module.
- Use **type hints** on all function signatures and return types.
- Keep functions under 50 lines. Extract helpers if longer.
- Use `click` for CLI commands, `pyyaml` for config parsing.
- No hardcoded secrets, tokens, or API keys in source code.

## Adding a New Rule

1. Create the rule in the appropriate scanner module under `agent_audit_kit/`.
2. Assign a unique rule ID following the pattern `AAK-<CATEGORY>-<NNN>`.
3. Include `severity`, `message`, `remediation`, and `owasp_ref` fields.
4. Add tests in `tests/` that cover both detection and non-detection cases.
5. Update `docs/rules.md` with the new rule.

## Pull Request Process

1. **Fork** the repository and create a branch from `main`:
   - `feature/<short-description>` for new features
   - `fix/<short-description>` for bug fixes
   - `chore/<short-description>` for maintenance
2. Make your changes. Ensure all checks pass:
   ```bash
   pytest -v
   ruff check .
   mypy agent_audit_kit
   ```
3. Write a clear commit message in imperative mood (e.g., "Add taint analysis for pickle.loads sink").
4. Open a pull request against `main`. Fill out the PR template completely.
5. A maintainer will review your PR. Address feedback promptly.

## What Makes a Good PR

- Solves one problem. Keep the diff focused.
- Includes tests that prove the change works.
- Updates documentation if user-facing behavior changes.
- Does not introduce secret values, `.env` files, or credentials.

## Reporting Issues

Use [GitHub Issues](https://github.com/sattyamjjain/agent-audit-kit/issues) for bugs and feature requests. For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
