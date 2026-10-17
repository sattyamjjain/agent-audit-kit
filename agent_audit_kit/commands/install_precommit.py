"""The ``install-precommit`` command.

Moved out of ``cli.py`` (issue #701) when it learned to write only inside the
project, which took ``cli.py`` past the 1,300 lines ``tests/test_cli_scan_extraction.py``
holds it under. Its decorators and parameter are the ones it had there, and ``cli``
registers the command with ``add_command``, as it does ``scan``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from agent_audit_kit import __version__
from agent_audit_kit.commands._common import EXIT_ERROR

__all__ = ["install_precommit_cmd"]


@click.command("install-precommit")
@click.version_option(version=__version__)
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
def install_precommit_cmd(path: str) -> None:
    """Add an agent-audit-kit entry to the project's .pre-commit-config.yaml.

    Exits 2, leaving the file as it was, when it cannot be written inside the
    project, for instance because it is a link that leads out of it.
    """
    from agent_audit_kit.fix import _as_written, _read_text, _write_inside_project, _write_refusal

    project = Path(path)
    cfg_path = project / ".pre-commit-config.yaml"
    # Pin the release that is running this command. A literal here (it was
    # v0.3.0) froze every new install on a months-old hook no matter which
    # version wrote it.
    snippet = (
        "  - repo: https://github.com/sattyamjjain/agent-audit-kit\n"
        f"    rev: v{__version__}\n"
        "    hooks:\n"
        "      - id: agent-audit-kit\n"
    )
    # The repository decides what sits at this path, and `is_file()`, `read_text`
    # and `write_text` followed a link: a config linked to a file outside the
    # project had the hook written into that file, a dangling link had the file it
    # named created, and a FIFO blocked the command forever. The path is looked at
    # before it is read, read only as a regular file and written through
    # `_write_inside_project`, as every `aak fix` recipe does. A missing file reads
    # as empty, which takes the same branch as it did.
    existing = ""
    refused = _write_refusal(cfg_path, project)
    if refused is None:
        try:
            existing = _read_text(cfg_path, encoding="utf-8")
        except FileNotFoundError:
            pass
        except OSError as exc:
            refused = f"{cfg_path.name} could not be read ({exc.strerror})" if exc.strerror else str(exc)
    if refused is None and "agent-audit-kit" in existing:
        click.echo("agent-audit-kit hook already configured in .pre-commit-config.yaml")
        return
    if refused is None:
        if "repos:" in existing:
            text = existing.rstrip() + "\n" + snippet
        else:
            text = "repos:\n" + snippet
        refused = _write_inside_project(cfg_path, _as_written(text), project)
    if refused is not None:
        click.echo(f"Cannot add the hook: {refused}. .pre-commit-config.yaml was not changed.", err=True)
        sys.exit(EXIT_ERROR)
    click.echo(f"added agent-audit-kit pre-commit hook to {cfg_path.relative_to(project)}")
    click.echo("next: run `pre-commit install`")
