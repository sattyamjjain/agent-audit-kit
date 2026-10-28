"""The ``update`` command: the vulnerability database and the malicious-release feed.

Moved out of ``cli.py`` (issue #701) when it learned to rebuild the malicious-release
feed, which took ``cli.py`` past the 1,300 lines ``tests/test_cli_scan_extraction.py``
holds it under. ``cli`` registers it with ``add_command``, as it does ``scan``.
"""

from __future__ import annotations

import sys

import click

from agent_audit_kit import __version__
from agent_audit_kit.commands._common import EXIT_ERROR

__all__ = ["update_cmd"]


def _github_token() -> str | None:
    """The token `--github-malware` pages GitHub with: GITHUB_TOKEN, else GH_TOKEN."""
    import os

    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value
    return None


@click.command("update")
@click.version_option(version=__version__)
@click.option(
    "--github-malware",
    is_flag=True,
    help="Also add GitHub's malware advisories for npm and pip to the feed. Needs "
         "GITHUB_TOKEN or GH_TOKEN, and takes about 1,200 API requests.",
)
def update_cmd(github_malware: bool) -> None:
    """Update the vulnerability database and the malicious-release feed.

    The feed is rebuilt from OSV's malicious-package records for PyPI and npm
    (about 260 MB of exports), and from GitHub's malware advisories with
    --github-malware. Scans never fetch it; they read the copy this writes,
    else the bundled one. Any failure keeps what was cached before and exits
    non-zero.
    """
    from agent_audit_kit import malicious_feed
    from agent_audit_kit.vuln_db import update_database

    token = _github_token()
    if github_malware and token is None:
        click.echo("--github-malware needs GITHUB_TOKEN or GH_TOKEN: GitHub allows 60 "
                   "unauthenticated requests an hour, too few to page its malware advisories.", err=True)
        sys.exit(EXIT_ERROR)
    failed = False
    count = update_database()
    if count >= 0:
        click.echo(f"Vulnerability database updated: {count} entries.")
    else:
        click.echo("Update failed. Using bundled database.", err=True)
        failed = True
    click.echo("Rebuilding the malicious-release feed from OSV (about 260 MB)...")
    try:
        done = malicious_feed.refresh(github_token=token if github_malware else None)
    except malicious_feed.FeedUpdateError as exc:
        kept = "the cached feed" if malicious_feed.cache_path().is_file() else "the bundled feed"
        click.echo(f"Malicious-release feed update failed: {exc}. Scans keep using {kept}.", err=True)
        failed = True
    else:
        counts = ", ".join(f"{source} {n:,}" for source, n in done.counts.items())
        click.echo(
            f"Malicious-release feed updated: {sum(done.counts.values()):,} entries ({counts}), "
            f"generated {done.generated_at}, written to {done.path}. GitHub: {done.github}."
        )
    if failed:
        sys.exit(EXIT_ERROR)
