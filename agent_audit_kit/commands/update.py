"""The ``update`` command: the vulnerability database and the two OSV feeds.

Moved out of ``cli.py`` (issue #701) when it learned to rebuild the malicious-release
feed, which took ``cli.py`` past the 1,300 lines ``tests/test_cli_scan_extraction.py``
holds it under. ``cli`` registers it with ``add_command``, as it does ``scan``. The
advisory feed AAK-KNOWN-VULN-001 reads is built from the same OSV exports, in the
same pass, so each is downloaded once.
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
    """Update the vulnerability database, the malicious-release feed and the advisory feed.

    Both feeds are rebuilt from OSV's exports for PyPI and npm (about 260 MB,
    downloaded once): the malicious-package records, plus GitHub's malware
    advisories with --github-malware, and every other advisory record. Scans
    never fetch them; they read the copies this writes, else the bundled ones.
    Any failure keeps what was cached before and exits non-zero.
    """
    from agent_audit_kit import advisory_feed, malicious_feed
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
    click.echo("Rebuilding the malicious-release and advisory feeds from OSV (about 260 MB)...")
    collector = advisory_feed.Collector()
    try:
        done = malicious_feed.refresh(github_token=token if github_malware else None, on_record=collector.add)
    except malicious_feed.FeedUpdateError as exc:
        kept = "the cached feed" if malicious_feed.cache_path().is_file() else "the bundled feed"
        kept_advisories = "the cached feed" if advisory_feed.cache_path().is_file() else "the bundled records"
        click.echo(f"Malicious-release feed update failed: {exc}. Scans keep using {kept}.", err=True)
        click.echo(f"Advisory feed not rebuilt: it is read from the same downloads. Scans keep using "
                   f"{kept_advisories}.", err=True)
        sys.exit(EXIT_ERROR)
    counts = ", ".join(f"{source} {n:,}" for source, n in done.counts.items())
    click.echo(
        f"Malicious-release feed updated: {sum(done.counts.values()):,} entries ({counts}), "
        f"generated {done.generated_at}, written to {done.path}. GitHub: {done.github}."
    )
    try:
        written = collector.write()
    except (OSError, ValueError) as exc:
        kept = "the cached feed" if advisory_feed.cache_path().is_file() else "the bundled records"
        click.echo(f"Advisory feed update failed: {type(exc).__name__}: {exc}. Scans keep using {kept}.", err=True)
        failed = True
    else:
        per_registry = ", ".join(f"{registry} {n:,}" for registry, n in written.counts.items())
        click.echo(
            f"Advisory feed updated: {sum(written.counts.values()):,} entries for {written.packages:,} "
            f"packages ({per_registry}), {written.size / 1e6:.1f} MB, generated {written.generated_at}, "
            f"written to {written.path}."
        )
        if written.severity_floor:
            click.echo(
                f"The full advisory feed was {written.full_size / 1e6:.1f} MB, over the "
                f"{advisory_feed.MAX_FEED_BYTES / 1e6:.0f} MB limit, so it keeps only HIGH and CRITICAL "
                "advisories: a MEDIUM one is not reported."
            )
    if failed:
        sys.exit(EXIT_ERROR)
