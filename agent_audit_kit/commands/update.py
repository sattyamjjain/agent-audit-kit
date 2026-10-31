"""The ``update`` command: the vulnerability database and the two OSV feeds.

Moved out of ``cli.py`` (issue #701) when it learned to rebuild the malicious-release
feed, which took ``cli.py`` past the 1,300 lines ``tests/test_cli_scan_extraction.py``
holds it under. ``cli`` registers it with ``add_command``, as it does ``scan``. The
advisory feed AAK-KNOWN-VULN-001 reads is built from the same OSV exports, in the
same pass, so each is downloaded once.
"""

from __future__ import annotations

import sys
from collections import Counter
from typing import TYPE_CHECKING

import click

from agent_audit_kit import __version__
from agent_audit_kit.commands._common import EXIT_ERROR

if TYPE_CHECKING:
    from agent_audit_kit.advisory_feed import Collector

__all__ = ["update_cmd"]


def _github_token() -> str | None:
    """The token `--github-malware` pages GitHub with: GITHUB_TOKEN, else GH_TOKEN."""
    import os

    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value
    return None


def _nvd_api_key() -> str | None:
    """NVD_API_KEY, which raises NVD's rate limit; None reads without one."""
    import os

    return os.environ.get("NVD_API_KEY") or None


def _kept(collector: Collector) -> str:
    """Keep the NVD entries scans read now, and say which."""
    kept = collector.keep_cached_nvd()
    lists = [(kind, count, origin) for kind, count, origin in (("NVD", kept.nvd, kept.nvd_origin),
                                                                 ("launch", kept.launch, kept.launch_origin)) if origin]
    if not lists:
        return "no NVD entries, as neither the cached nor the bundled feed lists any"
    if len(lists) == 2 and lists[0][2] == lists[1][2]:
        return f"the {kept.nvd:,} NVD and {kept.launch:,} launch entries of the {kept.nvd_origin} feed"
    return " and ".join(f"the {count:,} {kind} entries of the {origin} feed" for kind, count, origin in lists)


#: How many of the CNA (vendor, product) pairs that mapped to nothing `aak update` prints.
_UNMAPPED_SHOWN = 10


def _unmapped_line(pairs: Counter[tuple[str, str]]) -> str:
    """The most frequent CNA (vendor, product) pairs no row mapped, so the map can
    grow from what NVD actually carries."""
    top = sorted(pairs.items(), key=lambda item: (-item[1], item[0]))[:_UNMAPPED_SHOWN]
    shown = "; ".join(f"{vendor or '?'} / {product or '?'} ({count:,})" for (vendor, product), count in top)
    return f"The CNA (vendor, product) pairs most often mapped to nothing: {shown}."


def _read_nvd(collector: Collector, nvd_days: int) -> bool:
    """Read NVD's CNA records into `collector`; False when the read failed.

    A failed or skipped read keeps the NVD entries scans read now
    (`Collector.keep_cached_nvd`), so it costs neither the OSV half nor them.
    """
    from agent_audit_kit import nvd_feed

    if nvd_days == 0:
        click.echo(f"NVD not read (--nvd-days 0): the advisory feed keeps {_kept(collector)}.")
        return True
    api_key = _nvd_api_key()
    click.echo(
        f"Reading NVD's records modified in the last {nvd_days} days for CNA version data "
        f"(2,000 a page{', with NVD_API_KEY' if api_key else '; set NVD_API_KEY to raise its rate limit'})..."
    )

    def progress(done: int, expected: int) -> None:
        if done % 10 == 0 or done == expected:
            click.echo(f"  NVD: page {done:,} of {expected:,}")

    try:
        fetched = nvd_feed.fetch(nvd_days, api_key=api_key, progress=progress)
    except nvd_feed.NvdUpdateError as exc:
        click.echo(f"NVD read failed: {exc}. The advisory feed is rebuilt from OSV and keeps "
                   f"{_kept(collector)}.", err=True)
        return False
    collector.add_nvd(fetched.entries, fetched.window)
    tally = fetched.tally
    launch = sum(1 for entry in fetched.entries if "match" in entry)
    click.echo(
        f"NVD: {tally.records:,} records modified {fetched.window['start'][:10]} to {fetched.window['end'][:10]}. "
        f"{tally.with_cna:,} carry CNA version data: {tally.mapped:,} name a PyPI or npm package or software a "
        f"launch row lists ({len(fetched.entries) - launch:,} package and {launch:,} launch entries), "
        f"{tally.unmapped:,} name none that maps and are dropped, "
        f"{tally.no_range:,} map but state no version range that can be read. {tally.no_cna:,} carry none "
        f"(NVD's CPE data alone is not read), and {tally.rejected:,} are rejected."
    )
    if tally.unmapped_pairs:
        click.echo(_unmapped_line(tally.unmapped_pairs))
    return True


@click.command("update")
@click.version_option(version=__version__)
@click.option(
    "--github-malware",
    is_flag=True,
    help="Also add GitHub's malware advisories for npm and pip to the feed. Needs "
         "GITHUB_TOKEN or GH_TOKEN, and takes about 1,200 API requests.",
)
@click.option(
    "--nvd-days",
    type=click.IntRange(0, 120),
    default=120,
    show_default=True,
    help="Also read the CNA version data of NVD records modified in the last N days into the "
         "advisory feed, for CVEs OSV has no package record of (at most 120, NVD's window; about "
         "20 minutes and 200 MB for 120 days). 0 keeps the NVD entries cached before. Uses "
         "NVD_API_KEY when it is set.",
)
def update_cmd(github_malware: bool, nvd_days: int) -> None:
    """Update the vulnerability database, the malicious-release feed and the advisory feed.

    Both feeds are rebuilt from OSV's exports for PyPI and npm (about 260 MB,
    downloaded once): the malicious-package records, plus GitHub's malware
    advisories with --github-malware, and every other advisory record. The
    advisory feed also takes NVD's records of CNA version data for CVEs OSV
    has no package record of (--nvd-days). Scans never fetch them; they read
    the copies this writes, else the bundled ones. Any failure keeps what was
    cached before and exits non-zero.
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
    if not _read_nvd(collector, nvd_days):
        failed = True
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
            f"written to {written.path}. NVD CNA records: {written.nvd:,} package and {written.launch:,} launch "
            f"entries, "
            f"{written.nvd_twins:,} more dropped because OSV already lists their CVE."
        )
        if written.severity_floor:
            click.echo(
                f"The full advisory feed was {written.full_size / 1e6:.1f} MB, over the "
                f"{advisory_feed.MAX_FEED_BYTES / 1e6:.0f} MB limit, so it keeps only HIGH and CRITICAL "
                "advisories: a MEDIUM one is not reported."
            )
    if failed:
        sys.exit(EXIT_ERROR)
