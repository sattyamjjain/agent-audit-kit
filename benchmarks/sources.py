"""MCP-server discovery sources beyond the GitHub code-search crawler.

Closes C7–C10 from the pending-items audit.

Provides four additional sources the main crawler can merge in:
1. anthropics/claude-plugins-official — Anthropic's curated marketplace
   (fetched via the GitHub REST API, repo-contents listing).
2. claudemarketplaces.com — public index of community marketplaces.
3. aitmpl.com — AI template registry.
4. buildwithclaude.com — community projects + plugins directory.

Each source function returns a list of ServerEntry dataclasses with the
same shape so the existing benchmarks/crawler.py can merge them into its
results pipeline.

Network is optional: if a site is unreachable or rate-limited, the
source returns an empty list (logged on stderr) rather than raising.
This keeps the weekly `mcp-security-index.yml` workflow resilient.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class ServerEntry:
    """A discovered MCP server / plugin, regardless of source."""
    source: str              # "github", "anthropic-official", "cmps", "aitmpl", "bwc"
    repo: str                # e.g. "getsentry/spotlight" when it maps to a GH repo
    name: str                # human-readable name
    url: str = ""            # upstream URL (repo or home page)
    category: str = ""       # if the marketplace reports a category
    description: str = ""
    # For sources that provide a direct MCP config URL, include it so the
    # crawler doesn't need to re-discover the file.
    raw_config_url: str = ""
    extra: dict = field(default_factory=dict)


_USER_AGENT = "agent-audit-kit mcp-security-index/0.3"


def _fetch_json(url: str, headers: dict[str, str] | None = None, timeout: int = 20) -> dict | list | None:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": _USER_AGENT, **(headers or {})},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        sys.stderr.write(f"sources: fetch {url} failed: {exc}\n")
        return None


def _fetch_text(url: str, timeout: int = 20) -> str | None:
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": _USER_AGENT}, method="GET"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError) as exc:
        sys.stderr.write(f"sources: fetch {url} failed: {exc}\n")
        return None


# ---------------------------------------------------------------------------
# 1. Anthropic's official marketplace (github.com/anthropics/claude-plugins-official)
# ---------------------------------------------------------------------------


def anthropic_official(limit: int = 100) -> list[ServerEntry]:
    """Fetch plugin entries from anthropics/claude-plugins-official.

    Walks the repo's top-level directories via the GitHub contents API.
    Requires GITHUB_TOKEN env for reasonable rate limits; without it,
    caps at 60 req/h (usually enough for this repo).
    """
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    root = _fetch_json(
        "https://api.github.com/repos/anthropics/claude-plugins-official/contents",
        headers=headers,
    )
    if not isinstance(root, list):
        return []

    entries: list[ServerEntry] = []
    for item in root[:limit]:
        if item.get("type") != "dir":
            continue
        name = item.get("name", "")
        entries.append(
            ServerEntry(
                source="anthropic-official",
                repo="anthropics/claude-plugins-official",
                name=name,
                url=item.get("html_url", ""),
                raw_config_url=f"https://raw.githubusercontent.com/anthropics/claude-plugins-official/main/{name}/.mcp.json",
            )
        )
    return entries


# ---------------------------------------------------------------------------
# 2. claudemarketplaces.com — public index
# ---------------------------------------------------------------------------


_CMPS_HOME = "https://claudemarketplaces.com"
_CMPS_LINK_RE = re.compile(
    r'href="(?P<url>https://github\.com/(?P<repo>[\w.\-]+/[\w.\-]+))"',
    re.IGNORECASE,
)


def claudemarketplaces(limit: int = 200) -> list[ServerEntry]:
    """Scrape marketplace listings from claudemarketplaces.com.

    The site publishes GitHub repo links in href attributes. We parse
    those — no JSON feed is advertised. If/when the site adds one we'll
    prefer that path.
    """
    html = _fetch_text(_CMPS_HOME)
    if html is None:
        return []
    seen: set[str] = set()
    entries: list[ServerEntry] = []
    for match in _CMPS_LINK_RE.finditer(html):
        repo = match.group("repo")
        if repo in seen:
            continue
        if repo.startswith("sponsors/") or "." in repo.split("/")[0]:
            continue
        seen.add(repo)
        entries.append(
            ServerEntry(
                source="cmps",
                repo=repo,
                name=repo,
                url=f"https://github.com/{repo}",
            )
        )
        if len(entries) >= limit:
            break
    return entries


# ---------------------------------------------------------------------------
# 3. aitmpl.com — AI template registry
# ---------------------------------------------------------------------------


_AITMPL_HOME = "https://aitmpl.com"
_AITMPL_REPO_RE = re.compile(
    r'https://github\.com/(?P<repo>[\w.\-]+/[\w.\-]+)',
    re.IGNORECASE,
)


def aitmpl(limit: int = 200) -> list[ServerEntry]:
    """Scrape template listings from aitmpl.com."""
    html = _fetch_text(_AITMPL_HOME)
    if html is None:
        return []
    seen: set[str] = set()
    entries: list[ServerEntry] = []
    for match in _AITMPL_REPO_RE.finditer(html):
        repo = match.group("repo")
        if repo in seen or repo.startswith("sponsors/"):
            continue
        seen.add(repo)
        entries.append(
            ServerEntry(
                source="aitmpl",
                repo=repo,
                name=repo,
                url=f"https://github.com/{repo}",
            )
        )
        if len(entries) >= limit:
            break
    return entries


# ---------------------------------------------------------------------------
# 4. buildwithclaude.com — community projects + plugins
# ---------------------------------------------------------------------------


_BWC_HOME = "https://buildwithclaude.com"


def buildwithclaude(limit: int = 200) -> list[ServerEntry]:
    """Scrape project listings from buildwithclaude.com."""
    html = _fetch_text(_BWC_HOME)
    if html is None:
        return []
    seen: set[str] = set()
    entries: list[ServerEntry] = []
    for match in _AITMPL_REPO_RE.finditer(html):
        repo = match.group("repo")
        if repo in seen or repo.startswith("sponsors/"):
            continue
        seen.add(repo)
        entries.append(
            ServerEntry(
                source="bwc",
                repo=repo,
                name=repo,
                url=f"https://github.com/{repo}",
            )
        )
        if len(entries) >= limit:
            break
    return entries


# ---------------------------------------------------------------------------
# Merge helper
# ---------------------------------------------------------------------------


SOURCES: dict[str, Callable[[int], list[ServerEntry]]] = {
    "anthropic-official": anthropic_official,
    "cmps": claudemarketplaces,
    "aitmpl": aitmpl,
    "bwc": buildwithclaude,
}


def collect_all(limit_per_source: int = 200) -> list[ServerEntry]:
    """Fan out to every source; deduplicate by (repo or name)."""
    out: list[ServerEntry] = []
    seen: set[str] = set()
    for name, fn in SOURCES.items():
        try:
            for entry in fn(limit_per_source):
                key = entry.repo or entry.name
                if key in seen:
                    continue
                seen.add(key)
                out.append(entry)
        except Exception as exc:  # noqa: BLE001 — one bad source mustn't kill the rest
            sys.stderr.write(f"sources.{name}: crashed with {type(exc).__name__}: {exc}\n")
    return out
