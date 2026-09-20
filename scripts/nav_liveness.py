"""Check every `nav:` entry in mkdocs.yml against the deployed site.

`description-liveness.yml` established the pattern this follows: some claims can
only be settled by asking the network, and a claim nothing asks about decays
quietly. The nav is one of them. A page can be listed in `mkdocs.yml`, build
locally, and still 404 for every reader — because the deploy did not run, because
it ran and dropped a file, or because the page was renamed in one place only.

The gap this was written for was the inverse and worse: `mkdocs.yml` carried a
23-entry nav that no workflow deployed at all for a period, and nothing failed,
because nothing compared the nav to the site. Building the docs proves the
markdown parses. Only a request proves a reader can reach it.

Deliberately *not* a link checker. lychee already walks the prose links inside
pages. This asks a narrower question with a sharper answer: is every page the
navigation offers actually served?

Usage:
    python scripts/nav_liveness.py --list          # print the URLs, one per line
    python scripts/nav_liveness.py --check-live    # request each; non-200 fails
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MKDOCS_YML = REPO_ROOT / "mkdocs.yml"
HOOKS_PY = REPO_ROOT / "scripts" / "mkdocs_hooks.py"

_TIMEOUT = 30
_RETRIES = 3
# A plain urllib request is answered with 403 by some CDNs; GitHub Pages does
# not care, but saying who we are costs nothing and makes the logs legible.
_UA = "agent-audit-kit-nav-liveness/1.0 (+https://github.com/sattyamjjain/agent-audit-kit)"

_NAV_ENTRY_RE = re.compile(r":\s*([A-Za-z0-9_\-./]+\.md)\s*$", re.M)
_SITE_URL_RE = re.compile(r"^site_url:\s*(\S+)\s*$", re.M)
_DIRECTORY_URLS_RE = re.compile(r"^use_directory_urls:\s*(\S+)\s*$", re.M)


def _nav_block(text: str) -> str:
    """The `nav:` block of mkdocs.yml, as raw lines.

    Read textually rather than with a YAML parser so this script has no
    dependency beyond the standard library: the workflow that runs it does not
    install MkDocs, and a liveness check that needs the thing it is checking to
    be installed is a worse check.
    """
    out: list[str] = []
    inside = False
    for line in text.splitlines(keepends=True):
        if line.startswith("nav:"):
            inside = True
            continue
        if inside and line.strip() and not line.startswith((" ", "\t")):
            break
        if inside:
            out.append(line)
    return "".join(out)


def nav_sources(text: str | None = None) -> list[str]:
    """Every markdown file referenced by the nav, in nav order."""
    if text is None:
        text = MKDOCS_YML.read_text(encoding="utf-8")
    return _NAV_ENTRY_RE.findall(_nav_block(text))


def site_url(text: str | None = None) -> str:
    """The deployed base URL, from mkdocs.yml's own `site_url`."""
    if text is None:
        text = MKDOCS_YML.read_text(encoding="utf-8")
    match = _SITE_URL_RE.search(text)
    if not match:
        raise SystemExit(
            "nav_liveness: mkdocs.yml has no site_url, so there is no deployed "
            "address to check against. Set it rather than hardcoding one here."
        )
    return match.group(1).rstrip("/") + "/"


def _use_directory_urls(text: str) -> bool:
    match = _DIRECTORY_URLS_RE.search(text)
    return match.group(1).strip().lower() != "false" if match else True


def source_to_url(source: str, base: str, directory_urls: bool = True) -> str:
    """Map a nav markdown path to the URL MkDocs publishes it at."""
    if not directory_urls:
        return base + source[:-3] + ".html"
    if source == "index.md" or source.endswith("/index.md"):
        return base + source[: -len("index.md")]
    return base + source[:-3] + "/"


def nav_urls(text: str | None = None) -> list[str]:
    """Every nav entry as a deployed URL."""
    if text is None:
        text = MKDOCS_YML.read_text(encoding="utf-8")
    base = site_url(text)
    directory_urls = _use_directory_urls(text)
    return [source_to_url(s, base, directory_urls) for s in nav_sources(text)]


def published_asset_urls(base: str | None = None) -> list[str]:
    """The hook's published files that are NOT nav pages, as URLs.

    The PDF, `results.json`, the baseline snapshot and the two Black Hat
    abstracts are linked from docs pages and cited off-site, but they are not in
    the nav, so the nav walk alone would not see them. link-check.yml excludes
    this site's `/docs/` subtree from lychee on the grounds that this job covers
    it — that is only true if "this job" covers the assets as well as the pages.

    `PUBLISHED_FILES` is read out of `scripts/mkdocs_hooks.py` with `ast` rather
    than imported, because importing it pulls in MkDocs and this script is
    deliberately standard-library only.
    """
    if base is None:
        base = site_url()
    if not HOOKS_PY.is_file():
        return []
    tree = ast.parse(HOOKS_PY.read_text(encoding="utf-8"))
    names: list[str] = []
    research_dir = ""
    for node in ast.walk(tree):
        # PUBLISHED_FILES carries a type annotation, so it parses as AnnAssign
        # rather than Assign. Handle both or the walk silently finds nothing —
        # which would make this half of the check quietly vacuous.
        if isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        elif isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        else:
            continue
        for target in targets:
            if not isinstance(target, ast.Name) or value is None:
                continue
            if target.id == "RESEARCH_DIR" and isinstance(value, ast.Constant):
                research_dir = str(value.value)
            elif target.id == "PUBLISHED_FILES" and isinstance(value, ast.Tuple):
                names = [
                    e.value for e in value.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                ]
    if not research_dir or not names:
        return []
    nav = set(nav_sources())
    out = []
    for name in names:
        rel = f"{research_dir}/{name}"
        if rel in nav:  # already walked as a page
            continue
        out.append(base + (rel[:-3] + "/" if rel.endswith(".md") else rel))
    return out


def probe(url: str) -> tuple[int, str]:
    """Request `url`, returning (status, detail). Status 0 means no response."""
    last = ""
    for attempt in range(_RETRIES):
        request = urllib.request.Request(url, headers={"User-Agent": _UA})
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
                return response.status, ""
        except urllib.error.HTTPError as exc:
            # A 4xx is an answer, not a flake: report it without retrying.
            return exc.code, exc.reason or ""
        except Exception as exc:  # network/DNS/TLS - worth one more try
            last = f"{type(exc).__name__}: {exc}"
            if attempt == _RETRIES - 1:
                return 0, last
    return 0, last


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list", action="store_true", help="print the nav URLs")
    mode.add_argument(
        "--check-live", action="store_true", help="request each; non-200 fails"
    )
    args = parser.parse_args(argv)

    urls = nav_urls() + published_asset_urls()
    if not urls:
        print(
            "nav_liveness: parsed zero nav entries from mkdocs.yml. Either the "
            "nav is empty or this parser stopped matching it — both make the "
            "check vacuous, so this is a failure, not a pass.",
            file=sys.stderr,
        )
        return 1

    if args.list:
        print("\n".join(urls))
        return 0

    failures: list[tuple[str, int, str]] = []
    for url in urls:
        status, detail = probe(url)
        if status != 200:
            failures.append((url, status, detail))
        print(f"{status or 'ERR':>4}  {url}")

    if failures:
        print(
            f"\nnav_liveness: {len(failures)} of {len(urls)} nav entries are not "
            f"served:",
            file=sys.stderr,
        )
        for url, status, detail in failures:
            suffix = f" ({detail})" if detail else ""
            print(f"  {status or 'no response'}  {url}{suffix}", file=sys.stderr)
        print(
            "\nEvery one of these is offered to a reader by the site navigation. "
            "Either the deploy did not publish it or the nav names a page that no "
            "longer exists.",
            file=sys.stderr,
        )
        return 1

    print(
        f"\nnav liveness: all {len(urls)} published URLs return 200 "
        f"({len(nav_urls())} nav pages + {len(published_asset_urls())} assets)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
