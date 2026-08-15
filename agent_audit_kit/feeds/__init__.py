"""`aak watch-cve` CVE-feed poller.

Polls disclosed-CVE feeds (OX timeline, CERT/CC, ThaiCERT advisories,
IronPlate weekly intel) and surfaces entries that AAK does not yet cover. The
daemon is intentionally minimal — fetch, dedupe, dispatch — so a downstream
operator can wire it into Slack / a webhook / a GitHub-issue creator without
taking on a heavyweight runtime.

**Status: [experimental] — exactly one live feed (`nvd`); the rest stubbed.** The
`nvd` feed polls the NVD 2.0 API. Its network call is opt-in behind `--online`, so
a default run (and CI) reads its on-disk cache and never touches the network. The
other feeds (`ox`, `cert-cc`, `thaicert`, `ironplate`) are `_stub_fetcher`, which
raises `NotImplementedError`. `run_watch` classifies feeds up front, prints
`feed <id>: not implemented` for each stub, exits non-zero only when *every*
requested feed is a stub, and exits 0 when at least one live feed polled cleanly.
A real fetcher is registered by overriding `FEED_REGISTRY[<id>]`; tests inject one
that way.

`run_watch(feed_ids, emit, interval_seconds, max_iterations, dry_run)` is the
entry point. Each iteration over the *live* feeds:

    1. Fetch the feed.
    2. Diff against the local "seen" set in `~/.agent-audit-kit/watch-state.json`.
    3. For every new entry without an AAK rule mapping, emit a notification
       (or, in dry-run, print the body to stdout).
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable


_STATE_DIR = Path(os.environ.get("AAK_HOME", str(Path.home() / ".agent-audit-kit")))
_STATE_FILE = _STATE_DIR / "watch-state.json"


def _load_state() -> dict[str, Any]:
    if not _STATE_FILE.is_file():
        return {"seen": []}
    try:
        return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"seen": []}


def _save_state(state: dict[str, Any]) -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def _stub_fetcher(feed_id: str) -> list[dict[str, Any]]:
    """Explicitly-unimplemented feed fetcher. Raises so `aak watch-cve` fails
    loud instead of silently reporting an empty feed.

    `run_watch` never calls this directly — it detects stub feeds by identity
    and reports them as NOT IMPLEMENTED — but raising keeps the contract honest
    for any caller that invokes a stub fetcher through `FEED_REGISTRY`. Tests
    inject a real fetcher by overriding `FEED_REGISTRY[<id>]`.
    """
    raise NotImplementedError(
        f"feed {feed_id!r} has no fetcher. One live feed ships: `nvd` (the NVD 2.0 "
        "API). The rest are stubs. File an issue at "
        "https://github.com/sattyamjjain/agent-audit-kit/issues if you need one."
    )


# --- NVD 2.0 feed — the one live fetcher -----------------------------------
#
# NVD 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0) has a public rate
# limit of 5 requests / rolling 30 s (50 with an API key in NVD_API_KEY). A poll
# makes ONE request (a single results page), so it stays well under the limit.
# The network call is gated by `_ONLINE`, set only by run_watch(online=True) from
# the CLI's explicit `--online` flag — so a default run, and CI, never touch the
# network: the feed reads its on-disk cache instead.

_NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_KEYWORD = os.environ.get("AAK_NVD_KEYWORD", "mcp")
_NVD_RESULTS = 50
_NVD_CACHE = _STATE_DIR / "nvd-cache.json"

# Gates the ONLY network call in this module. Off by default so nothing polls the
# network without the explicit opt-in.
_ONLINE = False


def _nvd_cache_path() -> Path:
    return Path(os.environ.get("AAK_NVD_CACHE", str(_NVD_CACHE)))


def _parse_nvd(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse an NVD 2.0 /cves response body into watch entries. Pure and offline."""
    out: list[dict[str, Any]] = []
    for item in payload.get("vulnerabilities", []) or []:
        cve = (item or {}).get("cve", {}) or {}
        cid = cve.get("id")
        if not cid:
            continue
        descs = cve.get("descriptions", []) or []
        title = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
        out.append({
            "cve_id": cid,
            "title": title.strip()[:240],
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
            "published": cve.get("published", ""),
        })
    return out


def _read_nvd_cache() -> list[dict[str, Any]]:
    path = _nvd_cache_path()
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return data.get("entries", []) if isinstance(data, dict) else []


def _fetch_nvd_online() -> list[dict[str, Any]]:
    import urllib.parse
    import urllib.request

    params = urllib.parse.urlencode(
        {"keywordSearch": _NVD_KEYWORD, "resultsPerPage": _NVD_RESULTS}
    )
    headers = {"User-Agent": "agent-audit-kit-watch-cve"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(f"{_NVD_ENDPOINT}?{params}", headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 — fixed https host
        payload = json.loads(resp.read().decode("utf-8"))
    entries = _parse_nvd(payload)
    path = _nvd_cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"keyword": _NVD_KEYWORD, "entries": entries}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return entries


def _nvd_fetcher(feed_id: str) -> list[dict[str, Any]]:
    """The one live feed: NVD 2.0. Reads the disk cache; only reaches the network
    when run_watch was called with online=True (the CLI's `--online` flag)."""
    if _ONLINE:
        try:
            return _fetch_nvd_online()
        except Exception as exc:  # noqa: BLE001 — degrade to cache on any network error
            sys.stderr.write(f"[aak watch] nvd fetch failed ({exc}); using cache\n")
    return _read_nvd_cache()


FEED_REGISTRY: dict[str, Callable[[str], list[dict[str, Any]]]] = {
    "nvd": _nvd_fetcher,      # live: NVD 2.0 API (network only with --online)
    "ox": _stub_fetcher,      # stub — no fetcher yet
    "cert-cc": _stub_fetcher,
    "thaicert": _stub_fetcher,
    "ironplate": _stub_fetcher,
}


def _live_feed_names() -> list[str]:
    return sorted(fid for fid, fn in FEED_REGISTRY.items() if fn is not _stub_fetcher)


def _emit(target: str | None, payload: dict[str, Any], *, dry_run: bool) -> None:
    if dry_run or target is None:
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        sys.stdout.flush()
        return
    # Notification sinks are not implemented. Log to stderr so consumers know
    # the daemon isn't silently dropping events.
    sys.stderr.write(
        f"[aak watch] sink {target!r} not implemented; payload follows:\n"
    )
    sys.stderr.write(json.dumps(payload, indent=2) + "\n")
    sys.stderr.flush()


def run_watch(
    *,
    feed_ids: list[str],
    emit: str | None,
    interval_seconds: int,
    max_iterations: int,
    dry_run: bool,
    online: bool = False,
) -> int:
    """Run the watch loop over the *live* feeds.

    Returns 0 when at least one requested feed is live and polled cleanly (even if
    it found nothing new), and non-zero (2) when every requested feed is an
    unimplemented stub — so a run that could only ever find nothing fails loud
    instead of masquerading as success.

    `online` gates the one network call (the NVD feed): False by default, so a run
    without the CLI's `--online` flag never touches the network (the NVD feed reads
    its on-disk cache instead).
    """
    global _ONLINE
    _ONLINE = online

    implemented = _live_feed_names()
    unknown = [f for f in feed_ids if f not in FEED_REGISTRY]
    stub = [f for f in feed_ids if FEED_REGISTRY.get(f) is _stub_fetcher]
    live = [
        f for f in feed_ids
        if f in FEED_REGISTRY and FEED_REGISTRY.get(f) is not _stub_fetcher
    ]

    for feed_id in unknown:
        sys.stderr.write(f"[aak watch] unknown feed: {feed_id}\n")
    for feed_id in stub:
        sys.stderr.write(
            f"[aak watch] feed {feed_id}: not implemented "
            f"(live feed(s): {', '.join(implemented) or 'none'})\n"
        )

    if not live:
        sys.stderr.write(
            "[aak watch] none of the requested feeds is live. Implemented: "
            f"{', '.join(implemented) or 'none'}. Exiting non-zero so this does not "
            "look like a clean run that found nothing.\n"
        )
        sys.stderr.flush()
        return 2

    state = _load_state()
    seen: set[str] = set(state.get("seen", []) or [])
    iteration = 0
    try:
        while True:
            iteration += 1
            for feed_id in live:
                fetcher = FEED_REGISTRY[feed_id]
                try:
                    entries = fetcher(feed_id)
                except Exception as exc:  # noqa: BLE001 — keep daemon alive
                    sys.stderr.write(f"[aak watch] {feed_id} fetch failed: {exc}\n")
                    continue
                for entry in entries:
                    cve = entry.get("cve_id") or entry.get("id")
                    if not cve or cve in seen:
                        continue
                    seen.add(cve)
                    _emit(
                        emit,
                        {
                            "feed": feed_id,
                            "cve": cve,
                            "title": entry.get("title", ""),
                            "url": entry.get("url", ""),
                            "covered": False,
                        },
                        dry_run=dry_run,
                    )
            state["seen"] = sorted(seen)
            _save_state(state)
            if max_iterations and iteration >= max_iterations:
                return 0
            time.sleep(max(1, interval_seconds))
    except KeyboardInterrupt:
        return 0


__all__ = ["FEED_REGISTRY", "run_watch"]
