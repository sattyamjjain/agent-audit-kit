"""F2 — `aak watch` CVE-feed daemon.

Polls disclosed-CVE feeds (OX timeline, CERT/CC, ThaiCERT advisories,
IronPlate weekly intel) and surfaces entries that AAK does not yet
cover. The daemon is intentionally minimal — fetch, dedupe, dispatch
— so a downstream operator can wire it into Slack / a webhook / a
GitHub-issue creator without taking on a heavyweight runtime.

`run_watch(feed_ids, emit, interval_seconds, max_iterations, dry_run)`
is the entry point. Unknown feed IDs are skipped with a stderr
warning. Each iteration:

    1. Fetch the feed (cached, ETag-aware once a real feed lands).
    2. Diff against the local "seen" set in
       `~/.agent-audit-kit/watch-state.json`.
    3. For every new entry without an AAK rule mapping, emit a
       notification (or, in dry-run, print the body to stdout).

This v0.3.10 ship includes the framework + an in-process stub for
each feed. Wiring real fetchers (OX RSS, NVD JSON) lands in v0.3.11
behind the same interface.
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
    """Placeholder fetcher. Returns empty until a feed-specific fetcher
    lands in v0.3.11 (real OX RSS / NVD JSON / IronPlate pull).

    Tests inject a mock via FEED_REGISTRY override.
    """
    return []


FEED_REGISTRY: dict[str, Callable[[str], list[dict[str, Any]]]] = {
    "ox": _stub_fetcher,
    "cert-cc": _stub_fetcher,
    "thaicert": _stub_fetcher,
    "ironplate": _stub_fetcher,
}


def _emit(target: str | None, payload: dict[str, Any], *, dry_run: bool) -> None:
    if dry_run or target is None:
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        sys.stdout.flush()
        return
    # Real sinks ship in v0.3.11. For now, log to stderr so consumers
    # know the daemon isn't silently dropping events.
    sys.stderr.write(
        f"[aak watch] sink {target!r} not yet implemented; payload follows:\n"
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
) -> int:
    """Run the watch loop. Returns 0 on clean exit."""
    state = _load_state()
    seen: set[str] = set(state.get("seen", []) or [])
    iteration = 0
    try:
        while True:
            iteration += 1
            for feed_id in feed_ids:
                fetcher = FEED_REGISTRY.get(feed_id)
                if fetcher is None:
                    sys.stderr.write(f"[aak watch] unknown feed: {feed_id}\n")
                    continue
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
