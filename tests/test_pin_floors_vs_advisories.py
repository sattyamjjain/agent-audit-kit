"""Every release a bundled advisory lists, a version pin naming its package reports.

On 0.6.29 the langflow pin stopped at 1.12.0 while IBM's records of 29 Oct named
Langflow OSS 1.0.0 through 1.12.8 (CVE-2026-110186, CVSS 9.8), and nothing
failed: the advisory feed knew nothing of them, and no test compared a pin's
floor with what an advisory says. This test reads every OSV and NVD entry in the
bundled data/advisories.json against the `_Pin` rows naming its package, on
release triples as `_fires` reads a version, and fails when the advisory lists a
release at or above a row's floor that no row reports, unless the rule of a row
naming the package names the CVE: a disposition someone wrote down. It failed
on the tree that first bundled IBM's entries, while the langflow floor was still
1.12.0. Offline: the feed is the bundled file, never the cached one.
"""

from __future__ import annotations

import json
from typing import Iterator

import pytest

from agent_audit_kit import advisory_feed
from agent_audit_kit.malicious_feed import canonical_name
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners._versions import (
    TOP,
    ZERO,
    Spans,
    intersect,
    interval_spans,
    parse_version,
    subtract,
    union,
)
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _PINS, _fires, _Pin

_REGISTRY = {"py": "PyPI", "js": "npm"}


def _bundled() -> Iterator[advisory_feed.Advisory]:
    path = advisory_feed.BUNDLED_FEED
    feed = advisory_feed.parse_feed(json.loads(path.read_text(encoding="utf-8")), "bundled", path)
    for ecosystem in ("PyPI", "npm"):
        for name in sorted(feed.names(ecosystem)):
            yield from feed.advisories(ecosystem, name)


def _pins(ecosystem: str, name: str) -> list[_Pin]:
    key = canonical_name(ecosystem, name)
    return [pin for pin in _PINS
            if (pin.ecosystem is None or _REGISTRY.get(pin.ecosystem) == ecosystem)
            and any(canonical_name(ecosystem, n) == key for n in pin.names)]


def _reported(pins: list[_Pin]) -> Spans:
    """The releases the rows report, as `_fires` decides for a stated version."""
    pieces = []
    for pin in pins:
        low, high = pin.introduced or ZERO, TOP if pin.floor is None else pin.floor
        if low < high:
            pieces.append((low, high))
        pieces.extend(pin.also)
    return union(pieces)


def _unreported(advisory: advisory_feed.Advisory, pins: list[_Pin]) -> Spans:
    """What the advisory lists at or above a row's floor that no row reports."""
    floors = [pin.floor for pin in pins if pin.floor is not None]
    if not floors:
        return ()
    affected = interval_spans(((r.introduced, r.fixed, r.last_affected) for r in advisory.ranges),
                              advisory.versions)
    return intersect(subtract(affected, _reported(pins)), ((min(floors), TOP),))


def _pinned_advisories() -> list[tuple[advisory_feed.Advisory, list[_Pin]]]:
    return [(advisory, pins) for advisory in _bundled() if (pins := _pins(advisory.ecosystem, advisory.name))]


def test_the_bundled_feed_holds_advisories_a_pin_names() -> None:
    """Not vacuous: IBM's three langflow entries are pinned packages."""
    named = {(a.name, a.id) for a, _ in _pinned_advisories()}
    assert {("langflow", "CVE-2026-110186"), ("langflow", "CVE-2026-93680"),
            ("langflow", "CVE-2026-104339")} <= named


@pytest.mark.parametrize(("advisory", "pins"), _pinned_advisories(), ids=lambda v: getattr(v, "id", ""))
def test_a_pin_reports_every_release_a_bundled_advisory_lists(advisory: advisory_feed.Advisory,
                                                             pins: list[_Pin]) -> None:
    unreported = _unreported(advisory, pins)
    if not unreported:
        for row in advisory.ranges:  # the highest affected release, where the advisory names it
            last = parse_version(row.last_affected) if row.last_affected is not None else None
            if last is not None:
                assert any(_fires(pin, last) for pin in pins), (advisory.id, row.last_affected)
        return
    disposed = [pin.rule_id for pin in pins if any(cve in RULES[pin.rule_id].description for cve in advisory.cves)]
    floors = sorted({".".join(map(str, pin.floor)) for pin in pins if pin.floor is not None})
    assert disposed, (
        f"{advisory.label()} lists {advisory.ecosystem} `{advisory.name}` releases from "
        f"{'.'.join(map(str, unreported[0][0]))} that no pin reports (floors {', '.join(floors)}; "
        f"rules {', '.join(sorted({pin.rule_id for pin in pins}))}). Raise the floor to the release the "
        "vendor names as fixed, or name the CVE in the rule's description with the reason it stays."
    )


def test_the_langflow_floor_covers_ibm_s_records() -> None:
    """The case that made this test: through 1.12.8 is reported, 1.13.0 is not."""
    (pin,) = _pins("PyPI", "langflow")
    assert _fires(pin, (1, 12, 8)) and not _fires(pin, (1, 13, 0))
