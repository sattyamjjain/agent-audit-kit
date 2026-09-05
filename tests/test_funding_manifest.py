"""The FLOSS/fund manifest must stay valid, and must stay published.

`.well-known/funding-manifest-urls` names exactly one URL, and FLOSS/fund
requires that URL to return 200 with a schema-valid document. Two things can
break that quietly and neither shows up anywhere else:

* the manifest drifting out of schema, or naming a URL whose hostname differs
  from the manifest's own without the `wellKnown` proof-of-control pointer that
  the schema conditionally requires; and
* the deploy step that copies it into the published site being removed. gh-pages
  is rebuilt by `git init` + `git push --force` on every snapshot, so the file
  exists on the site only for as long as something explicitly stages it. Drop
  that line and the URL goes back to 404 on the next Monday with no failure
  anywhere.

Offline by construction: the schema constraints that matter are re-implemented
here as assertions rather than fetched, so this fails on a bad edit rather than
on a network blip.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
POINTER = REPO_ROOT / ".well-known" / "funding-manifest-urls"
MANIFEST = REPO_ROOT / "funding.json"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "mcp-security-index.yml"


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _declared_url() -> str:
    raw = POINTER.read_text(encoding="utf-8").splitlines()
    lines = [line.strip() for line in raw if line.strip()]
    assert len(lines) == 1, f"the pointer must name exactly one URL, found {len(lines)}"
    return lines[0]


# ---------------------------------------------------------------------------
# The pointer and the manifest have to agree
# ---------------------------------------------------------------------------

def test_pointer_names_one_https_url() -> None:
    url = _declared_url()
    assert url.startswith("https://"), url


def test_the_declared_url_ends_at_the_manifest_filename() -> None:
    """The pointer is what a fund crawler fetches. If it names a path this repo
    does not publish, the whole mechanism is decorative."""
    assert _declared_url().endswith("/funding.json")


def test_manifest_is_valid_json_with_the_required_top_level_keys() -> None:
    doc = _manifest()
    for key in ("version", "entity", "funding"):
        assert key in doc, f"schema requires {key!r}"
    assert doc["$schema"].startswith("https://floss.fund/schema/v1.0.0/")


def test_entity_carries_every_required_field() -> None:
    ent = _manifest()["entity"]
    for key in ("type", "role", "name", "email", "description", "webpageUrl"):
        assert ent.get(key), f"entity.{key} is required and must be non-empty"
    assert ent["type"] in {"individual", "group", "organisation", "other"}
    assert ent["role"] in {"owner", "steward", "maintainer", "contributor", "other"}


def test_project_carries_every_required_field() -> None:
    proj = _manifest()["projects"][0]
    for key in ("guid", "name", "description", "webpageUrl",
                "repositoryUrl", "licenses", "tags"):
        assert proj.get(key), f"projects[].{key} is required and must be non-empty"
    assert len(proj["licenses"]) <= 5
    assert len(proj["tags"]) <= 10


def test_every_plan_references_a_declared_channel() -> None:
    """A plan naming a channel guid that does not exist is payable to nothing."""
    funding = _manifest()["funding"]
    declared = {c["guid"] for c in funding["channels"]}
    for plan in funding["plans"]:
        missing = set(plan["channels"]) - declared
        assert not missing, f"plan {plan['guid']} references undeclared {missing}"


# ---------------------------------------------------------------------------
# The conditional wellKnown rule -- the one that silently fails validation
# ---------------------------------------------------------------------------

def test_cross_host_urls_carry_a_wellknown_pointer() -> None:
    """The schema requires `wellKnown` on any URL whose hostname differs from
    the manifest's own, as proof the publisher may solicit for that URL.

    This is the rule that bit on the first draft: an entity webpage on
    github.com cannot be proven, because serving
    `https://github.com/.well-known/funding-manifest-urls` is not something
    this project can do. Same-host URLs are the way out, and repositoryUrl --
    which is github.com by definition -- carries the repo-file pointer instead.
    """
    doc = _manifest()
    host = urlparse(_declared_url()).hostname

    def check(label: str, node: dict) -> None:
        node_host = urlparse(node["url"]).hostname
        if node_host != host:
            assert node.get("wellKnown"), (
                f"{label} is on {node_host}, not {host}, so the schema requires "
                f"a wellKnown proof-of-control URL"
            )
            assert node["wellKnown"].endswith("/.well-known/funding-manifest-urls")

    check("entity.webpageUrl", doc["entity"]["webpageUrl"])
    for proj in doc["projects"]:
        check("projects[].webpageUrl", proj["webpageUrl"])
        check("projects[].repositoryUrl", proj["repositoryUrl"])


def test_the_repo_wellknown_pointer_targets_this_repository() -> None:
    """The proof-of-control file is the one committed at .well-known/ here."""
    wk = _manifest()["projects"][0]["repositoryUrl"]["wellKnown"]
    assert "sattyamjjain/agent-audit-kit" in wk
    assert POINTER.is_file(), "the file the pointer promises must exist"


# ---------------------------------------------------------------------------
# It has to stay published
# ---------------------------------------------------------------------------

def test_the_deploy_stages_the_manifest() -> None:
    """gh-pages is `git init` + `git push --force` on every snapshot, so the
    manifest lives on the site only while this line survives. Without it the
    URL 404s again on the next Monday and nothing anywhere fails."""
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "cp funding.json pages_staging/funding.json" in text, (
        "mcp-security-index.yml no longer stages funding.json into gh-pages"
    )


def test_the_manifest_is_not_left_only_on_gh_pages() -> None:
    """It must be in the source tree, because the deploy copies from here."""
    assert MANIFEST.is_file(), "funding.json must live in the repo root"
