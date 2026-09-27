#!/usr/bin/env python3
"""Render the GitHub repo description from ``RULE_COUNT``.

Reads ``.github/repo-metadata.yml``'s ``description_template`` and substitutes the
live ``agent_audit_kit.RULE_COUNT`` into it, printing the final string to stdout.
This is the machine-readable source of truth for the repo description so the count
on github.com can never drift from the code again (it drifted to 271 while the code
said 274).

Dependency-free on purpose (no PyYAML): the template is a single ``>-`` folded
block scalar, which we fold by hand so this runs in any clean checkout.

    python scripts/render_repo_metadata.py

We do NOT write the description to GitHub from here — that needs repo-admin rights a
CI token does not have. Paste the printed string into repo Settings when RULE_COUNT
changes (CONTRIBUTING.md "Release checklist").

``--check-live`` compares github.com's live description against this rendering and
exits 1 on drift. release.yml and description-liveness.yml both call it, so there is
one implementation of the comparison rather than a copy in each workflow — and the
scheduled caller is the one that matters, because the release-time check can only
notice drift during a release. The description sat one rule stale from 2026-08-31
until 2026-09-01 for exactly that reason: 0.3.91 never released, so the only thing
that would have looked never ran.

``make count-check`` is the third caller. On 2026-09-27 two reads of the description
disagreed (332 rules from the API, 362 on a rendered page) and no local check could
say which one matched the code. It reads with ``gh repo view --json description``, the
command a person uses to check by hand. Where gh is missing or holds no credentials
(CI's ``counts`` job has no token), the comparison is skipped and the output says so.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_METADATA = _REPO / ".github" / "repo-metadata.yml"


def load_description_template(text: str) -> str:
    """Extract the ``description_template`` ``>-`` folded block scalar, folded.

    A ``>-`` scalar folds each run of non-empty, more-indented lines into a single
    space-joined line and chomps the trailing newline — which for a one-paragraph
    template is exactly ``" ".join(stripped_non_empty_lines)``.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.match(r"^description_template:\s*>-\s*$", line):
            block: list[str] = []
            for cont in lines[i + 1:]:
                if cont.strip() == "":
                    break
                if not cont.startswith((" ", "\t")):  # dedent ends the block
                    break
                block.append(cont.strip())
            if not block:
                break
            return " ".join(block)
    raise SystemExit(
        f"description_template (a `>-` block scalar) not found in {_METADATA}"
    )


def render() -> str:
    """The final repo description with every derivable count substituted.

    Only ``{RULE_COUNT}`` was substituted until v0.3.84; the category and
    framework counts sat in the template as literals. That is the same drift the
    markdown guard exists to catch, in the one surface it cannot see -- and it
    had already happened: the template still said "12 categories" after Category
    gained COMPOSITION, so the rendered description was wrong the moment the
    release job asked for it. Anything computable from code is substituted here
    rather than typed into the template.
    """
    # Put the repo root on sys.path ourselves rather than requiring every caller
    # to remember `PYTHONPATH=.`. Running `python scripts/x.py` puts *scripts/* on
    # sys.path, not the root, so the import below fails in any job that has not
    # installed the package -- which is most of them. release.yml carries a
    # PYTHONPATH= for exactly this reason and a comment saying the omission "is
    # why a stale description survived three release cycles undetected";
    # sync-repo-metadata.yml did not, and the moment this module became a
    # dependency of `sync_repo_metadata --description` that job started dying with
    # ModuleNotFoundError. Fixing it here fixes it for every caller, present and
    # future, instead of once per workflow.
    if str(_REPO) not in sys.path:
        sys.path.insert(0, str(_REPO))

    from agent_audit_kit import RULE_COUNT
    from agent_audit_kit.models import Category
    from agent_audit_kit.output import pdf_report

    template = load_description_template(_METADATA.read_text(encoding="utf-8"))
    return (
        template
        .replace("{RULE_COUNT}", str(RULE_COUNT))
        .replace("{CATEGORY_COUNT}", str(len(list(Category))))
        .replace("{FRAMEWORK_COUNT}", str(len(pdf_report._FRAMEWORK_TITLES)))
    )


#: ``gh help exit-codes``: "If a command requires authentication, the exit code will be 4".
_GH_AUTH_REQUIRED = 4


class GhUnavailable(RuntimeError):
    """gh is not installed, or has no credentials: nothing was read."""


def live_description(repo: str) -> str:
    """github.com's current description for ``repo``.

    Raises GhUnavailable when gh is missing or unauthenticated, and RuntimeError on
    any other failure (a rejected token is exit 1 to gh, not 4, so it lands there).
    """
    import subprocess

    try:
        out = subprocess.run(
            ["gh", "repo", "view", repo, "--json", "description", "--jq", '.description // ""'],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError as exc:
        raise GhUnavailable("gh is not installed") from exc
    if out.returncode == _GH_AUTH_REQUIRED:
        raise GhUnavailable("gh is not authenticated (gh auth login, or set GH_TOKEN)")
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "gh repo view failed")
    return out.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Render the GitHub repo description.")
    parser.add_argument(
        "--check-live", metavar="OWNER/REPO",
        help="Compare github.com's live description against this rendering; exit 1 on drift.",
    )
    args = parser.parse_args(argv if argv is not None else [])

    expected = render()
    if not args.check_live:
        sys.stdout.write(expected + "\n")
        return 0

    try:
        live = live_description(args.check_live)
    except GhUnavailable as exc:
        # The expected case on a fresh machine and in any CI job without a token, so
        # a plain line rather than an annotation on every run. Still never a pass.
        sys.stderr.write(f"repo description: not compared, {exc}. Skipped, not a pass.\n")
        return 0
    except Exception as exc:  # noqa: BLE001 - any failure means "not compared"
        # Never a silent pass. Same rule as check_registry_parity: an unreadable
        # surface must not look like a matching one.
        sys.stderr.write(
            f"::warning::repo description NOT COMPARED — could not read "
            f"{args.check_live} ({exc}). This is not a pass.\n"
        )
        return 0

    if live == expected:
        # The string itself, so the count that was compared is on screen.
        sys.stdout.write(f"repo description liveness: live == rendered: {live}\n")
        return 0

    sys.stderr.write(
        f"::error title=Repo description is stale::Paste this into repo "
        f"Settings > About (a CI token cannot set it): {expected}\n"
    )
    sys.stderr.write(f"  live    : {live}\n  rendered: {expected}\n")
    sys.stderr.write(
        f"  fix     : gh repo edit {args.check_live} --description "
        '"$(PYTHONPATH=. python scripts/render_repo_metadata.py)"\n'
    )
    return 1


if __name__ == "__main__":
    # sys.argv[1:] explicitly. `main()` defaults its argv to `[]` so importers and
    # tests get a deterministic parse instead of picking up pytest's own flags --
    # the bug that made gen_owasp_coverage.py and build_coverage_page.py exit
    # mid-test-run. The cost is that __main__ has to hand over the real argv, and
    # forgetting to made --check-live silently render instead of check.
    raise SystemExit(main(sys.argv[1:]))
