"""docs/RELEASING.md names the jobs a tag push starts, as release.yml names them.

It said "Watch the 5 release jobs" and named five while release.yml ran ten, so
the test suite, the three liveness and latency jobs and the metadata sync were
never on the list a release watcher reads (#1060).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RELEASE_YML = REPO_ROOT / ".github" / "workflows" / "release.yml"
RELEASING_MD = REPO_ROOT / "docs" / "RELEASING.md"


def _job_names() -> list[str]:
    jobs = yaml.safe_load(RELEASE_YML.read_text(encoding="utf-8"))["jobs"]
    return [str(job.get("name") or key) for key, job in jobs.items()]


def _prose() -> str:
    """The doc with each line break folded to a space, so a name wrapped across
    two lines still reads as one."""
    return re.sub(r"\s+", " ", RELEASING_MD.read_text(encoding="utf-8"))


def test_the_doc_states_how_many_release_jobs_there_are() -> None:
    counts = re.findall(r"Watch the (\d+) release jobs", _prose())
    assert counts == [str(len(_job_names()))], counts


def test_the_doc_names_every_release_job() -> None:
    prose = _prose()
    missing = [name for name in _job_names() if name not in prose]
    assert not missing, f"docs/RELEASING.md does not name these release.yml jobs: {missing}"
