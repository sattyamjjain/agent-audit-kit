"""The GitLab jobs in the docs do what the docs say they do.

Every GitLab example filed its SARIF under ``artifacts:reports:sast``, which is
GitLab's own SAST report format and does not read SARIF; SARIF goes under
``artifacts:reports:sarif`` (GitLab Ultimate, 19.1+). And GitLab ingests SARIF
only from a job that succeeds, so a SARIF job that also gates on findings
publishes nothing on exactly the runs that have findings. The Docker example
also needs ``entrypoint: [""]``: GitLab starts its own shell in the image.

https://docs.gitlab.com/user/application_security/detect/sarif/
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
DOCS = [REPO / "docs" / "gitlab-ci.md", REPO / "docs" / "ci-cd.md"]
IMAGE = "ghcr.io/sattyamjjain/agent-audit-kit"
_YAML_BLOCK = re.compile(r"```yaml\n(.*?)```", re.S)


def _gitlab_jobs() -> list[tuple[str, str, dict]]:
    """``(doc, job name, job)`` for every GitLab job in the docs' YAML blocks."""
    jobs = []
    for doc in DOCS:
        text = doc.read_text(encoding="utf-8")
        if doc.name == "ci-cd.md":  # one section among several CI systems
            text = text.split("## GitLab CI", 1)[1].split("\n## ", 1)[0]
        for block in _YAML_BLOCK.findall(text):
            data = yaml.safe_load(block)
            for name, job in (data or {}).items():
                if isinstance(job, dict) and "script" in job:
                    jobs.append((doc.name, name, job))
    return jobs


def _reports(job: dict) -> dict:
    return (job.get("artifacts") or {}).get("reports") or {}


def test_the_docs_show_a_sarif_report() -> None:
    assert any("sarif" in _reports(job) for _, _, job in _gitlab_jobs())


def test_sarif_is_never_filed_as_a_sast_report() -> None:
    for doc, name, job in _gitlab_jobs():
        sast = str(_reports(job).get("sast", ""))
        assert not sast.endswith(".sarif"), f"{doc}:{name} files SARIF under reports:sast"


def test_a_sarif_job_does_not_fail_on_findings() -> None:
    """GitLab drops the report of a failed job, `allow_failure` or not."""
    for doc, name, job in _gitlab_jobs():
        if "sarif" not in _reports(job):
            continue
        script = " ".join(job["script"])
        assert "--ci" not in script.split(), f"{doc}:{name}: --ci fails the job on findings"
        assert "--fail-on none" in script, f"{doc}:{name} must report with --fail-on none"


def test_the_image_job_lets_gitlab_start_its_shell() -> None:
    image_jobs = [
        (doc, name, job) for doc, name, job in _gitlab_jobs()
        if IMAGE in str(job.get("image", ""))
    ]
    assert image_jobs
    for doc, name, job in image_jobs:
        assert isinstance(job["image"], dict) and job["image"].get("entrypoint") == [""], (
            f"{doc}:{name} runs the image without `entrypoint: [\"\"]`"
        )
