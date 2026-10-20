# Pin to specific digest for supply chain security
# Multi-arch index digest of python:3.11-slim as of 2026-10-20 (`crane digest python:3.11-slim`).
FROM python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce AS base

LABEL maintainer="AgentAuditKit"
LABEL org.opencontainers.image.source="https://github.com/sattyamjjain/agent-audit-kit"
LABEL org.opencontainers.image.description="Security scanner for MCP-connected AI agent pipelines"

COPY . /app
WORKDIR /app
# The image runs the CLI and installs nothing afterwards, so the build tools the
# base image ships (pip, setuptools, wheel, and the packages pip and setuptools
# vendor) leave once the package is in: Trivy reported CVE-2026-24049 (wheel)
# and CVE-2026-23949 (setuptools' jaraco.context) on them after the Debian CVEs
# were cleared, and upgrading pip instead brought its vendored msgpack and
# urllib3 into the report.
RUN pip install --no-cache-dir . \
    && pip uninstall -y pip setuptools wheel

# The GitHub Action bridge. action.yml selects it with `runs.entrypoint`; it
# reads its positional arguments as the Action's inputs ($1 path, $2 severity).
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# NOTE: We deliberately run the container as root. Docker GitHub
# Actions mount /github/workspace (the runner's checkout) into the
# container, owned by the runner's UID; a non-root container user
# cannot write the SARIF output back. v0.3.6 shipped with
# `USER scanner` and was unwriteable in CI for any consumer — see
# self-scan workflow logs from PR #71. Container isolation, not
# in-container UID, is the load-bearing security boundary here.

# Everyone except the Action gets the CLI: `docker run IMAGE scan /project`.
# Through 0.6.9 this was the bridge, which read `scan` as the path and
# `/project` as the severity, so every documented one-liner exited 2.
ENTRYPOINT ["agent-audit-kit"]
