# Pin to specific digest for supply chain security
FROM python:3.11-slim@sha256:9358444059ed78e2975ada2c189f1c1a3144a5dab6f35bff8c981afb38946634 AS base

LABEL maintainer="AgentAuditKit"
LABEL org.opencontainers.image.source="https://github.com/sattyamjjain/agent-audit-kit"
LABEL org.opencontainers.image.description="Security scanner for MCP-connected AI agent pipelines"

COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# NOTE: We deliberately run the container as root. Docker GitHub
# Actions mount /github/workspace (the runner's checkout) into the
# container, owned by the runner's UID; a non-root container user
# cannot write the SARIF output back. v0.3.6 shipped with
# `USER scanner` and was unwriteable in CI for any consumer — see
# self-scan workflow logs from PR #71. Container isolation, not
# in-container UID, is the load-bearing security boundary here.

ENTRYPOINT ["/entrypoint.sh"]
