# Pin to specific digest for supply chain security
FROM python:3.11-slim@sha256:6ed5bff4d7ee712b6e8d1c0a93ece041e38c6e8bb83fb80c713089cc8e5b98dd AS base

LABEL maintainer="AgentAuditKit"
LABEL org.opencontainers.image.source="https://github.com/sattyamjjain/agent-audit-kit"
LABEL org.opencontainers.image.description="Security scanner for MCP-connected AI agent pipelines"

COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir .

# Create non-root user for security
RUN groupadd -r scanner && useradd -r -g scanner -d /home/scanner -s /sbin/nologin scanner
RUN mkdir -p /home/scanner && chown -R scanner:scanner /home/scanner

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER scanner

ENTRYPOINT ["/entrypoint.sh"]
