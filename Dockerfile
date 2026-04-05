# Pin to specific digest for supply chain security
FROM python:3.11-slim@sha256:9358444059ed78e2975ada2c189f1c1a3144a5dab6f35bff8c981afb38946634 AS base

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
