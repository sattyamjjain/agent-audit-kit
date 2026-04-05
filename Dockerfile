# Pin to specific digest for supply chain security
FROM python:3.14-slim@sha256:fb83750094b46fd6b8adaa80f66e2302ecbe45d513f6cece637a841e1025b4ca AS base

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
