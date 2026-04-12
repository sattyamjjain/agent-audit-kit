#!/usr/bin/env bash
# AgentAuditKit — Docker One-Liner
#
# Scan any directory without installing Python or pip.
# The container runs as non-root for security.

# Basic scan (console output)
docker run --rm -v "$(pwd)":/project ghcr.io/sattyamjjain/agent-audit-kit scan /project

# JSON output
docker run --rm -v "$(pwd)":/project ghcr.io/sattyamjjain/agent-audit-kit scan /project --format json

# SARIF output (save to file)
docker run --rm -v "$(pwd)":/project ghcr.io/sattyamjjain/agent-audit-kit scan /project --format sarif > results.sarif

# With severity filter
docker run --rm -v "$(pwd)":/project ghcr.io/sattyamjjain/agent-audit-kit scan /project --severity medium --fail-on high

# Security score
docker run --rm -v "$(pwd)":/project ghcr.io/sattyamjjain/agent-audit-kit score /project
