#!/usr/bin/env bash
# AgentAuditKit pre-commit one-liner installer.
#
# Usage:
#   curl -fsSL https://aak.dev/install-pre-commit.sh | bash
#   # or
#   curl -fsSL https://raw.githubusercontent.com/sattyamjjain/agent-audit-kit/main/scripts/install-pre-commit.sh | bash
#
# What it does:
#   1. Resolves the latest GitHub Release tag (or uses $AAK_VERSION).
#   2. Appends an `agent-audit-kit` repo block to the project's
#      `.pre-commit-config.yaml` (or creates the file if missing).
#   3. Runs `pre-commit install` so the hook is active.
#
# Idempotent: re-runs detect an existing AAK block and only update
# the rev pin when AAK_VERSION drifts.
#
# Closes #65.

set -euo pipefail

# --------------------------------------------------------------------------
# 0. Sanity checks.
# --------------------------------------------------------------------------
if ! command -v git >/dev/null 2>&1; then
    echo "error: git is required. Install git and re-run." >&2
    exit 2
fi

if [ ! -d .git ]; then
    echo "error: this directory is not a git repository. Run \`git init\` first." >&2
    exit 2
fi

if ! command -v pre-commit >/dev/null 2>&1; then
    echo "info: pre-commit is not installed. Install with:" >&2
    echo "  pip install pre-commit" >&2
    echo "  # or" >&2
    echo "  pipx install pre-commit" >&2
    echo "  # or" >&2
    echo "  brew install pre-commit" >&2
    exit 2
fi

# --------------------------------------------------------------------------
# 1. Resolve target version.
# --------------------------------------------------------------------------
AAK_VERSION="${AAK_VERSION:-}"
if [ -z "$AAK_VERSION" ]; then
    if command -v curl >/dev/null 2>&1; then
        AAK_VERSION=$(curl -fsSL https://api.github.com/repos/sattyamjjain/agent-audit-kit/releases/latest \
            | grep -E '"tag_name"' \
            | head -1 \
            | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')
    fi
fi

if [ -z "$AAK_VERSION" ]; then
    echo "error: could not resolve latest agent-audit-kit version. Set AAK_VERSION manually:" >&2
    echo "  AAK_VERSION=v0.3.13 curl ... | bash" >&2
    exit 2
fi

echo "==> agent-audit-kit pre-commit installer"
echo "    target version: $AAK_VERSION"

# --------------------------------------------------------------------------
# 2. Build / update .pre-commit-config.yaml.
# --------------------------------------------------------------------------
CONFIG=".pre-commit-config.yaml"
AAK_REPO_URL="https://github.com/sattyamjjain/agent-audit-kit"

if [ ! -f "$CONFIG" ]; then
    echo "==> creating $CONFIG"
    cat > "$CONFIG" <<EOF
repos:
  - repo: $AAK_REPO_URL
    rev: $AAK_VERSION
    hooks:
      - id: agent-audit-kit
EOF
elif ! grep -q "$AAK_REPO_URL" "$CONFIG"; then
    echo "==> appending agent-audit-kit block to $CONFIG"
    cat >> "$CONFIG" <<EOF

  - repo: $AAK_REPO_URL
    rev: $AAK_VERSION
    hooks:
      - id: agent-audit-kit
EOF
else
    # Update the rev line in the existing block (idempotent re-runs).
    if command -v sed >/dev/null 2>&1; then
        # GNU sed vs BSD sed in-place flag dance.
        if sed --version >/dev/null 2>&1; then
            sed -i -E "s|(repo: $AAK_REPO_URL\\s*\\n\\s*rev:\\s*)v[0-9]+\\.[0-9]+\\.[0-9]+|\\1$AAK_VERSION|" "$CONFIG" 2>/dev/null || true
        fi
    fi
    echo "==> $CONFIG already contains an agent-audit-kit entry — left as-is"
fi

# --------------------------------------------------------------------------
# 3. Activate the hook.
# --------------------------------------------------------------------------
echo "==> running \`pre-commit install\`"
pre-commit install

echo ""
echo "✓ agent-audit-kit pre-commit hook installed at $AAK_VERSION."
echo "  Test it on the current repo: pre-commit run --all-files"
echo ""
