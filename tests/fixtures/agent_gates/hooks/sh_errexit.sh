#!/usr/bin/env bash
set -euo pipefail
cmd=$(jq -r '.tool_input.command')
case "$cmd" in *"rm -rf"*) exit 2 ;; esac
exit 0
