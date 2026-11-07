#!/usr/bin/env bash
set -euo pipefail
trap 'echo "guard failed" >&2; exit 2' ERR
cmd=$(jq -r '.tool_input.command')
case "$cmd" in *"rm -rf"*) exit 2 ;; esac
