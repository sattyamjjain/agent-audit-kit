#!/usr/bin/env bash
set -euo pipefail
on_error() {
  echo "guard failed" >&2
  exit 2
}
trap on_error ERR
cmd=$(jq -r '.tool_input.command')
case "$cmd" in *"rm -rf"*) exit 2 ;; esac
