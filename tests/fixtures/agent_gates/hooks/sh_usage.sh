#!/usr/bin/env bash
usage() {
  echo "usage: guard.sh" >&2
  exit 64
}
[ $# -le 1 ] || usage
cmd=$(jq -r '.tool_input.command')
case "$cmd" in *"rm -rf"*) exit 2 ;; esac
