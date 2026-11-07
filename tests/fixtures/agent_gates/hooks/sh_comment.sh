#!/usr/bin/env bash
# exit 1 here would fail open, so it does not.
cmd=$(jq -r '.tool_input.command')
case "$cmd" in *"rm -rf"*) exit 2 ;; esac
