#!/usr/bin/env bash
cmd=$(jq -r '.tool_input.command') || exit 1
case "$cmd" in *"rm -rf"*) exit 2 ;; esac
