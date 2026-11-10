#!/bin/bash -e
cmd=$(jq -r '.tool_input.command')
case "$cmd" in *"rm -rf"*) exit 2 ;; esac
