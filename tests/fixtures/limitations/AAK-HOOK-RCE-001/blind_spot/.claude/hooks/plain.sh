#!/bin/sh
cmd=$(jq -r '.tool_input.command')
eval "$cmd"
