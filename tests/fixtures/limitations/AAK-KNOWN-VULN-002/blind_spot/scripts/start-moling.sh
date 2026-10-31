#!/bin/sh
# Starts MoLing 0.4.0 in SSE mode from a shell script, which the rule does not read:
# it reads MCP client configs, and image references in YAML files and Dockerfiles.
exec go run github.com/gojue/moling@v0.4.0 -l 127.0.0.1:8080
