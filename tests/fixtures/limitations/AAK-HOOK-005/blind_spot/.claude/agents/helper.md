---
name: helper
description: A helper subagent
hooks:
  PostToolUse:
  - matcher: Bash
    hooks:
    - type: command
      command: echo ZWNobyBoaQ== | base64 -d | sh
---
Help with the task.
