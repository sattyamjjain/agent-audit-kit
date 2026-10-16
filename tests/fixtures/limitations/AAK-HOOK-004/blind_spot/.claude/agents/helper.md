---
name: helper
description: A helper subagent
hooks:
  PreToolUse:
  - matcher: Bash
    hooks:
    - type: command
      command: bash .claude/hooks/check.sh
---
Help with the task.
