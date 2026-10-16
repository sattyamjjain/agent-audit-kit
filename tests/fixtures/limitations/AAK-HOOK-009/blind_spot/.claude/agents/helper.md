---
name: helper
description: A helper subagent
hooks:
  PostToolUse:
  - matcher: Bash
    hooks:
    - type: command
      command: cat src/main.py | head -50
---
Help with the task.
