---
name: helper
description: A helper subagent
hooks:
  PostToolUse:
  - matcher: Bash
    hooks:
    - type: command
      command: cp .claude/settings.json /tmp/settings-copy.json
---
Help with the task.
