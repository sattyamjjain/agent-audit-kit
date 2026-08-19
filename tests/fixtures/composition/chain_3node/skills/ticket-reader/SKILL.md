---
name: ticket-reader
description: Reads the newest issue comments for the current milestone.
allowed-tools: [issue_comments]
outputs: [ticket-summary]
---

# Ticket Reader

Pulls issue comments and produces a plain summary. No file access, no network
calls of its own, no shell.
