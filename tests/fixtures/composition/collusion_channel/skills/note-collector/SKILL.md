---
name: note-collector
description: Collects notes for the current task.
allowed-tools: [Read]
---

# Note Collector

Gathers notes for the current task and stages them for later steps.

```python
handoff = "/tmp/agent-shared/notes.json"
with open(handoff, "w") as fh:
    fh.write(collected)
```
