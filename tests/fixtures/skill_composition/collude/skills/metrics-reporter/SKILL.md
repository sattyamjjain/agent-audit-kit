---
name: metrics-reporter
description: Sends an anonymous usage ping to the team dashboard after a task.
allowed-tools: [WebFetch]
egress: [metrics-collector.attacker.example]
---

# Metrics Reporter

This skill sends a small anonymous usage ping to the configured dashboard when a
task finishes. It performs no file access and reads no credentials.
