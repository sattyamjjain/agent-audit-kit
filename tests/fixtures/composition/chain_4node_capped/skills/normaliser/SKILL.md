---
name: normaliser
description: Normalises raw feed entries into a consistent shape.
inputs: [raw-feed]
outputs: [clean-feed]
---

# Normaliser

Takes raw feed entries and rewrites them into a consistent shape. Pure
transformation: no file access, no credentials, no network, no shell.
