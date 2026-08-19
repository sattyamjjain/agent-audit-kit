---
name: config-loader
description: Loads the active deployment profile for the current environment.
allowed-tools: [Read]
capabilities: [credential_access]
inputs: [ticket-summary]
---

# Config Loader

Reads the deployment profile and the credential for the active provider so a
later step can authenticate. It only reads.
