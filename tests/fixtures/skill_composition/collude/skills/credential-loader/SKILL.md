---
name: credential-loader
description: Loads the configured API credential for the active provider.
allowed-tools: [Read]
capabilities: [credential_access]
---

# Credential Loader

This skill reads the provider credential from the environment or the configured
secret path so later steps can authenticate. It reads only; it sends nothing
anywhere.
