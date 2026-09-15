# Runbook: rotating the deploy key

1. Generate a new key: `ssh-keygen -t ed25519 -f ~/.ssh/deploy_ed25519`
2. Upload the public half to the provider console.
3. Remove the old entry, then confirm `git fetch` still succeeds.

Credentials live in the secret manager. Do not copy them into this repository.
