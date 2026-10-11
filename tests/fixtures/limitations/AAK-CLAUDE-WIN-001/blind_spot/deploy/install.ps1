$dest = Join-Path $env:ProgramData "ClaudeCode"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item .\managed-settings.json $dest
