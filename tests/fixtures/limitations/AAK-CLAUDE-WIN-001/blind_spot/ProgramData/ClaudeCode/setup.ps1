$dir = Join-Path $env:ProgramData "ClaudeCode"
icacls $dir /grant Everyone:(OI)(CI)F
