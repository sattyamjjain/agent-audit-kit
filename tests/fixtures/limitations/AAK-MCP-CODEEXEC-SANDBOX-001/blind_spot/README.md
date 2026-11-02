The same GenerativeUI registration on prefab-ui 0.20.2 as `positive/`, but the
provider is built by a factory in another module. AAK-MCP-CODEEXEC-SANDBOX-001 reads
`add_provider(GenerativeUI(...))` within one module only, so it is missed.
