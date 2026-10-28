# AAK-STARTUP-HOOK-DOCKERFILE-001

**Dockerfile adds a Python startup hook, or sets PYTHONSTARTUP in an MCP server image**

| Field | Value |
|---|---|
| Severity | MEDIUM |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.28 |
| Scanner | `agent_audit_kit/scanners/startup_hooks.py` |
| OWASP MCP | MCP04:2025 (Software Supply Chain Attacks & Dependency Tampering) |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities), ASI05 (Unexpected Code Execution) |

## What it catches

A build step that puts code where Python runs it at every start, in every
container started from the image:

```dockerfile
COPY cook.pth /usr/local/lib/python3.12/site-packages/
RUN echo 'import hook' > /usr/local/lib/python3.12/site-packages/hook.pth
RUN cp tools/hook.py /usr/local/lib/python3.12/site-packages/sitecustomize.py
```

A COPY or ADD of a `.pth`, `sitecustomize.py` or `usercustomize.py`, a RUN that
writes one through a redirect, `tee`, `cp`, `mv`, `install` or `ln`, and
`ENV PYTHONSTARTUP` in an image that runs an MCP server are reported.
`PYTHONSTARTUP` names a file every interactive Python session in the image runs
first; a debugging shell inside a server container is one.

An image is taken to run an MCP server when an `mcp` word, `fastmcp` or
`modelcontextprotocol` appears in a CMD, ENTRYPOINT, RUN or LABEL, when a
manifest beside the Dockerfile declares an MCP SDK, or when an `.mcp.json` sits
beside it.

## What it does not catch

- A package that `pip install` installs with such a file inside it: scan the
  built image's files for that (see [Scan a container image's files](../scan-image-rootfs.md)).
- A directory copy that happens to contain a hook, unless the directory is on
  `PYTHONPATH` (AAK-STARTUP-HOOK-SITECUSTOMIZE-001 reads that case).
- A file written by a script the RUN calls, and a path built from `ARG` or `$VAR`.

## How to fix

Remove the step, or move what the hook does into the application's entry point.
If the image must carry it, keep its source in the repository and review changes
to it like code.
