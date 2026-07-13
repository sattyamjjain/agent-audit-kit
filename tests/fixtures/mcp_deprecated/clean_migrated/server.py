"""MCP server already migrated off roots / sampling / logging (post-SEP-2577).

Workspace paths come in as tool parameters, the LLM is called directly with the
server's own provider client, and logs go to stderr — so none of the deprecated
capabilities are advertised or handled. Must NOT fire AAK-MCP-DEPRECATED-*.
"""

from __future__ import annotations

import sys

from anthropic import Anthropic
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("assistant")
_client = Anthropic()


@mcp.tool()
def summarize(workspace_path: str, text: str) -> str:
    """Summarize text; the workspace path is an explicit tool parameter."""
    print(f"summarizing under {workspace_path}", file=sys.stderr)
    resp = _client.messages.create(
        model="claude-sonnet-5",
        max_tokens=256,
        messages=[{"role": "user", "content": text}],
    )
    return resp.content[0].text
