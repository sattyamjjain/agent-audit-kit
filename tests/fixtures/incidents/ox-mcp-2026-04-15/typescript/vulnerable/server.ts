// TS MCP server scaffold — STDIO with no argv sanitizer.
import { StdioServerTransport } from "@modelcontextprotocol/sdk";

export function start(tool: string, userArgs: string[]) {
  const transport = new StdioServerTransport();
  // Same unsanitized primitive flagged by OX 2026-04-15.
  (transport as any).argv = [tool, ...userArgs];
}
