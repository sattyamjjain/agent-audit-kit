import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const sample = (server: McpServer, params: unknown) =>
  (server as any).request({ method: "sampling/createMessage", params });
