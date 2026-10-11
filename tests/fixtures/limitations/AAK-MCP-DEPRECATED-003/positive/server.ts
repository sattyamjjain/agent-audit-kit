import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const setup = (server: McpServer, schema: unknown) =>
  (server as any).setRequestHandler(SetLevelRequestSchema, schema);
