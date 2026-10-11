import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const sample = (server: McpServer) =>
  (server as any).createMessage({ messages: [], maxTokens: 100 });
