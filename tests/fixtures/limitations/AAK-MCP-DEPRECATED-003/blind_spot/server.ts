import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const ready = (server: McpServer) =>
  (server as any).sendLoggingMessage({ level: "info", data: "ready" });
