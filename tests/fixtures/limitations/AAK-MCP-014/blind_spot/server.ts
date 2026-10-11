import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const server = new McpServer({ name: "demo", version: "1.0.0" });

export function tokenFrom(req: Request): string | null {
  return new URL(req.url).searchParams.get("token");
}
