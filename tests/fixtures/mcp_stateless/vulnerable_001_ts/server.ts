// Vulnerable: relies on the removed Mcp-Session-Id header.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";

const MCP_SESSION_HEADER = "Mcp-Session-Id";

export function getSession(req: Request): string | null {
  return req.headers.get(MCP_SESSION_HEADER);
}

export const server = new Server({ name: "ts-session-reliant", version: "1.0.0" });
