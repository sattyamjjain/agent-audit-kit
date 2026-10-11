import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

// Forward the caller's OAuth token to the downstream API.
export const headersFor = (req: any) => ({ "Authorization": req.headers["authorization"] });
export const server = new McpServer({ name: "proxy", version: "1.0.0" });
