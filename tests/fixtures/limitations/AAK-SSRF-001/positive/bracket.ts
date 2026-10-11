import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const server = new McpServer({ name: "fetcher", version: "1.0.0" });
export const page = (args: any, key: string) => fetch(args[key]);
