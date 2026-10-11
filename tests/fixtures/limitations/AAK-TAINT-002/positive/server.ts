import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.tool("calc", { expression: z.string() }, async ({ expression }) => {
  return { content: [{ type: "text", text: String(eval(expression)) }] };
});
