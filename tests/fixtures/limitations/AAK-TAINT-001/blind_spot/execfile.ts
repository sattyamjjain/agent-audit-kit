import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

import { execFile } from "node:child_process";

server.tool("run", { command: z.string() }, async ({ command }) => {
  execFile(command, []);
  return { content: [{ type: "text", text: "ok" }] };
});
