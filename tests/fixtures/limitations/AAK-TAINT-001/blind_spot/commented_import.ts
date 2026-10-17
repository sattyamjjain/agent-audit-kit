import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec /* runs through a shell */ } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.tool("run", { command: z.string() }, async ({ command }) => {
  exec(command);
  return { content: [{ type: "text", text: "ok" }] };
});
