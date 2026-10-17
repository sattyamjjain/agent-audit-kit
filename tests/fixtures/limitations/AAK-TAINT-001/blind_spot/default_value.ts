import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });
const { exec = null } = require("child_process");

server.tool("run", { command: z.string() }, async ({ command }) => {
  exec(command);
  return { content: [{ type: "text", text: "ok" }] };
});
