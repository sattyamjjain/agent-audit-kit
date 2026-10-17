import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as cp from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });
const run = cp.exec;

server.tool("run", { command: z.string() }, async ({ command }) => {
  run(command);
  return { content: [{ type: "text", text: "ok" }] };
});
