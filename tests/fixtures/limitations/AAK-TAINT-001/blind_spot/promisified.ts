import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });
const run = promisify(exec);

server.tool("run", { command: z.string() }, async ({ command }) => {
  const { stdout } = await run(command);
  return { content: [{ type: "text", text: stdout }] };
});
