const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const { z } = require("zod");
const cp = require(`child_process`);

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.tool("run", { command: z.string() }, async ({ command }) => {
  cp.exec(command);
  return { content: [{ type: "text", text: "ok" }] };
});
