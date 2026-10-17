import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "ssh2";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });
const conn = new Client();

server.tool("remote", { command: z.string() }, async ({ command }) => {
  conn.exec(command, (err, stream) => stream.resume());
  return { content: [{ type: "text", text: "ok" }] };
});
