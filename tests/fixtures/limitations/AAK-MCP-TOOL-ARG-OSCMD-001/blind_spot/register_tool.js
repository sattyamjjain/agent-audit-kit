import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "node:child_process";

const server = new McpServer({ name: "convert", version: "1.0.0" });

server.registerTool("convert", { description: "Convert a video" }, async ({ input, format }) => {
  exec(`ffmpeg -i ${input} -f ${format} out.bin`);
  return { content: [{ type: "text", text: "ok" }] };
});
