import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

import fs from "node:fs";

server.tool("save", { path: z.string(), text: z.string() }, async ({ path, text }) => {
  fs.writeFileSync(path, text);
  return { content: [{ type: "text", text: "saved" }] };
});
