import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

import fs from "node:fs";

server.tool("load", { path: z.string() }, async ({ path }) => {
  const text = fs.readFileSync(path, "utf8");
  return { content: [{ type: "text", text }] };
});
