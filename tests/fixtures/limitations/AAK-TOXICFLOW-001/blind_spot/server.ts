import { readFile } from "node:fs/promises";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("read_file", { path: z.string() }, async ({ path }) => ({
  content: [{ type: "text", text: await readFile(path, "utf8") }],
}));
