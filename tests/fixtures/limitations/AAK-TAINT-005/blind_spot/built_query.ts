import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("find", { title: z.string() }, async ({ title }) => {
  const sql = `SELECT * FROM notes WHERE title = '${title}'`;
  const rows = await db.query(sql);
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});
