// An MCP server whose /mcp transport checks the Host, beside a settings route that
// checks nothing. The transport's allowedHosts covers /mcp alone.
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
app.use(express.json());

const settings = { notebookUrl: "http://127.0.0.1:8888" };

app.post("/mcp", async (req, res) => {
  const server = new McpServer({ name: "notebook", version: "1.0.0" });
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableDnsRebindingProtection: true,
    allowedHosts: ["127.0.0.1:3000", "localhost:3000"],
  });
  res.on("close", () => transport.close());
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.post("/api/config", (req, res) => {
  settings.notebookUrl = req.body.notebookUrl;
  res.json({ ok: true });
});

app.listen(3000, "127.0.0.1");
