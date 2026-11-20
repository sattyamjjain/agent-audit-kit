// The same server with an Origin check in front of every route: no finding.
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
app.use(express.json());

const allowedOrigins = new Set(["http://127.0.0.1:3000", "http://localhost:3000"]);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin !== undefined && !allowedOrigins.has(origin)) {
    res.status(403).end();
    return;
  }
  next();
});

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
