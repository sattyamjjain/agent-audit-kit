// The control: a StreamableHTTP transport with no Host allow-list and no other route.
// AAK-DNS-REBIND-001 reports it; AAK-DNS-REBIND-003 has no route beside /mcp to report.
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
app.use(express.json());

app.post("/mcp", async (req, res) => {
  const server = new McpServer({ name: "notebook", version: "1.0.0" });
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => transport.close());
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000, "127.0.0.1");
