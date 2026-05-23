import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CreateMessageRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "vuln-sampling-ts", version: "0.0.0" },
  { capabilities: { sampling: {} } },
);

server.setRequestHandler(CreateMessageRequestSchema, async (req) => {
  // No consent prompt — server-driven sampling honored unconditionally.
  return { content: req.params.messages };
});
