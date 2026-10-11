import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

export const transport = new StreamableHTTPServerTransport({
  sessionIdGenerator: () => randomUUID(),
});
