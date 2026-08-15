// FP-resistance fixture for AAK-MCP-STDIO-CMD-INJ-002 (#22).
//
// A network-controlled source and a StdioClientTransport sink are both present
// in this file, and the source sits a few lines above the sink — but nothing
// flows from one to the other. The command is a constant chosen from a fixed
// table. The proximity heuristic fires here; data-flow analysis must not.

import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio";

const SERVERS: Record<string, string> = {
  primary: "/usr/bin/server-a",
  secondary: "/usr/bin/server-b",
};

export async function handler(req: any) {
  // A genuine source — used only for logging, never for the command.
  const reason = req.body.reason;
  await recordAudit(reason);

  const command = SERVERS.primary;
  return new StdioClientTransport({ command, args: [] });
}

async function recordAudit(reason: string): Promise<void> {
  console.log(`spawn requested: ${reason}`);
}
