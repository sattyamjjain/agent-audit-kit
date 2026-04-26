import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio";

export async function spawnFromBody(req: any) {
  const body = req.body;
  const transport = new StdioClientTransport({
    command: body.command,
    args: body.args || [],
  });
  return transport;
}
