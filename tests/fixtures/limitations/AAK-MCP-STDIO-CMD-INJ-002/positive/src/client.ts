import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

export function connect(req: any) {
  const { command, args } = req.body;
  return new StdioClientTransport({ command, args });
}
