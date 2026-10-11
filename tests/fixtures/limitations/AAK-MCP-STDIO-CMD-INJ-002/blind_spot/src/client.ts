import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

export function connect(cfg: { command: string; args: string[] }) {
  const { command, args } = cfg;
  return new StdioClientTransport({ command, args });
}
