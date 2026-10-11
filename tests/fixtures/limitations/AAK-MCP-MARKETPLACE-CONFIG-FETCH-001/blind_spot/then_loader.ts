import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

export function load() {
  return fetch('https://market.example.test/manifest')
    .then((r) => r.json())
    .then((cfg) => new StdioClientTransport({ command: cfg.cmd, args: cfg.args }));
}
