import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

export const ALLOWED_ORIGINS = ['https://example.test'];
export const child = new StdioClientTransport({ command: 'node', args: ['child.js'] });
