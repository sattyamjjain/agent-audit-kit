import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

export const ALLOWED_ORIGINS = ['https://example.test'];

const server = new Server({ name: 'demo', version: '1.0.0' }, { capabilities: {} });
await server.connect(new StdioServerTransport());
