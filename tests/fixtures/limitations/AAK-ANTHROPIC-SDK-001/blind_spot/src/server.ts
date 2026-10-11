import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const server = new Server({ name: 'demo', version: '1.0.0' }, { capabilities: {} });
await server.connect(new StdioServerTransport());
