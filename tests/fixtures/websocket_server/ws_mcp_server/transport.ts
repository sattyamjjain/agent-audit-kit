// The WebSocket half of an MCP gateway, built in a file of its own, as Supergateway 4.1.0
// builds it (src/server/websocket.ts): no `verifyClient`, and no process started here.
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { Server } from "http";
import { WebSocket, WebSocketServer } from "ws";

export class WebSocketServerTransport {
  private readonly wss: WebSocketServer;
  private readonly clients = new Map<string, WebSocket>();

  constructor({ path, server }: { path: string; server: Server }) {
    this.wss = new WebSocketServer({ path, server });
  }

  start(onmessage: (message: JSONRPCMessage, clientId: string) => void): void {
    this.wss.on("connection", (ws: WebSocket) => {
      const clientId = crypto.randomUUID();
      this.clients.set(clientId, ws);
      ws.on("message", (data: Buffer) => onmessage(JSON.parse(data.toString()), clientId));
      ws.on("close", () => this.clients.delete(clientId));
    });
  }
}
