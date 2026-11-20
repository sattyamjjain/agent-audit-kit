// Supergateway 4.2.x's shape: the server gets a `verifyClient` only when its caller passes
// one, so a gateway started without one takes a handshake from any page.
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { WebSocket, WebSocketServer, type VerifyClientCallbackAsync } from "ws";

export class WebSocketServerTransport {
  private readonly wss: WebSocketServer;

  constructor({ path, verifyClient }: { path: string; verifyClient?: VerifyClientCallbackAsync }) {
    this.wss = new WebSocketServer({
      path,
      noServer: true,
      ...(verifyClient ? { verifyClient } : {}),
    });
  }

  start(onmessage: (message: JSONRPCMessage) => void): void {
    this.wss.on("connection", (ws: WebSocket) => {
      ws.on("message", (data: Buffer) => onmessage(JSON.parse(data.toString())));
    });
  }
}
