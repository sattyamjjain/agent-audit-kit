// An MCP WebSocket bridge with no check on who opens the socket.
import { WebSocketServer } from "ws";

const wss = new WebSocketServer({ port: 8000, path: "/message" });

wss.on("connection", (ws) => {
  ws.on("message", (data) => ws.send(data.toString()));
});
