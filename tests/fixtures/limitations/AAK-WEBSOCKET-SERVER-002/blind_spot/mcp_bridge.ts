// The same bridge with a verifyClient that accepts every handshake. Any verifyClient in
// the options counts as the check, whatever it does, so the rule stands down.
import { WebSocketServer } from "ws";

const wss = new WebSocketServer({
  port: 8000,
  path: "/message",
  verifyClient: (_info, done) => done(true),
});

wss.on("connection", (ws) => {
  ws.on("message", (data) => ws.send(data.toString()));
});
