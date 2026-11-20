// The same gateway with `verifyClient` refusing a handshake from a page it does not serve:
// no finding.
import express from "express";
import { createServer } from "http";
import { spawn } from "child_process";
import { WebSocketServer } from "ws";

const stdioCommand = process.env.STDIO_COMMAND ?? "node";
const stdioArgs = (process.env.STDIO_ARGS ?? "server.js").split(" ");

const app = express();
app.get("/healthz", (_req, res) => res.send("ok"));

const httpServer = createServer(app);
const allowedOrigins = new Set(["http://127.0.0.1:8000", "http://localhost:8000"]);
const wss = new WebSocketServer({
  server: httpServer,
  path: "/message",
  verifyClient: (info) => info.origin === undefined || allowedOrigins.has(info.origin),
});

wss.on("connection", (ws) => {
  const child = spawn(stdioCommand, stdioArgs, { stdio: ["pipe", "pipe", "inherit"] });
  child.stdout.on("data", (chunk) => ws.send(chunk.toString()));
  ws.on("message", (data) => child.stdin.write(`${data}\n`));
  ws.on("close", () => child.kill());
});

httpServer.listen(8000, "127.0.0.1");
