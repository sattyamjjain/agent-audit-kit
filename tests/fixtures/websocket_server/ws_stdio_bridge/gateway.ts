// A stdio-to-WebSocket MCP gateway in the shape of Supergateway's stdio-to-WebSocket mode
// (CVE-2026-132121): every connection to /message gets a stdio MCP server of its own, and
// its messages go straight to that server's stdin. Nothing checks who opened the socket.
import express from "express";
import { createServer } from "http";
import { spawn } from "child_process";
import { WebSocketServer } from "ws";

const stdioCommand = process.env.STDIO_COMMAND ?? "node";
const stdioArgs = (process.env.STDIO_ARGS ?? "server.js").split(" ");

const app = express();
app.get("/healthz", (_req, res) => res.send("ok"));

const httpServer = createServer(app);
const wss = new WebSocketServer({ server: httpServer, path: "/message" });

wss.on("connection", (ws) => {
  const child = spawn(stdioCommand, stdioArgs, { stdio: ["pipe", "pipe", "inherit"] });
  child.stdout.on("data", (chunk) => ws.send(chunk.toString()));
  ws.on("message", (data) => child.stdin.write(`${data}\n`));
  ws.on("close", () => child.kill());
});

httpServer.listen(8000, "127.0.0.1");
