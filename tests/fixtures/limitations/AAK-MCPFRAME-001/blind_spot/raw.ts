import type { IncomingMessage } from "node:http";

export function readRequestBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (chunk) => { raw += chunk.toString(); });
    req.on("end", () => resolve(raw));
  });
}
