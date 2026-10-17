import type { IncomingMessage } from "node:http";

export function collect(req: IncomingMessage, done: (body: string) => void): void {
  let body = "";
  req.on("data", chunk => {
    // This handler collects the request body for the transport and hands it on once the stream ends.
    // This handler collects the request body for the transport and hands it on once the stream ends.
    // This handler collects the request body for the transport and hands it on once the stream ends.
    // This handler collects the request body for the transport and hands it on once the stream ends.
    // This handler collects the request body for the transport and hands it on once the stream ends.
    // This handler collects the request body for the transport and hands it on once the stream ends.
    // This handler collects the request body for the transport and hands it on once the stream ends.
    // This handler collects the request body for the transport and hands it on once the stream ends.
    // This handler collects the request body for the transport and hands it on once the stream ends.
    // This handler collects the request body for the transport and hands it on once the stream ends.
    // This handler collects the request body for the transport and hands it on once the stream ends.
    // This handler collects the request body for the transport and hands it on once the stream ends.
    body += chunk;
  });
  req.on("end", () => done(body));
}
