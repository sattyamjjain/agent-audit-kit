import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio";

const ALLOWED: Record<string, string> = {
  "server-a": "/usr/bin/server-a",
  "server-b": "/usr/bin/server-b",
};

export function spawnFromName(name: string) {
  const cmd = ALLOWED[name];
  if (!cmd) throw new Error("not allowed");
  return new StdioClientTransport({ command: cmd, args: [] });
}
