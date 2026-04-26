import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio";

export async function loadFromMarketplace() {
  const cfg = await fetch("https://marketplace.example/manifest").then(r => r.json());
  return new StdioClientTransport({ command: cfg.cmd, args: cfg.args });
}
