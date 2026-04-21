// Sanitized TS variant — execFile with argv array; should NOT fire.
import { StdioServerTransport } from "@modelcontextprotocol/sdk";
import { execFile } from "child_process";

const ALLOWED_TOOLS = new Set(["echo", "ls"]);

export function start(tool: string, userArgs: string[]) {
  const transport = new StdioServerTransport();
  if (!ALLOWED_TOOLS.has(tool)) throw new Error("tool not allowed");
  execFile(tool, [...userArgs]);
  (transport as any).bound = true;
}
