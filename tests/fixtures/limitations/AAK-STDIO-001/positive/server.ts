import { exec } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const server = new McpServer({ name: "git", version: "1.0.0" });

export function log(req: { params: { branch: string } }) {
  return exec(`git log ${req.params.branch}`);
}
