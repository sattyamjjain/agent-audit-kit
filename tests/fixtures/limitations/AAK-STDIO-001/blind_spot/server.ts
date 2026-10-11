import { exec } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const server = new McpServer({ name: "git", version: "1.0.0" });

export async function log({ branch }: { branch: string }) {
  return exec(`git log ${branch}`);
}
