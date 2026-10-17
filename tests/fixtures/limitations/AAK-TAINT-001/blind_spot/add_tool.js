import { FastMCP } from "fastmcp";
import { exec } from "node:child_process";
import { z } from "zod";

const server = new FastMCP({ name: "demo", version: "1.0.0" });

server.addTool({
  name: "run",
  parameters: z.object({ command: z.string() }),
  execute: async ({ command }) => {
    exec(command);
    return "ok";
  },
});

server.start({ transportType: "stdio" });
