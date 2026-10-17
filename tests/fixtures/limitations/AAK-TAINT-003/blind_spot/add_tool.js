import { FastMCP } from "fastmcp";
import fs from "node:fs";
import { z } from "zod";

const server = new FastMCP({ name: "demo", version: "1.0.0" });

server.addTool({
  name: "save",
  parameters: z.object({ path: z.string(), text: z.string() }),
  execute: async ({ path, text }) => {
    fs.writeFileSync(path, text);
    return "saved";
  },
});

server.start({ transportType: "stdio" });
