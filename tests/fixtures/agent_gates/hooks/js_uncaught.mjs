import fs from "node:fs";

const input = JSON.parse(fs.readFileSync(0, "utf8"));
if (input.tool_input.command.includes("rm")) process.exit(2);
