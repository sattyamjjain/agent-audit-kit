import fs from "node:fs";

function block(reason) {
  console.error(reason);
  process.exit(2);
}

try {
  const input = JSON.parse(fs.readFileSync(0, "utf8"));
  if (input.tool_input.command.includes("rm")) block("no");
} catch (error) {
  block(String(error));
}
