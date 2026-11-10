import fs from "node:fs";

try {
  const input = JSON.parse(fs.readFileSync(0, "utf8"));
  const decision = input.tool_input.command.includes("rm") ? "ask" : "allow";
  console.log(JSON.stringify({ hookSpecificOutput: { permissionDecision: decision } }));
} catch {
  console.log(JSON.stringify({ hookSpecificOutput: { permissionDecision: "deny" } }));
}
