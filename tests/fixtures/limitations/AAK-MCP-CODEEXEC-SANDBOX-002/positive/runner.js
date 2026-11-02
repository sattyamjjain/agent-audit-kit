// Runs a caller's Python under Pyodide, in a Deno child started with every permission.
import { spawn } from "node:child_process";

export function start(script) {
  return spawn("deno", ["run", "-A", script], { stdio: ["pipe", "pipe", "inherit"] });
}

export async function execute(pyodide, request) {
  const { code } = JSON.parse(request);
  return await pyodide.runPythonAsync(code);
}
