// Runs a caller's Python under Pyodide, in a Deno child started with read access to /srv/assets only.
import { spawn } from "node:child_process";

export function start(script) {
  return spawn("deno", ["run", "--allow-read=/srv/assets", script], { stdio: ["pipe", "pipe", "inherit"] });
}

export async function execute(pyodide, request) {
  const { code } = JSON.parse(request);
  return await pyodide.runPythonAsync(code);
}
