import { loadPyodide } from "npm:pyodide@0.27.8";
import { readLines } from "https://deno.land/std@0.224.0/io/read_lines.ts";

const pyodide = await loadPyodide();
await pyodide.runPythonAsync("import json as _json");

// Bootstrap is done: take back the file and network access it needed.
for (const name of ["read", "write", "net"]) {
  await Deno.permissions.revoke({ name });
}

for await (const line of readLines(Deno.stdin)) {
  const { code } = JSON.parse(line);
  const result = await pyodide.runPythonAsync(`_json.dumps(${JSON.stringify(code)})`);
  console.log(result);
}
