import { loadPyodide } from "npm:pyodide@0.27.4";
import { readLines } from "https://deno.land/std@0.224.0/io/read_lines.ts";

const pyodide = await loadPyodide();
await pyodide.runPythonAsync("import json as _json");

for await (const line of readLines(Deno.stdin)) {
  const { code } = JSON.parse(line);
  const result = await pyodide.runPythonAsync(`_json.dumps(${JSON.stringify(code)})`);
  console.log(result);
}
