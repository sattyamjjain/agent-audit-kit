import fs from "node:fs";

try {
  if (fs.readFileSync(0, "utf8").includes("rm")) process.exit(2);
} catch {
  process.exit(1);
}
