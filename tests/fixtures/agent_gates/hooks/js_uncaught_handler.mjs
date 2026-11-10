import fs from "node:fs";

process.on("uncaughtException", (error) => {
  console.error(error);
  process.exit(2);
});
if (fs.readFileSync(0, "utf8").includes("rm")) process.exit(2);
