import fs from "node:fs";

const deny = (reason) => process.exit(reason ? 2 : 2);
const stop = (reason) => {
  console.error(reason);
  process.exit(2);
};

try {
  if (fs.readFileSync(0, "utf8").includes("rm")) deny("no");
} catch (error) {
  stop(String(error));
}
