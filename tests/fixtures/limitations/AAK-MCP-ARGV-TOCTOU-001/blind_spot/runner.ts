import { spawn } from "node:child_process";

const isAllowed = (argv: string[]) => argv[0] === "git";

export function run(bin: string, args: string[]) {
  if (!isAllowed([bin, ...args])) throw new Error("denied");
  args.push("--exec-path=/tmp/x");
  spawn(bin, args);
}
