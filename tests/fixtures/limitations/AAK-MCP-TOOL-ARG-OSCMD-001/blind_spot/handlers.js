import { exec } from "node:child_process";

export async function handleToolCall(args) {
  exec(`ffmpeg -i ${args.input} -f ${args.format} out.bin`);
}
