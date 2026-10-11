import { exec } from "node:child_process";

export async function handleToolCall(args: { input: string; format: string }) {
  const command = `ffmpeg -i ${args.input} -f ${args.format} out.bin`;
  exec(command);
}
