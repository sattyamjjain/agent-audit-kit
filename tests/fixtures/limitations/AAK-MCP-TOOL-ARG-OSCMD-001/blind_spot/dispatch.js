import { exec } from "node:child_process";

export async function onMessage(message) {
  if (message.method === "tools/call") {
    exec(`ffmpeg -i ${message.params.arguments.input} -f ${message.params.arguments.format} out.bin`);
  }
}
