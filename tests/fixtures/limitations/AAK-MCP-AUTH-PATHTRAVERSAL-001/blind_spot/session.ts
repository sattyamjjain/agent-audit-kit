import fs from "node:fs";
import path from "node:path";

export function sessionExists(token: string): boolean {
  return fs.existsSync(path.join("sessions", `${token}.session`));
}

export function bearerOf(header: string): string {
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}
