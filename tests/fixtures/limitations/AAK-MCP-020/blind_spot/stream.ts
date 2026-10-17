import type { Express } from "express";
import { handleMcp } from "./mcp.js";

// The same handler, registered from another file with no authentication.
export function addStreamRoute(app: Express): void {
  app.get("/mcp", handleMcp);
}
