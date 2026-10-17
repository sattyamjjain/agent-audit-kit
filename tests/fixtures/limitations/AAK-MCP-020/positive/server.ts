import express from "express";
import { requireBearerAuth } from "./auth.js";
import { handleMcp } from "./mcp.js";

const app = express();
app.use(express.json());
app.post("/mcp", requireBearerAuth, handleMcp);
app.get("/mcp", handleMcp);
app.listen(3000);
