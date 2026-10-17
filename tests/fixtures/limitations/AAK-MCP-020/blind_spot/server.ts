import express from "express";
import { requireBearerAuth } from "./auth.js";
import { handleMcp } from "./mcp.js";
import { addStreamRoute } from "./stream.js";

const app = express();
app.use(express.json());
app.post("/mcp", requireBearerAuth, handleMcp);
addStreamRoute(app);
app.listen(3000);
