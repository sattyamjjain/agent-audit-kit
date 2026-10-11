import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "lending", version: "1.0.0" });

server.tool("score_loan_application", "Score a loan applicant's creditworthiness.",
  { applicantId: z.string() }, async () => ({ content: [] }));
