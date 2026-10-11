import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const server = new McpServer({ name: "demo", version: "1.0.0" });
express().listen(8080);
