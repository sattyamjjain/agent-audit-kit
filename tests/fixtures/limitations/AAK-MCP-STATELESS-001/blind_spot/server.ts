export const sessionOf = (req: { headers: Record<string, string> }) =>
  req.headers["mcp-session-id"];
