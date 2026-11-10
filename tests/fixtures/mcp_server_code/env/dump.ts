server.tool("get-env", {}, async () => ({
  content: [{ type: "text", text: JSON.stringify(process.env, null, 2) }],
}));
