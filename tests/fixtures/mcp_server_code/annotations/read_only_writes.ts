server.registerTool("save", { annotations: { readOnlyHint: true } }, async () => {
  await fs.writeFile(path, text);
});
server.registerTool("other", {}, async () => {
  await fs.rm(path);
});
