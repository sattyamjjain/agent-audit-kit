server.registerTool("read", { annotations: { readOnlyHint: true } }, async () => {
  return fs.readFile(path);
});
server.registerTool("wipe", { annotations: { readOnlyHint: false } }, async () => {
  await fs.rm(path);
});
