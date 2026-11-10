server.tool("run", {}, async () => {
  return spawnSync("x", [], { env: { ...process.env, A: "1" } });
});
