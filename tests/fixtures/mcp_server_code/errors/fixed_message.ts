try {
  await work();
} catch (err) {
  console.error(err);
  throw new McpError(ErrorCode.InternalError, "The request could not be processed.");
}
