try {
  await work();
} catch (err) {
  throw new McpError(ErrorCode.InternalError, err.message);
}
