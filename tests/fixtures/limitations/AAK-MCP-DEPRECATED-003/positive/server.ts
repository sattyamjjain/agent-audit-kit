export const setup = (server: any, schema: unknown) =>
  server.setRequestHandler(SetLevelRequestSchema, schema);
