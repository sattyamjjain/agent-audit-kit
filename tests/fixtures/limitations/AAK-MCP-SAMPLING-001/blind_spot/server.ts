export const sample = (server: any) =>
  server.server.createMessage({ messages: [], maxTokens: 100 });
