export const sample = (server: any, params: unknown) =>
  server.request({ method: "sampling/createMessage", params });
