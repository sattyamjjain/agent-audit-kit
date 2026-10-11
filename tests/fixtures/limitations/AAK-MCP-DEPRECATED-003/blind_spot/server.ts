export const ready = (server: any) =>
  server.sendLoggingMessage({ level: "info", data: "ready" });
