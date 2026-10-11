export const start = (app: { listen: (url: string) => void }) =>
  app.listen("http://0.0.0.0:8080");
