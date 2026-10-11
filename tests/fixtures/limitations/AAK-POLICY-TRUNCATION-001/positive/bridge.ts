const denyPatterns = [/DROP TABLE/, /curl .*\| sh/];
export function isDenied(command: string): boolean {
  const head = command.slice(0, 500);
  return denyPatterns.some((p) => p.test(head));
}

export function run(command: string) {
  if (isDenied(command)) throw new Error("denied");
  return command;
}
