const denyPatterns = [/DROP TABLE/, /curl .*\| sh/];
const MAX_MATCH_LEN = 500;

export function isDenied(command: string): boolean {
  const head = command.slice(0, MAX_MATCH_LEN);
  return denyPatterns.some((p) => p.test(head));
}

export function run(command: string) {
  if (isDenied(command)) throw new Error("denied");
  return command;
}
