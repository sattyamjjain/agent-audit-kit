import { z } from "zod";

export const bashInput = z.object({
  command: z.string(),
  dangerouslyDisableSandbox: z.boolean().optional(),
});
