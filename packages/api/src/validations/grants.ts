import { z } from "zod";
import { sessionPolicySchema } from "./policy";

// ── Grants request shapes ───────────────────────────────────────────────────
// A connection grant is either the whole-app attach or an explicit per-tool
// tri-state (allow / ask; the rest compiles to blocked). Only structural laws
// live here; catalog membership and the plan gate are the service's job.
//
// `resources` is the grant's session policy, tri-state: absent preserves what
// the stack already carries, null clears it, an object sets it.

export const connectionGrantSchema = z
  .discriminatedUnion("access", [
    z.object({
      access: z.literal("full"),
      resources: sessionPolicySchema.nullish(),
    }),
    z.object({
      access: z.literal("custom"),
      allow: z.array(z.string().min(1).max(255)).max(200),
      ask: z.array(z.string().min(1).max(255)).max(200),
      resources: sessionPolicySchema.nullish(),
    }),
  ])
  .refine(
    (v) => v.access === "full" || v.allow.length + v.ask.length > 0,
    // An all-blocked grant is a detach, not a grant.
    {
      message:
        "Custom access needs at least one allowed or approval tool — detach instead.",
    },
  )
  .refine(
    (v) => v.access === "full" || !v.allow.some((tool) => v.ask.includes(tool)),
    { message: "A tool can't be both always-allowed and require approval." },
  );
export type ConnectionGrantInput = z.infer<typeof connectionGrantSchema>;

/** GET /v1/agents `include` projections — absent = the plain agent list. */
export const agentsIncludeSchema = z.enum(["grants-summary"]).optional();
