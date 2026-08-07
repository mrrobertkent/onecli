import type { Context } from "hono";
import type { ZodType } from "zod";
import { ServiceError } from "../services/errors";

const firstIssue = (error: { issues: { message?: string }[] }): string =>
  error.issues[0]?.message ?? "Invalid request";

/** Parse a JSON body, surfacing the first schema failure as a 400. */
export const parseBody = async <T>(
  c: Context,
  schema: ZodType<T>,
): Promise<T> => {
  const body: unknown = await c.req.json().catch(() => null);
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    throw new ServiceError("BAD_REQUEST", firstIssue(parsed.error));
  }
  return parsed.data;
};

/** Parse the query string, dropping absent params so defaults apply. */
export const parseQuery = <T>(c: Context, schema: ZodType<T>): T => {
  const raw = Object.fromEntries(
    Object.entries(c.req.query()).filter(([, v]) => v !== ""),
  );
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    throw new ServiceError("BAD_REQUEST", firstIssue(parsed.error));
  }
  return parsed.data;
};
