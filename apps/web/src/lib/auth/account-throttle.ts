import { db } from "@onecli/db";

/**
 * Per-account login throttling.
 *
 * The auth library's own limiter keys on `${ip}|${path}`, so a single account
 * attacked from rotating addresses gets no protection at all. OWASP is explicit
 * that the counter belongs on the account rather than the source address.
 *
 * Delay rather than lockout, and capped: a hard lockout on the one account that
 * exists to recover a broken instance would let anyone deny recovery by
 * failing logins against it.
 */

/** Failures tolerated before any delay applies. */
const FREE_ATTEMPTS = 5;

const BASE_DELAY_MS = 1_000;

/** Ceiling on the backoff, so the account is always eventually reachable. */
const MAX_DELAY_MS = 5 * 60 * 1000;

/** Quiet period after which the count is forgotten. */
const RESET_AFTER_MS = 60 * 60 * 1000;

/** Shares `auth_rate_limits` with the library; the prefix keeps them apart. */
const keyFor = (email: string) => `account|${email.trim().toLowerCase()}`;

export interface ThrottleDecision {
  allowed: boolean;
  /** Seconds until the next attempt is permitted; 0 when allowed. */
  retryAfterSeconds: number;
}

const delayFor = (failures: number): number => {
  if (failures <= FREE_ATTEMPTS) return 0;
  const steps = failures - FREE_ATTEMPTS - 1;
  // 2**31 overflows to Infinity long before this matters, and Math.min still
  // clamps it, but the exponent is bounded anyway to keep the maths readable.
  const scaled = BASE_DELAY_MS * 2 ** Math.min(steps, 20);
  return Math.min(scaled, MAX_DELAY_MS);
};

/** Whether this account may attempt a password login right now. */
export const checkAccountThrottle = async (
  email: string,
  now = Date.now(),
): Promise<ThrottleDecision> => {
  const row = await db.authRateLimit.findUnique({
    where: { key: keyFor(email) },
    select: { count: true, lastRequest: true },
  });
  if (!row) return { allowed: true, retryAfterSeconds: 0 };

  // No reset check here: `MAX_DELAY_MS` is below `RESET_AFTER_MS`, so a row old
  // enough to be forgotten has necessarily served its delay already. Forgetting
  // happens on the next failure instead.
  const wait = delayFor(row.count) - (now - Number(row.lastRequest));
  if (wait <= 0) return { allowed: true, retryAfterSeconds: 0 };

  return { allowed: false, retryAfterSeconds: Math.ceil(wait / 1000) };
};

/** Count a failed attempt, restarting the count after a long quiet period. */
export const recordAccountFailure = async (
  email: string,
  now = Date.now(),
): Promise<void> => {
  const key = keyFor(email);
  const row = await db.authRateLimit.findUnique({
    where: { key },
    select: { count: true, lastRequest: true },
  });

  const stale = row && now - Number(row.lastRequest) > RESET_AFTER_MS;
  const count = !row || stale ? 1 : row.count + 1;

  await db.authRateLimit.upsert({
    where: { key },
    create: { key, count, lastRequest: BigInt(now) },
    update: { count, lastRequest: BigInt(now) },
  });
};

/** A successful login clears the account's backoff. */
export const clearAccountThrottle = async (email: string): Promise<void> => {
  await db.authRateLimit.deleteMany({ where: { key: keyFor(email) } });
};
