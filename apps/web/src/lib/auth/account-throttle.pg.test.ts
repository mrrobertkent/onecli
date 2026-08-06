import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { proofDatabaseUrl } from "@onecli/api/testing/pg-proof";

/**
 * Per-account login throttling against real PostgreSQL. The counter lives in a
 * shared table with a `BigInt` timestamp column, so the storage is as much
 * under test as the arithmetic.
 *
 * Env-gated like the other proof suites; see pg-proof.ts.
 */

const PROOF_URL = proofDatabaseUrl();

type Db = typeof import("@onecli/db").db;
type Throttle = typeof import("./account-throttle");

let db: Db;
let throttle: Throttle;

const EMAIL = "throttle-proof@proof.test";
const KEY = `account|${EMAIL}`;

const reset = async () => {
  await db.authRateLimit.deleteMany({
    where: { key: { startsWith: "account|" } },
  });
};

/** Fail `n` times, all at the same instant. */
const failTimes = async (n: number, at: number) => {
  for (let i = 0; i < n; i++) await throttle.recordAccountFailure(EMAIL, at);
};

beforeAll(async () => {
  if (!PROOF_URL) return;
  process.env.DATABASE_URL = PROOF_URL;

  ({ db } = await import("@onecli/db"));
  throttle = await import("./account-throttle");

  await reset();
});

afterAll(async () => {
  if (!PROOF_URL) return;
  await reset();
});

beforeEach(async () => {
  if (!PROOF_URL) return;
  await reset();
});

describe.skipIf(!PROOF_URL)("account throttling on real PostgreSQL", () => {
  const T0 = 1_800_000_000_000;

  it("an unknown account is not throttled", async () => {
    await expect(throttle.checkAccountThrottle(EMAIL, T0)).resolves.toEqual({
      allowed: true,
      retryAfterSeconds: 0,
    });
  });

  it("the first five failures cost nothing", async () => {
    await failTimes(5, T0);

    await expect(throttle.checkAccountThrottle(EMAIL, T0)).resolves.toEqual({
      allowed: true,
      retryAfterSeconds: 0,
    });
  });

  it("the sixth failure starts the backoff", async () => {
    await failTimes(6, T0);

    const decision = await throttle.checkAccountThrottle(EMAIL, T0);
    expect(decision.allowed).toBe(false);
    expect(decision.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("the backoff grows with each further failure", async () => {
    await failTimes(6, T0);
    const first = await throttle.checkAccountThrottle(EMAIL, T0);

    await failTimes(2, T0);
    const later = await throttle.checkAccountThrottle(EMAIL, T0);

    expect(later.retryAfterSeconds).toBeGreaterThan(first.retryAfterSeconds);
  });

  it("waiting out the delay allows another attempt", async () => {
    await failTimes(6, T0);
    const { retryAfterSeconds } = await throttle.checkAccountThrottle(
      EMAIL,
      T0,
    );

    const after = T0 + retryAfterSeconds * 1000;
    await expect(throttle.checkAccountThrottle(EMAIL, after)).resolves.toEqual({
      allowed: true,
      retryAfterSeconds: 0,
    });
  });

  it("the delay is capped, so the account never becomes permanently locked", async () => {
    // Far past any plausible backoff: an uncapped doubling would be centuries.
    await failTimes(60, T0);

    const { retryAfterSeconds } = await throttle.checkAccountThrottle(
      EMAIL,
      T0,
    );
    expect(retryAfterSeconds).toBeLessThanOrEqual(5 * 60);
  });

  it("a success clears the backoff", async () => {
    await failTimes(10, T0);
    await throttle.clearAccountThrottle(EMAIL);

    await expect(throttle.checkAccountThrottle(EMAIL, T0)).resolves.toEqual({
      allowed: true,
      retryAfterSeconds: 0,
    });
    await expect(db.authRateLimit.count({ where: { key: KEY } })).resolves.toBe(
      0,
    );
  });

  it("a failure after a long quiet period restarts the count at one", async () => {
    await failTimes(10, T0);

    // Asserted on the stored count, not on being allowed: the cap means an old
    // row is allowed through anyway, so "allowed" would pass either way and
    // prove nothing about forgetting.
    const muchLater = T0 + 2 * 60 * 60 * 1000;
    await throttle.recordAccountFailure(EMAIL, muchLater);

    const row = await db.authRateLimit.findUnique({
      where: { key: KEY },
      select: { count: true },
    });
    expect(row?.count).toBe(1);
  });

  it("throttles by account, not by address — the counter has no IP in its key", async () => {
    await failTimes(6, T0);

    const rows = await db.authRateLimit.findMany({
      where: { key: { startsWith: "account|" } },
      select: { key: true },
    });
    // One row for the account however many addresses attacked it.
    expect(rows).toEqual([{ key: KEY }]);
  });
});
