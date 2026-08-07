import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { proofDatabaseUrl } from "@onecli/api/testing/pg-proof";

/**
 * The Better Auth instance against real PostgreSQL, using the real
 * `betterAuth()` object, Prisma client and schema. The other auth tests mock
 * `@onecli/db` and so never execute an insert.
 *
 * Env-gated like the other proof suites; see pg-proof.ts.
 */

const PROOF_URL = proofDatabaseUrl();

type Db = typeof import("@onecli/db").db;
type AuthModule = typeof import("./better-auth-config");

let db: Db;
let auth: AuthModule["auth"];

const P = "balogin-";
const PASSWORD = "correct-horse-battery-staple-9";
const EXISTING = `${P}existing@proof.test`;
const NEWCOMER = `${P}newcomer@proof.test`;

/** A stub OIDC discovery document, so `/sign-in/oauth2` is genuinely routable. */
let idp: Server;

const reset = async () => {
  const users = await db.user.findMany({
    where: { email: { startsWith: P } },
    select: { id: true },
  });
  const userIds = users.map((u) => u.id);
  await db.authSession.deleteMany({ where: { userId: { in: userIds } } });
  await db.authAccount.deleteMany({ where: { userId: { in: userIds } } });
  await db.user.deleteMany({ where: { id: { in: userIds } } });
};

const setSignupMode = async (signupMode: string) => {
  await db.instanceSetting.upsert({
    where: { id: "instance" },
    create: { id: "instance", signupMode },
    update: { signupMode },
  });
};

/** `auth.api.*` throws `APIError` on non-2xx; normalise both into a status. */
const statusOf = async (fn: () => Promise<unknown>): Promise<number> => {
  try {
    await fn();
    return 200;
  } catch (err) {
    const status = (err as { statusCode?: number }).statusCode;
    return status ?? 500;
  }
};

beforeAll(async () => {
  if (!PROOF_URL) return;

  idp = createServer((req, res) => {
    const { port } = idp.address() as AddressInfo;
    const issuer = `http://127.0.0.1:${port}`;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
      }),
    );
  });
  await new Promise<void>((resolve) => idp.listen(0, "127.0.0.1", resolve));
  const { port } = idp.address() as AddressInfo;

  // Set BEFORE the dynamic imports: `@/lib/env` snapshots `process.env` at
  // module load, and `betterAuth()` reads its whole configuration once at
  // construction.
  process.env.DATABASE_URL = PROOF_URL;
  process.env.AUTH_SECRET = "proof-secret-not-used-outside-this-suite";
  process.env.APP_URL = "http://localhost:10254";
  process.env.OIDC_ISSUER = `http://127.0.0.1:${port}`;
  process.env.OIDC_CLIENT_ID = "proof-client";
  process.env.OIDC_CLIENT_SECRET = "proof-client-secret";

  ({ db } = await import("@onecli/db"));
  ({ auth } = await import("./better-auth-config"));

  await reset();
});

afterAll(async () => {
  if (!PROOF_URL) return;
  await reset();
  // The unrecognised-mode case leaves a value nothing else understands on a row
  // every other suite shares. Put the default back rather than hand the next
  // reader an instance whose sign-up mode reads as nonsense.
  await setSignupMode("closed");
  await new Promise<void>((resolve) => idp.close(() => resolve()));
});

beforeEach(async () => {
  if (!PROOF_URL) return;
  await setSignupMode("open");
});

describe.skipIf(!PROOF_URL)("Better Auth against real PostgreSQL", () => {
  it("a sign-up inserts, with external_auth_id equal to the row's id", async () => {
    await reset();

    const result = await auth.api.signUpEmail({
      body: { email: EXISTING, password: PASSWORD, name: "Existing User" },
    });

    expect(result.user.id).toBeTruthy();

    // Read the raw row: `external_auth_id` is `returned: false`, and what
    // reached the column is the point.
    const row = await db.user.findUnique({
      where: { email: EXISTING },
      select: { id: true, externalAuthId: true, emailVerified: true },
    });

    expect(row).not.toBeNull();
    expect(row?.id).toBe(result.user.id);
    // The invariant every session lookup depends on.
    expect(row?.externalAuthId).toBe(row?.id);
  });

  it("mints a UUID id, matching what every relation on users.id holds", async () => {
    await reset();
    const result = await auth.api.signUpEmail({
      body: { email: EXISTING, password: PASSWORD, name: "Existing User" },
    });

    expect(result.user.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it("signupMode 'closed' does not block an existing user signing in", async () => {
    await reset();
    await auth.api.signUpEmail({
      body: { email: EXISTING, password: PASSWORD, name: "Existing User" },
    });

    await setSignupMode("closed");

    // A gate on the sign-in routes throws SIGNUP_CLOSED here, locking out
    // every provisioned user on every login.
    const session = await auth.api.signInEmail({
      body: { email: EXISTING, password: PASSWORD },
    });

    expect(session.user.email).toBe(EXISTING);
  });

  it("signupMode 'closed' does not block OIDC initiation", async () => {
    await setSignupMode("closed");

    // An initiation endpoint cannot know whether the identity behind it is
    // new, and every provisioned user hits it on every login, so it must hand
    // back an authorize URL regardless of the sign-up mode.
    const result = await auth.api.signInWithOAuth2({
      body: { providerId: "oidc", callbackURL: "/" },
    });

    expect(result.url).toContain("/authorize");
  });

  it("signupMode 'closed' blocks a new account, and writes no row", async () => {
    await reset();
    await setSignupMode("closed");

    const status = await statusOf(() =>
      auth.api.signUpEmail({
        body: { email: NEWCOMER, password: PASSWORD, name: "Newcomer" },
      }),
    );

    expect(status).toBe(403);
    // A gate that denies the response but leaves a row is not a gate.
    await expect(
      db.user.findUnique({ where: { email: NEWCOMER } }),
    ).resolves.toBeNull();
  });

  it("signupMode 'sso-only' blocks password sign-up", async () => {
    await reset();
    await setSignupMode("sso-only");

    const status = await statusOf(() =>
      auth.api.signUpEmail({
        body: { email: NEWCOMER, password: PASSWORD, name: "Newcomer" },
      }),
    );

    expect(status).toBe(403);
  });

  it("an unrecognised signupMode fails CLOSED against the real column", async () => {
    await reset();
    // Asserted against a real write: the value a mock returns is chosen by
    // the test, so it cannot settle this.
    await setSignupMode("wide-open-please");

    const status = await statusOf(() =>
      auth.api.signUpEmail({
        body: { email: NEWCOMER, password: PASSWORD, name: "Newcomer" },
      }),
    );

    expect(status).toBe(403);
  });
});
