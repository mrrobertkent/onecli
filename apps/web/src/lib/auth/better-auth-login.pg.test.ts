import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { proofDatabaseUrl } from "@onecli/api/testing/pg-proof";

/**
 * The Better Auth instance on REAL PostgreSQL — the suite that would have
 * caught F2, F3 and F4 before they were committed.
 *
 * The rest of the auth tests mock `@onecli/db`, so not one of them has ever
 * executed an insert. Three HIGH blockers passed a green 1,384-test suite for
 * exactly that reason: two of them are `NOT NULL` and routing facts that a mock
 * cannot have an opinion about. Everything here therefore runs the real
 * `betterAuth()` object, the real Prisma client, and the real schema.
 *
 * Laws proven:
 *  - a sign-up actually INSERTS, and lands `external_auth_id` equal to the row's
 *    own id, in the same statement (F2);
 *  - `signupMode: "closed"` stops NEW accounts and does not touch sign-IN or
 *    OAuth initiation, on any path (F3);
 *  - the gate is fail-closed for an unrecognised mode, against the real column.
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
  await new Promise<void>((resolve) => idp.close(() => resolve()));
});

beforeEach(async () => {
  if (!PROOF_URL) return;
  await setSignupMode("open");
});

describe.skipIf(!PROOF_URL)("Better Auth against real PostgreSQL", () => {
  it("F2: a sign-up inserts, with external_auth_id equal to the row's id", async () => {
    await reset();

    const result = await auth.api.signUpEmail({
      body: { email: EXISTING, password: PASSWORD, name: "Existing User" },
    });

    expect(result.user.id).toBeTruthy();

    // Read the raw row, not the library's view of it: `external_auth_id` is
    // `returned: false`, and the whole point is what reached the column.
    const row = await db.user.findUnique({
      where: { email: EXISTING },
      select: { id: true, externalAuthId: true, emailVerified: true },
    });

    expect(row).not.toBeNull();
    expect(row?.id).toBe(result.user.id);
    // The invariant every session lookup depends on — `middleware/auth/
    // session.ts`, `resolve-user.ts`, `actions/user.ts` and the Rust gateway
    // all resolve a session through this column.
    expect(row?.externalAuthId).toBe(row?.id);
  });

  it("F2: the id is a real UUID, so the 22 relations keyed on it keep their shape", async () => {
    await reset();
    const result = await auth.api.signUpEmail({
      body: { email: EXISTING, password: PASSWORD, name: "Existing User" },
    });

    expect(result.user.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it("F3: signupMode 'closed' does NOT block an existing user signing in", async () => {
    await reset();
    await auth.api.signUpEmail({
      body: { email: EXISTING, password: PASSWORD, name: "Existing User" },
    });

    await setSignupMode("closed");

    // The regression. The gate used to sit on `hooks.before` over the sign-IN
    // routes, so this threw FORBIDDEN/SIGNUP_CLOSED for every provisioned user
    // on every login — a permanent, total lockout of the instance.
    const session = await auth.api.signInEmail({
      body: { email: EXISTING, password: PASSWORD },
    });

    expect(session.user.email).toBe(EXISTING);
  });

  it("F3: signupMode 'closed' does NOT block OIDC initiation", async () => {
    await setSignupMode("closed");

    // `/sign-in/oauth2` is an INITIATION endpoint: every already-provisioned
    // user hits it on every login, and it cannot yet know whether the identity
    // behind it is new. Gating it was the lockout. It must hand back an
    // authorize URL regardless of the sign-up mode.
    const result = await auth.api.signInWithOAuth2({
      body: { providerId: "oidc", callbackURL: "/" },
    });

    expect(result.url).toContain("/authorize");
  });

  it("F3: signupMode 'closed' DOES block a new account, and writes no row", async () => {
    await reset();
    await setSignupMode("closed");

    const status = await statusOf(() =>
      auth.api.signUpEmail({
        body: { email: NEWCOMER, password: PASSWORD, name: "Newcomer" },
      }),
    );

    expect(status).toBe(403);
    // The gate runs in `create.before`, so the insert must not have happened —
    // a gate that denies the response but leaves a row is not a gate.
    await expect(
      db.user.findUnique({ where: { email: NEWCOMER } }),
    ).resolves.toBeNull();
  });

  it("F3: signupMode 'sso-only' blocks password sign-up", async () => {
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
    // US-1: "misconfiguration denies; it does not admit". Asserted against a
    // real write, because the value a mock returns is chosen by the test.
    await setSignupMode("wide-open-please");

    const status = await statusOf(() =>
      auth.api.signUpEmail({
        body: { email: NEWCOMER, password: PASSWORD, name: "Newcomer" },
      }),
    );

    expect(status).toBe(403);
  });
});
