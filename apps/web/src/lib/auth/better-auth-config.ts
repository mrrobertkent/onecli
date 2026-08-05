import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { nextCookies } from "better-auth/next-js";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { db } from "@onecli/db";
import type { SignupKind } from "@onecli/api/services/signup-policy";
import { isSignupAllowed } from "@onecli/api/services/signup-policy";
import {
  APP_URL,
  AUTH_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  OIDC_CLIENT_ID,
  OIDC_CLIENT_SECRET,
  OIDC_ISSUER,
} from "@/lib/env";
import { hashPassword, verifyPassword } from "@/lib/auth/password-hash";

/**
 * The Better Auth instance (design D-9).
 *
 * D-10: Better Auth's `user` model is mapped onto OneCLI's EXISTING `users`
 * table. There is no second user table and no email-keyed mirror — one user row
 * per human. Its other three tables are additive (`Auth*` in the Prisma schema).
 *
 * Cloud aliases this file's consumers away (`next.config.js` →
 * `@/ee/auth/cognito-*`), so nothing here reaches the cloud edition.
 */

/**
 * Generic OIDC, configured from the environment.
 *
 * `genericOAuth` — not `socialProviders`. `socialProviders` is a CLOSED registry
 * of named providers with no generic OIDC entry; an unknown key there is a
 * TypeError at startup, not an ignored provider.
 *
 * No `getUserInfo` override, and none is needed: the shipped presets
 * (`keycloak()`, `okta()`) map no claims, but the claim PATH lookup design D-4
 * requires (Keycloak keeps roles at `realm_access.roles`) does not read the
 * userinfo response at all. It reads the RAW id_token Better Auth persists to
 * `auth_accounts.id_token`, which keeps the full nested claim object intact —
 * see `session-membership.ts`. Better Auth's `mapping.extraFields` is flat-key
 * only and could not express the path; the id_token needs no mapping.
 */
const oidcConfigured = Boolean(
  OIDC_ISSUER && OIDC_CLIENT_ID && OIDC_CLIENT_SECRET,
);

const oidcProviders = oidcConfigured
  ? [
      {
        providerId: "oidc",
        // Sent verbatim. The live Authentik issuer advertises a TRAILING SLASH
        // and normalising it away breaks discovery.
        discoveryUrl: `${OIDC_ISSUER.replace(/\/$/, "")}/.well-known/openid-configuration`,
        issuer: OIDC_ISSUER,
        clientId: OIDC_CLIENT_ID,
        clientSecret: OIDC_CLIENT_SECRET,
        scopes: ["openid", "profile", "email"],
        pkce: true,
        // Same as `emailAndPassword.disableSignUp`: the gate is
        // `databaseHooks.user.create.before`, which is where US-1's
        // "authenticating at the IdP is not sufficient to be provisioned" is
        // enforced. Setting this `true` would instead route a new identity to
        // an interstitial "complete sign-up" step, which is not the policy.
        disableImplicitSignUp: false,
      },
    ]
  : [];

export const auth = betterAuth({
  appName: "OneCLI",
  baseURL: APP_URL,
  secret: AUTH_SECRET,

  database: prismaAdapter(db, { provider: "postgresql" }),

  // Better Auth's `user` is OneCLI's `users` (D-10). `name` stays nullable in
  // the schema: Better Auth enforces `required` on create only, and reads go
  // through `filterOutputFields`, which filters rather than validates.
  user: {
    additionalFields: {
      /**
       * `users.external_auth_id` is `NOT NULL` + unique, and it is the column
       * five separate consumers resolve a session through — including the Rust
       * gateway (`db.rs:105`), which is not ours to re-point. Better Auth
       * cannot write a column it does not know about, so declare it.
       *
       * `input: false` keeps it off the sign-up request body — a client that
       * could choose its own `external_auth_id` could impersonate any user by
       * claiming theirs. `returned: false` keeps it out of session responses.
       * The only writer is the `create.before` hook below.
       */
      externalAuthId: {
        type: "string",
        input: false,
        returned: false,
      },
    },
  },
  session: { modelName: "authSession" },
  account: { modelName: "authAccount" },
  verification: { modelName: "authVerification" },

  emailAndPassword: {
    enabled: true,
    // Deliberately FALSE — the gate is `databaseHooks.user.create.before`
    // below (design D-15).
    //
    // This field is read once, when `betterAuth()` is constructed, so it cannot
    // express an admin-changeable setting: flipping it would need a container
    // restart, and "restart the container to let a colleague in" is what pushes
    // operators to leave sign-up open permanently. Leaving it `true` alongside
    // the hook would make `signupMode: "open"` unreachable.
    disableSignUp: false,
    password: {
      hash: hashPassword,
      // Better Auth calls this with `{hash, password}`; our service takes them
      // positionally so it owes nothing to the library's shape (D-6).
      verify: ({ hash, password }) => verifyPassword(hash, password),
    },
  },

  socialProviders: GOOGLE_CLIENT_ID
    ? {
        google: {
          clientId: GOOGLE_CLIENT_ID,
          clientSecret: GOOGLE_CLIENT_SECRET,
          disableImplicitSignUp: true,
        },
      }
    : {},

  rateLimit: {
    // Explicitly on. Better Auth enables rate limiting only in production by
    // default, and a limiter that silently disappears in other environments is
    // not one you can reason about.
    enabled: true,
    // Survives a container restart, which the default in-memory store does not.
    // The database storage does an atomic check-and-increment, so concurrent
    // requests cannot all pass a stale read.
    storage: "database",
    modelName: "authRateLimit",
  },

  advanced: {
    database: {
      // Better Auth mints its own id format by default. `users.id` is the
      // target of 22 relations that have always held UUIDs, so keep the shape
      // it has always had rather than introducing a second id format into a
      // table other code already reads.
      generateId: "uuid",
    },
    ipAddress: {
      // REQUIRED behind the reverse proxy. Without it Better Auth cannot resolve
      // a client IP and degrades to ONE SHARED BUCKET per path — i.e. one
      // attacker consumes everybody's login budget.
      ipAddressHeaders: ["x-forwarded-for", "x-real-ip"],
    },
  },

  databaseHooks: {
    user: {
      create: {
        /**
         * The sign-up gate (design D-15) AND the `external_auth_id` writer.
         *
         * Both live here because this hook fires at exactly one moment: a user
         * row is about to be inserted. That is the definition of provisioning,
         * so it is the only place the gate can sit without also catching
         * sign-IN.
         *
         * The gate previously ran as a `hooks.before` middleware over
         * `/sign-in/oauth2`, `/sign-in/social`, `/callback` and
         * `/oauth2/callback`. Those are the endpoints EVERY already-provisioned
         * user hits on EVERY login — they are not sign-up routes — so with
         * `signupMode` defaulting to `closed` the middleware locked the whole
         * instance out permanently. An initiation endpoint cannot tell a new
         * identity from a returning one; only this hook can, because by the
         * time it runs Better Auth has already looked for a matching user and
         * found none.
         *
         * `isSignupAllowed` denies on ANY failure — missing row, database
         * error, unrecognised value — so US-1's "misconfiguration denies; it
         * does not admit" holds even though the gate is no longer a build-time
         * constant. Throwing `APIError` here aborts the insert; returning
         * `false` would abort it just as surely but surface as an opaque 500.
         */
        before: async (user, ctx) => {
          // The route pattern of the endpoint being dispatched (better-auth
          // sets it on the async-local endpoint context). `/sign-up/*` is the
          // password path; every other route that reaches a user insert is an
          // OAuth/OIDC first login. When the path cannot be established, take
          // the STRICTER of the two: `password` is permitted only under
          // `open`, so an unrecognised creation path fails closed.
          const kind: SignupKind = ctx?.path?.startsWith("/sign-up")
            ? "password"
            : ctx?.path
              ? "sso"
              : "password";

          if (!(await isSignupAllowed(kind))) {
            throw new APIError("FORBIDDEN", {
              message:
                "This instance is not accepting new accounts. Ask an administrator for access.",
              code: "SIGNUP_CLOSED",
            });
          }

          // `users.external_auth_id` is NOT NULL + unique and has no default,
          // so the insert fails outright unless the value is part of it. Under
          // D-10 the column means "this user's id in the authoritative identity
          // system", and that system is now Better Auth — so its own id IS the
          // correct value, not a placeholder.
          //
          // Generated HERE, not in `create.after`: `after` is queued to run
          // AFTER the transaction commits (`with-hooks.mjs:33`), which would
          // both fail the NOT NULL constraint and leave a committed window in
          // which `middleware/auth/session.ts:26` cannot resolve the session it
          // just issued. `createWithHooks` passes `forceAllowId`, so the id we
          // choose is the id that is inserted.
          const id = crypto.randomUUID();
          return { data: { ...user, id, externalAuthId: id } };
        },
      },
    },
  },

  plugins: [
    genericOAuth({ config: oidcProviders }),
    // MUST be last: it writes Set-Cookie via next/headers on the way out.
    nextCookies(),
  ],
});

export type Auth = typeof auth;
