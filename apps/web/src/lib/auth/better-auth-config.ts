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
 * No `getUserInfo` override: role resolution reads the raw `id_token` Better
 * Auth persists on `auth_accounts`, which keeps nested claims intact, rather
 * than the userinfo response. See `session-membership.ts`.
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
        // The gate is `databaseHooks.user.create.before`. Setting this true
        // would instead route new identities to an interstitial "complete
        // sign-up" step, which is not the policy here.
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
       * Declared so Better Auth can write it — `external_auth_id` is NOT NULL
       * and unique, and several session lookups resolve through it.
       *
       * `input: false` keeps it off the request body: a client able to choose
       * its own value could claim another user's. `returned: false` keeps it
       * out of session responses. Its only writer is the create hook below.
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
    // Deliberately FALSE — the gate is `databaseHooks.user.create.before`.
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
         * The sign-up gate and the `external_auth_id` writer.
         *
         * The gate belongs here rather than on a route: this hook runs only
         * when a user row is about to be inserted, so it cannot catch sign-in.
         * The OAuth initiation routes cannot tell a new identity from a
         * returning one, so gating them denies every login.
         *
         * Throwing `APIError` aborts the insert with a real status; returning
         * `false` also aborts it but surfaces as an opaque 500.
         */
        before: async (user, ctx) => {
          // `ctx.path` is the dispatched route pattern. Anything reaching a
          // user insert that is not `/sign-up/*` is an OAuth first login. An
          // unknown path takes the stricter of the two, which is permitted
          // only under `open`.
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

          // `external_auth_id` is NOT NULL, unique, and has no default, so it
          // has to be part of this insert. Better Auth is the identity system
          // here, so its own id is the value.
          //
          // Not `create.after`: that hook is queued until after the
          // transaction commits, far too late for a NOT NULL column.
          // `createWithHooks` passes `forceAllowId`, so the id set here is the
          // id inserted.
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
