import { betterAuth } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { nextCookies } from "better-auth/next-js";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { db } from "@onecli/db";
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
 * `getUserInfo` is supplied deliberately: the shipped presets (`keycloak()`,
 * `okta()`) map no claims, and we need the RAW claim object so a claim PATH
 * (design D-4 — Keycloak keeps roles at `realm_access.roles`) stays reachable.
 * Better Auth's own `mapping.extraFields` is flat-key only and cannot express it.
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
        // Same as `emailAndPassword.disableSignUp`: the gate is the `before`
        // hook, which is where US-1's "authenticating at the IdP is not
        // sufficient to be provisioned" is enforced.
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
  session: { modelName: "authSession" },
  account: { modelName: "authAccount" },
  verification: { modelName: "authVerification" },

  emailAndPassword: {
    enabled: true,
    // Deliberately FALSE — the gate is the `before` hook below (design D-15).
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

  hooks: {
    /**
     * The sign-up gate (design D-15).
     *
     * Runs before the handler, so it covers every route that can create a user:
     * `/sign-up/email` and the OAuth entry points. It reads the persisted
     * `signupMode` per request, which is what makes the setting changeable from
     * the admin GUI without a restart.
     *
     * `isSignupAllowed` denies on ANY failure — missing row, database error,
     * unrecognised value — so US-1's "misconfiguration denies; it does not
     * admit" holds even though the gate is no longer a build-time constant.
     *
     * Note this gates PROVISIONING, not sign-in. An existing user signing in
     * does not pass through `/sign-up/*`, and the OAuth paths below only create
     * a user when none matches; an already-provisioned identity is unaffected
     * by `signupMode: "closed"`.
     */
    before: createAuthMiddleware(async (ctx) => {
      const path = ctx.path;
      const isPasswordSignup = path.startsWith("/sign-up");
      // Both the initiation and the callback: denying only at the callback
      // would still have sent the user to the IdP and back for nothing, and
      // denying only at initiation would leave the callback reachable directly.
      const isOAuthEntry =
        path.startsWith("/sign-in/oauth2") ||
        path.startsWith("/oauth2/callback") ||
        path.startsWith("/sign-in/social") ||
        path.startsWith("/callback");

      if (!isPasswordSignup && !isOAuthEntry) return;

      const allowed = await isSignupAllowed(
        isPasswordSignup ? "password" : "sso",
      );
      if (allowed) return;

      throw new APIError("FORBIDDEN", {
        message:
          "This instance is not accepting new accounts. Ask an administrator for access.",
        code: "SIGNUP_CLOSED",
      });
    }),
  },

  databaseHooks: {
    user: {
      create: {
        after: async (user) => {
          // `users.external_auth_id` is NOT NULL + unique and Better Auth does
          // not know it. Under D-10 the column means "this user's id in the
          // authoritative identity system", and that system is now Better Auth
          // — so its own id IS the correct value, not a placeholder. This keeps
          // `middleware/auth/session.ts`'s lookup working unchanged.
          await db.user.update({
            where: { id: user.id },
            data: { externalAuthId: user.id },
          });
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
