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
 * Better Auth's `user` model maps onto OneCLI's existing `users` table; its
 * other three tables are additive (`Auth*` in the Prisma schema). Cloud aliases
 * this file's consumers away in `next.config.js`.
 */

/**
 * Generic OIDC, configured from the environment.
 *
 * Role resolution reads the raw `id_token` from `auth_accounts` rather than the
 * userinfo response, so no `getUserInfo` override. See `session-membership.ts`.
 */
const oidcConfigured = Boolean(
  OIDC_ISSUER && OIDC_CLIENT_ID && OIDC_CLIENT_SECRET,
);

const oidcProviders = oidcConfigured
  ? [
      {
        providerId: "oidc",
        discoveryUrl: `${OIDC_ISSUER.replace(/\/$/, "")}/.well-known/openid-configuration`,
        // Verbatim: Authentik advertises a trailing slash and normalising it
        // away breaks discovery.
        issuer: OIDC_ISSUER,
        clientId: OIDC_CLIENT_ID,
        clientSecret: OIDC_CLIENT_SECRET,
        scopes: ["openid", "profile", "email"],
        pkce: true,
        // Sign-up is gated in `databaseHooks.user.create.before`, not by an
        // interstitial "complete sign-up" step.
        disableImplicitSignUp: false,
      },
    ]
  : [];

export const auth = betterAuth({
  appName: "OneCLI",
  baseURL: APP_URL,
  secret: AUTH_SECRET,

  database: prismaAdapter(db, { provider: "postgresql" }),

  user: {
    additionalFields: {
      /**
       * Declared so Better Auth can write `external_auth_id`, which is NOT NULL
       * and unique. Written only by the create hook below; `input: false` stops
       * a client picking its own value and claiming another user's.
       */
      externalAuthId: {
        type: "string",
        input: false,
        returned: false,
      },
    },
  },
  session: { modelName: "authSession" },
  account: {
    modelName: "authAccount",
    accountLinking: {
      /**
       * Implicit linking otherwise requires the IdP to assert `email_verified`,
       * and Authentik's built-in email mapping returns a hardcoded `false` — it
       * has no verification concept — so every SSO login onto an existing row
       * fails with ACCOUNT_NOT_LINKED. Trusting the configured provider says
       * the instance's own directory is authoritative for its identities.
       * Enumerated, not blanket: only the provider this deployment configures.
       */
      trustedProviders: oidcConfigured ? ["oidc"] : [],
    },
  },
  verification: { modelName: "authVerification" },

  emailAndPassword: {
    enabled: true,
    // Read once at construction, so it cannot express an admin-changeable
    // setting. Sign-up is gated in `databaseHooks.user.create.before` instead.
    disableSignUp: false,
    password: {
      hash: hashPassword,
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
    // Explicit: the default is production-only.
    enabled: true,
    // Survives a container restart, unlike the default in-memory store.
    storage: "database",
    modelName: "authRateLimit",
  },

  advanced: {
    database: {
      // `users.id` is the target of relations that already hold UUIDs.
      generateId: "uuid",
    },
    ipAddress: {
      // Needed behind the reverse proxy; without it rate limiting degrades to
      // one shared bucket per path.
      ipAddressHeaders: ["x-forwarded-for", "x-real-ip"],
    },
  },

  databaseHooks: {
    user: {
      create: {
        /**
         * The sign-up gate and the `external_auth_id` writer.
         *
         * Gating here rather than on a route is what distinguishes a new
         * identity from a returning one — the OAuth routes cannot. Throwing
         * `APIError` aborts the insert with a real status; returning `false`
         * surfaces as an opaque 500.
         */
        before: async (user, ctx) => {
          // Anything reaching a user insert from outside `/sign-up/*` is an
          // OAuth first login; an unknown path takes the stricter of the two.
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

          // `external_auth_id` has no default, so it must be part of this
          // insert — `create.after` runs post-commit, too late.
          const id = crypto.randomUUID();
          return { data: { ...user, id, externalAuthId: id } };
        },
      },
    },
  },

  plugins: [
    genericOAuth({ config: oidcProviders }),
    // Must be last: it writes Set-Cookie via next/headers on the way out.
    nextCookies(),
  ],
});

export type Auth = typeof auth;
