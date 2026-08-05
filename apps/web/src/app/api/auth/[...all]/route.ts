import { toNextJsHandler } from "better-auth/next-js";
import { auth } from "@/lib/auth/better-auth-config";

/**
 * Better Auth's catch-all mount (design D-9), replacing next-auth's
 * `[...nextauth]`.
 *
 * DEPLOYMENT-FACING: the generic-OIDC callback path CHANGES. next-auth used
 * `/api/auth/callback/oidc`; Better Auth's `genericOAuth` uses
 * `/api/auth/oauth2/callback/oidc`. The redirect URI must be updated in the
 * IdP or every login fails at the callback. Google is unaffected — its social
 * callback is `/api/auth/callback/google` in both.
 */
export const { GET, POST } = toNextJsHandler(auth);
