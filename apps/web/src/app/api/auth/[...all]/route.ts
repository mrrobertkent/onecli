import { toNextJsHandler } from "better-auth/next-js";
import { auth } from "@/lib/auth/better-auth-config";

/**
 * Better Auth's catch-all mount.
 *
 * The generic-OIDC callback is `/api/auth/oauth2/callback/oidc`, which is what
 * the IdP's redirect URI has to name. Google's stays
 * `/api/auth/callback/google`.
 */
export const { GET, POST } = toNextJsHandler(auth);
