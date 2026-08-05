"use client";

import { createAuthClient } from "better-auth/react";
import { genericOAuthClient } from "better-auth/client/plugins";

/**
 * Browser-side Better Auth client (design D-9).
 *
 * `genericOAuthClient()` is what surfaces `signIn.oauth2({providerId})`. The
 * generic-OIDC provider is NOT reachable through `signIn.social({provider})` —
 * that only addresses Better Auth's closed built-in registry, which has no
 * generic OIDC entry.
 *
 * No `baseURL`: the client defaults to the current origin, which is correct for
 * a self-hosted instance behind any hostname the operator chooses.
 */
export const authClient = createAuthClient({
  plugins: [genericOAuthClient()],
});

export const { useSession, signIn, signOut } = authClient;
