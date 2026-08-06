"use client";

import { createAuthClient } from "better-auth/react";
import { genericOAuthClient } from "better-auth/client/plugins";

/**
 * Browser-side Better Auth client. `genericOAuthClient()` is what surfaces
 * `signIn.oauth2({providerId})`; the generic-OIDC provider is not reachable
 * through `signIn.social()`.
 *
 * No `baseURL`, so the client defaults to the current origin — correct for a
 * self-hosted instance behind any hostname.
 */
export const authClient = createAuthClient({
  plugins: [genericOAuthClient()],
});

export const { useSession, signIn, signOut } = authClient;
