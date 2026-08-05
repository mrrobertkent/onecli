"use client";

import { useCallback, useMemo, type ReactNode } from "react";
import { useSession, signIn, signOut } from "@/lib/auth/auth-client";
import { AuthContext } from "@/providers/auth-provider";
import type { AuthUser, AuthContextValue } from "@/lib/auth/types";
import type { AuthMode, AuthProviderInfo } from "@/lib/auth/auth-mode";

const LOCAL_USER: AuthUser = {
  id: "local-admin",
  email: "admin@localhost",
  name: "Admin",
};

const LocalAuthProvider = ({ children }: { children: ReactNode }) => {
  const value = useMemo<AuthContextValue>(
    () => ({
      isAuthenticated: true,
      isLoading: false,
      user: LOCAL_USER,
      signIn: async () => {},
      signOut: async () => {},
      authProviderId: "",
      authProviderName: "",
      authProviderLogo: "",
      authProviderColor: "",
      authProviderTextColor: "",
      authProviderLogoOnly: false,
    }),
    [],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

const OAuthInner = ({
  children,
  authProvider,
}: {
  children: ReactNode;
  authProvider: AuthProviderInfo;
}) => {
  // Better Auth returns `{data, isPending}` rather than next-auth's `status`
  // string. `data` is the session or null once settled.
  const { data: session, isPending } = useSession();

  const user = useMemo<AuthUser | null>(() => {
    if (!session?.user?.id || !session.user.email) return null;
    return {
      id: session.user.id,
      email: session.user.email,
      name: session.user.name ?? undefined,
      emailVerified: session.user.emailVerified,
    };
  }, [session]);

  const handleSignIn = useCallback(async () => {
    // The generic OIDC provider lives behind `signIn.oauth2`, NOT
    // `signIn.social` — the latter only addresses Better Auth's closed built-in
    // registry, which has no generic OIDC entry. Google, being a built-in, is
    // the one case that goes through `social`.
    if (authProvider.id === "google") {
      await signIn.social({ provider: "google", callbackURL: "/" });
      return;
    }
    await signIn.oauth2({ providerId: authProvider.id, callbackURL: "/" });
  }, [authProvider.id]);

  const handleSignOut = useCallback(async () => {
    await signOut();
    window.location.href = "/auth/login";
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      isAuthenticated: Boolean(session?.user),
      isLoading: isPending,
      user,
      signIn: handleSignIn,
      signOut: handleSignOut,
      authProviderId: authProvider.id,
      authProviderName: authProvider.name,
      authProviderLogo: authProvider.logo,
      authProviderColor: authProvider.color,
      authProviderTextColor: authProvider.textColor,
      authProviderLogoOnly: authProvider.logoOnly,
    }),
    [
      session,
      isPending,
      user,
      handleSignIn,
      handleSignOut,
      authProvider.id,
      authProvider.name,
      authProvider.logo,
      authProvider.color,
      authProvider.textColor,
      authProvider.logoOnly,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const AuthProviderImpl = ({
  children,
  authMode,
  authProvider,
}: {
  children: ReactNode;
  authMode: AuthMode;
  authProvider: AuthProviderInfo;
}) => {
  if (authMode === "local") {
    return <LocalAuthProvider>{children}</LocalAuthProvider>;
  }

  // No provider wrapper: Better Auth's `useSession` reads from a nanostores
  // atom held by the client singleton, so there is no React context to mount
  // (next-auth's `<SessionProvider>` had no equivalent here).
  return <OAuthInner authProvider={authProvider}>{children}</OAuthInner>;
};
