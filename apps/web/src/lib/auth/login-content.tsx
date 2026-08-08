"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Image from "next/image";
import { Loader2 } from "lucide-react";
import { Button } from "@onecli/ui/components/button";
import { Input } from "@onecli/ui/components/input";
import { Label } from "@onecli/ui/components/label";
import { useAuth } from "@/providers/auth-provider";
import { authClient } from "@/lib/auth/auth-client";
import { apiFetch } from "@/lib/api-fetch";
import { CAPS } from "@/lib/env";

export interface LoginContentProps {
  /** The stored login-method setting, plus anything recovery is lending. */
  passwordLogin?: boolean;
  /** False when no identity provider is configured, so the button is a dead end. */
  ssoConfigured?: boolean;
}

export const LoginContent = ({
  passwordLogin = false,
  ssoConfigured = true,
}: LoginContentProps) => {
  const router = useRouter();
  const {
    isAuthenticated,
    isLoading,
    user,
    signIn,
    signOut,
    authProviderId,
    authProviderName,
    authProviderLogo,
    authProviderColor,
    authProviderTextColor,
    authProviderLogoOnly,
  } = useAuth();
  const [signingIn, setSigningIn] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Google keeps its branded button; any other provider (generic OIDC) gets a
  // neutral button labelled with the configured provider name, optionally
  // branded with the logo and colour the operator configured.
  const isGoogle = authProviderId === "google";
  const brandColor = isGoogle ? "" : normalizeHex(authProviderColor);
  const brandLogo = isGoogle ? "" : authProviderLogo;
  // Explicit foreground wins; otherwise derive the more legible of black/white.
  const brandText =
    (isGoogle ? "" : normalizeHex(authProviderTextColor)) ||
    (brandColor ? readableOn(brandColor) : "");
  // A lockup already contains the provider's wordmark, so repeating the name
  // beside it would duplicate it and re-set it in this app's typeface. A bare
  // mark does not, so it keeps the name; with no artwork at all the label needs
  // the verb to read as an action.
  const logoOnly = brandLogo !== "" && authProviderLogoOnly;
  const oidcLabel = brandLogo
    ? authProviderName
    : `Continue with ${authProviderName}`;

  useEffect(() => {
    if (!isAuthenticated || !user) return;

    const syncUser = async () => {
      try {
        const res = await apiFetch("/v1/auth/session");
        if (res.ok) {
          const data = (await res.json()) as { projectId?: string };
          if (CAPS.webSurface === "connect-only") {
            router.replace("/app-connect");
            return;
          }
          router.replace(
            data.projectId ? `/p/${data.projectId}/overview` : "/overview",
          );
        } else if (res.status === 401) {
          await signOut();
        }
      } catch {
        // Transient error (deploy, network) — don't sign out
      }
    };

    syncUser();
  }, [isAuthenticated, user, router, signOut]);

  const onPasswordSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPasswordError(null);
    setSubmitting(true);

    const { error } = await authClient.signIn.email({ email, password });
    if (error) {
      setPasswordError(error.message ?? "That did not work. Try again.");
      setSubmitting(false);
      return;
    }

    // A full load, the same as the identity provider's callback: it re-enters
    // this page with the session already established, and the effect above
    // routes on to the right project.
    window.location.assign("/");
  };

  return (
    <div className="bg-background flex min-h-svh flex-col items-center justify-center px-6 pb-24">
      <div className="mb-8">
        <Image
          src="/onecli-full-logo.png"
          alt="onecli"
          width={140}
          height={40}
          priority
          className="dark:hidden"
        />
        <Image
          src="/onecli-full-logo-dark.png"
          alt="onecli"
          width={140}
          height={40}
          priority
          className="hidden dark:block"
        />
      </div>

      {isLoading || isAuthenticated ? (
        <div className="flex flex-col items-center gap-4 py-20">
          <div className="text-brand h-8 w-8 animate-spin rounded-full border-2 border-current border-t-transparent" />
          <p className="text-muted-foreground text-sm">
            {isAuthenticated ? "Signing you in..." : "Loading..."}
          </p>
        </div>
      ) : (
        <>
          <div className="mb-8 text-center">
            <h1 className="font-[family-name:var(--font-serif)] text-4xl font-semibold tracking-tight sm:text-5xl">
              Log in
            </h1>
            <p className="text-muted-foreground mt-3 text-lg">
              Continue with your account to
              <br />
              authenticate connections
            </p>
          </div>

          <div className="w-full max-w-sm rounded-2xl border border-border/50 bg-card p-8">
            {/* Credentials first, identity provider under them: the order every
                sign-in screen uses, and the one that puts the fields a returning
                operator types into under their cursor. */}
            {passwordLogin && (
              <form onSubmit={onPasswordSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="username"
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    required
                  />
                </div>

                {passwordError && (
                  <p className="text-destructive text-sm" role="alert">
                    {passwordError}
                  </p>
                )}

                <Button type="submit" className="w-full" disabled={submitting}>
                  {submitting ? (
                    <>
                      <Loader2 className="size-4 animate-spin" />
                      Signing in...
                    </>
                  ) : (
                    "Sign in"
                  )}
                </Button>
              </form>
            )}

            {passwordLogin && ssoConfigured && (
              <div className="my-6 flex items-center gap-3">
                <span className="bg-border h-px flex-1" />
                <span className="text-muted-foreground text-xs uppercase">
                  or
                </span>
                <span className="bg-border h-px flex-1" />
              </div>
            )}

            {ssoConfigured && (
              <Button
                size="lg"
                variant="outline"
                className={
                  isGoogle
                    ? "w-full gap-2 text-base bg-white text-black hover:bg-gray-100 dark:bg-white dark:text-black dark:hover:bg-gray-100"
                    : "w-full gap-2 text-base"
                }
                // Inline rather than a class: the value is operator-supplied at
                // runtime, so Tailwind cannot have generated a utility for it.
                // `filter` dims on hover, which works against any hue without
                // needing a second configured colour.
                style={
                  brandColor
                    ? {
                        backgroundColor: brandColor,
                        color: brandText,
                        borderColor: brandColor,
                      }
                    : undefined
                }
                loading={signingIn}
                onClick={() => {
                  setSigningIn(true);
                  signIn();
                }}
              >
                {isGoogle && <GoogleIcon />}
                {!isGoogle && brandLogo && (
                  // Plain <img>: the source is arbitrary operator input, so it
                  // must not go through next/image's configured-domain
                  // allowlist. A lockup keeps its own aspect ratio and carries
                  // the accessible name; a bare mark is a fixed square and is
                  // decorative, because the visible label already names the
                  // provider.
                  // eslint-disable-next-line @next/next/no-img-element
                  <img
                    src={brandLogo}
                    alt={logoOnly ? authProviderName : ""}
                    aria-hidden={logoOnly ? undefined : true}
                    className={logoOnly ? "h-5 w-auto" : "h-4 w-4"}
                  />
                )}
                {signingIn
                  ? "Redirecting..."
                  : isGoogle
                    ? "Continue with Google"
                    : logoOnly
                      ? null
                      : oidcLabel}
              </Button>
            )}

            {!passwordLogin && !ssoConfigured && (
              // Unreachable unless the settings row cannot be read: password
              // login is available whenever it is the only method configured.
              <p className="text-muted-foreground text-sm leading-relaxed">
                No login method is available. Mint a recovery key on the host
                with{" "}
                <code className="text-foreground">
                  onecli-gateway create-recovery-key
                </code>{" "}
                and open the link it prints.
              </p>
            )}

            <p className="text-muted-foreground mt-4 text-center text-xs">
              By continuing, you acknowledge OneCLI&apos;s{" "}
              <a
                href="https://onecli.sh/privacy"
                className="underline hover:text-foreground"
              >
                Privacy Policy
              </a>
              .
            </p>
          </div>
        </>
      )}
    </div>
  );
};

/**
 * Accept `#rgb`, `#rrggbb`, or the same without the leading `#`, and reject
 * anything else. The value reaches the DOM as an inline style, so it is
 * validated rather than interpolated blindly.
 */
const normalizeHex = (value: string): string => {
  const v = value.trim().replace(/^#/, "");
  if (!/^([0-9a-f]{3}|[0-9a-f]{6})$/i.test(v)) return "";
  const full =
    v.length === 3
      ? v
          .split("")
          .map((c) => c + c)
          .join("")
      : v;
  return `#${full.toLowerCase()}`;
};

/**
 * Black or white, whichever is legible on `hex`. Uses the WCAG relative
 * luminance formula so the operator configures one value and cannot end up with
 * unreadable text — a light brand colour gets dark text and vice versa.
 */
const readableOn = (hex: string): string => {
  const n = parseInt(hex.slice(1), 16);
  const channel = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  const luminance =
    0.2126 * channel((n >> 16) & 255) +
    0.7152 * channel((n >> 8) & 255) +
    0.0722 * channel(n & 255);
  return luminance > 0.179 ? "#000000" : "#ffffff";
};

const GoogleIcon = () => (
  <svg
    className="h-4 w-4"
    viewBox="-3 0 262 262"
    xmlns="http://www.w3.org/2000/svg"
  >
    <path
      d="M255.878 133.451c0-10.734-.871-18.567-2.756-26.69H130.55v48.448h71.947c-1.45 12.04-9.283 30.172-26.69 42.356l-.244 1.622 38.755 30.023 2.685.268c24.659-22.774 38.875-56.282 38.875-96.027"
      fill="#4285F4"
    />
    <path
      d="M130.55 261.1c35.248 0 64.839-11.605 86.453-31.622l-41.196-31.913c-11.024 7.688-25.82 13.055-45.257 13.055-34.523 0-63.824-22.773-74.269-54.25l-1.531.13-40.298 31.187-.527 1.465C35.393 231.798 79.49 261.1 130.55 261.1"
      fill="#34A853"
    />
    <path
      d="M56.281 156.37c-2.756-8.123-4.351-16.827-4.351-25.82 0-8.994 1.595-17.697 4.206-25.82l-.073-1.73L15.26 71.312l-1.335.635C5.077 89.644 0 109.517 0 130.55s5.077 40.905 13.925 58.602l42.356-32.782"
      fill="#FBBC05"
    />
    <path
      d="M130.55 50.479c24.514 0 41.05 10.589 50.479 19.438l36.844-35.974C195.245 12.91 165.798 0 130.55 0 79.49 0 35.393 29.301 13.925 71.947l42.211 32.783c10.59-31.477 39.891-54.251 74.414-54.251"
      fill="#EB4335"
    />
  </svg>
);
