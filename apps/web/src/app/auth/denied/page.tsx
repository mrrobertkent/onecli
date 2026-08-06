import Image from "next/image";
import { ShieldX } from "lucide-react";

/**
 * Terminal page for a session that authenticated but was NOT authorised
 *.
 *
 * The loop this exists to prevent: `/v1/auth/session` returns 401, the
 * dashboard signs the user out and sends them to the login page, they are still
 * signed in at the IdP so the next click silently re-authenticates, and they
 * land on 401 again — forever, with no explanation. This page is a dead end on
 * purpose: no automatic redirect, and no sign-in button.
 */

const DENIALS: Record<string, { title: string; description: string }> = {
  NOT_AUTHORISED: {
    title: "Access not granted",
    description:
      "You signed in successfully, but your account has not been granted access to this instance. An administrator has to grant it before you can continue.",
  },
  AUTHORISATION_UNAVAILABLE: {
    title: "Access could not be verified",
    description:
      "Your access could not be checked just now. This is usually temporary — try again shortly. If it persists, an administrator should check the server logs.",
  },
  SIGNUP_CLOSED: {
    title: "Not accepting new accounts",
    description:
      "This instance is not currently accepting new accounts. An administrator can enable sign-up or create an account for you.",
  },
};

const FALLBACK = {
  title: "Access denied",
  description:
    "You signed in, but this instance did not authorise the session. An administrator can check the server logs for the reason.",
};

export default async function AuthDeniedPage({
  searchParams,
}: {
  searchParams: Promise<{ code?: string }>;
}) {
  const { code } = await searchParams;
  // Unknown codes fall back rather than redirecting — a redirect from here is
  // the loop this page exists to break.
  const denial = (code && DENIALS[code]) || FALLBACK;

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

      <div className="border-destructive/50 bg-card w-full max-w-md rounded-2xl border p-8">
        <div className="flex items-center gap-3">
          <div className="bg-destructive/10 flex size-9 shrink-0 items-center justify-center rounded-full">
            <ShieldX className="text-destructive size-4" />
          </div>
          <h1 className="text-base font-medium">{denial.title}</h1>
        </div>
        <p className="text-muted-foreground mt-4 text-sm leading-relaxed">
          {denial.description}
        </p>
      </div>
    </div>
  );
}
