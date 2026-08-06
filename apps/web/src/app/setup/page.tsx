import Image from "next/image";
import { ShieldX } from "lucide-react";
import { claimWindow } from "@/lib/auth/bootstrap-admin";
import { getAuthMode } from "@/lib/auth/auth-mode";
import { SetupForm } from "@/app/setup/_components/setup-form";

/**
 * First-administrator setup.
 *
 * Reachable only while the instance has no administrator and the window opened
 * by this process start has not closed. Both are re-checked in the action that
 * performs the claim — what is rendered here is a snapshot and decides nothing.
 */

const CLOSED = {
  "already-claimed": {
    title: "Already set up",
    description:
      "This instance already has an administrator. Sign in instead, or ask them to grant you access.",
  },
  "window-expired": {
    title: "Setup window closed",
    description:
      "The window for claiming the first administrator has closed. Restart the instance to reopen it, or configure BOOTSTRAP_ADMIN_EMAIL with BOOTSTRAP_ADMIN_PASSWORD_HASH and restart.",
  },
} as const;

const Shell = ({ children }: { children: React.ReactNode }) => (
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
    <div className="bg-card w-full max-w-md rounded-2xl border p-8">
      {children}
    </div>
  </div>
);

export default async function SetupPage() {
  // Local auth has a single implicit operator and no login, so there is no
  // first administrator to claim.
  const window =
    getAuthMode() === "local"
      ? ({ claimable: false, reason: "already-claimed" } as const)
      : await claimWindow();

  if (!window.claimable) {
    const closed = CLOSED[window.reason];
    return (
      <Shell>
        <div className="flex items-center gap-3">
          <div className="bg-destructive/10 flex size-9 shrink-0 items-center justify-center rounded-full">
            <ShieldX className="text-destructive size-4" />
          </div>
          <h1 className="text-base font-medium">{closed.title}</h1>
        </div>
        <p className="text-muted-foreground mt-4 text-sm leading-relaxed">
          {closed.description}
        </p>
      </Shell>
    );
  }

  return (
    <Shell>
      <h1 className="text-base font-medium">Create the first administrator</h1>
      <p className="text-muted-foreground mt-2 text-sm leading-relaxed">
        This instance has no administrator yet. The account created here owns
        the organization and can grant access to everyone else.
      </p>
      <p className="text-muted-foreground mt-2 text-sm leading-relaxed">
        This page stops accepting claims at{" "}
        <time dateTime={window.expiresAt.toISOString()} className="font-medium">
          {window.expiresAt.toLocaleTimeString()}
        </time>
        . Restart the instance to reopen it.
      </p>
      <SetupForm />
    </Shell>
  );
}
