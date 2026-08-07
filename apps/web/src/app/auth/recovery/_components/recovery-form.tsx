"use client";

import { useState } from "react";
import { ShieldCheck, Loader2 } from "lucide-react";
import { Button } from "@onecli/ui/components/button";
import { redeemRecoveryKey } from "@/lib/actions/redeem-recovery-key";

export interface RecoveryFormProps {
  recoveryKey: string;
}

export const RecoveryForm = ({ recoveryKey }: RecoveryFormProps) => {
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    const result = await redeemRecoveryKey(recoveryKey);
    if (!result.ok) {
      setError(result.error ?? "Something went wrong.");
      setSubmitting(false);
      return;
    }

    // A full load, not router.replace: the session was created server-side, so
    // the client's session state still says signed-out and a client-side
    // navigation would carry that to the dashboard, which bounces it to login.
    window.location.assign("/overview");
  };

  if (!recoveryKey) {
    return (
      <div className="border-destructive/50 bg-card w-full max-w-sm rounded-2xl border p-8">
        <p className="text-muted-foreground text-sm leading-relaxed">
          This page needs a recovery key. Mint one on the host with{" "}
          <code className="text-foreground">
            onecli-gateway create-recovery-key
          </code>{" "}
          and open the link it prints.
        </p>
      </div>
    );
  }

  return (
    <div className="border-border/50 bg-card w-full max-w-sm rounded-2xl border p-8">
      <form onSubmit={onSubmit} className="space-y-4">
        <p className="text-muted-foreground text-sm leading-relaxed">
          This signs you in without the identity provider and turns password
          login on for a limited time. Your password and your identity provider
          settings are left exactly as they are.
        </p>

        {error && (
          <p className="text-destructive text-sm" role="alert">
            {error}
          </p>
        )}

        <Button type="submit" className="w-full" disabled={submitting}>
          {submitting ? (
            <>
              <Loader2 className="size-4 animate-spin" />
              Signing you in...
            </>
          ) : (
            <>
              <ShieldCheck className="size-4" />
              Sign in with this key
            </>
          )}
        </Button>
      </form>
    </div>
  );
};
