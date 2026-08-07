"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ShieldAlert } from "lucide-react";
import { Button } from "@onecli/ui/components/button";
import {
  getRecoveryBannerState,
  enablePasswordLoginPermanently,
  leaveRecoveryMode,
  type RecoveryBannerState,
} from "@/lib/actions/recovery-mode";

/**
 * Says the instance is in recovery mode, and offers the three ways out of it.
 * Renders nothing at all otherwise, which is every other minute of the
 * instance's life.
 */
export const RecoveryBanner = () => {
  const [state, setState] = useState<RecoveryBannerState | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setState(await getRecoveryBannerState());
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (!state) return null;

  const until = new Date(state.expiresAt).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });

  const run = async (
    action: () => Promise<{ ok: boolean; error?: string }>,
  ) => {
    setBusy(true);
    setError(null);
    const result = await action();
    if (!result.ok) {
      setError(result.error ?? "Something went wrong.");
      setBusy(false);
      return;
    }
    await load();
    setBusy(false);
  };

  return (
    <div
      role="status"
      className="border-b border-amber-500/40 bg-amber-500/10 px-4 py-3 sm:px-6"
    >
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <ShieldAlert className="size-4 shrink-0 text-amber-600 dark:text-amber-500" />
        <p className="text-sm">
          <span className="font-medium">Recovery mode.</span>{" "}
          {state.passwordLoginEnabled
            ? `Signed in with a recovery key. This ends at ${until}.`
            : `Password login is on until ${until}, then it turns back off.`}
        </p>

        {state.canAct && (
          <div className="ml-auto flex flex-wrap items-center gap-2">
            {!state.passwordLoginEnabled && (
              <Button
                size="sm"
                variant="outline"
                disabled={busy}
                onClick={() => run(enablePasswordLoginPermanently)}
              >
                Keep password login on
              </Button>
            )}
            <Button size="sm" variant="outline" asChild>
              <Link href="/auth/change-password">
                {state.hasPassword ? "Change password" : "Set a password"}
              </Link>
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() => run(leaveRecoveryMode)}
            >
              Exit recovery
            </Button>
          </div>
        )}

        {error && (
          <p className="text-destructive w-full text-sm" role="alert">
            {error}
          </p>
        )}
      </div>
    </div>
  );
};
