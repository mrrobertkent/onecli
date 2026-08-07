"use server";

import "@/lib/init/server";
import { headers } from "next/headers";
import { auth } from "@/lib/auth/better-auth-config";
import { RECOVERY_REFUSED } from "@/lib/auth/recovery-endpoint";

export interface RedeemRecoveryResult {
  ok: boolean;
  error?: string;
}

/**
 * Redeem a host-minted recovery key, signing the operator in.
 *
 * The work is in the auth library's own endpoint (`recovery-endpoint.ts`),
 * which is the only place a session can be minted without a password. Every
 * failure returns the same message, so this catches rather than inspects.
 */
export const redeemRecoveryKey = async (
  key: string,
): Promise<RedeemRecoveryResult> => {
  try {
    await auth.api.redeemRecoveryKey({
      body: { key },
      headers: await headers(),
    });
    return { ok: true };
  } catch (err) {
    console.warn("[onecli] recovery key redemption refused", err);
    return { ok: false, error: RECOVERY_REFUSED };
  }
};
