"use server";

import "@/lib/init/server";
import { headers } from "next/headers";
import { auth } from "@/lib/auth/better-auth-config";
import { getAuthMode } from "@/lib/auth/auth-mode";
import {
  BootstrapAdminAlreadyExistsError,
  claimWindow,
  establishBootstrapAdmin,
} from "@/lib/auth/bootstrap-admin";

export interface ClaimResult {
  ok: boolean;
  error?: string;
}

const GENERIC_FAILURE =
  "The administrator could not be created. Check the server logs.";

/**
 * Claim the first administrator and sign them in.
 *
 * Re-checks the window server-side rather than trusting the page that rendered
 * the form: the page's answer is a snapshot, and this is the only check that
 * decides anything.
 */
export const claimBootstrapAdmin = async (
  email: string,
  password: string,
  name?: string,
): Promise<ClaimResult> => {
  // Local auth has no login and its operator is already the sole identity, so
  // there is no first admin to claim and nothing here should be reachable.
  if (getAuthMode() === "local") {
    return { ok: false, error: GENERIC_FAILURE };
  }

  const window = await claimWindow();
  if (!window.claimable) {
    return {
      ok: false,
      error:
        window.reason === "already-claimed"
          ? "This instance already has an administrator."
          : "The setup window has closed. Restart the instance to reopen it.",
    };
  }

  const trimmedEmail = email.trim();
  if (!trimmedEmail.includes("@")) {
    return { ok: false, error: "Enter a valid email address." };
  }
  if (password.length < 12) {
    return { ok: false, error: "Use a password of at least 12 characters." };
  }

  try {
    await establishBootstrapAdmin({
      email: trimmedEmail,
      password,
      name: name?.trim() || undefined,
    });
  } catch (err) {
    if (err instanceof BootstrapAdminAlreadyExistsError) {
      return { ok: false, error: err.message };
    }
    console.error("[onecli] bootstrap admin claim failed", err);
    return { ok: false, error: GENERIC_FAILURE };
  }

  // The credential was chosen here by the person using it, so there is nothing
  // to rotate — sign them straight in.
  await auth.api.signInEmail({
    body: { email: trimmedEmail, password },
    headers: await headers(),
  });

  return { ok: true };
};
