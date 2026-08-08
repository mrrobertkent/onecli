"use server";

import "@/lib/init/server";
import { isOAuthConfigured } from "@/lib/auth/auth-mode";
import {
  readLoginPolicy,
  setPasswordLoginEnabled,
  LastLoginMethodError,
} from "@/lib/auth/login-policy";
import { requireOrgRole, OrgRoleError } from "@/lib/actions/require-org-role";

export interface LoginMethods {
  /** The stored answer, which a recovery window never writes. */
  passwordLoginEnabled: boolean;
  /** Whether an identity provider is configured to switch to. */
  ssoConfigured: boolean;
  /** True while a recovery window is lending password login. */
  lentByRecovery: boolean;
}

export interface LoginMethodsResult {
  ok: boolean;
  error?: string;
}

/**
 * The instance's login methods, for the settings surface. The `admin` guard
 * sits here, not in `setPasswordLoginEnabled`, which recovery also calls.
 */
export const getLoginMethods = async (): Promise<LoginMethods> => {
  await requireOrgRole("admin");
  const policy = await readLoginPolicy();

  return {
    passwordLoginEnabled: policy.passwordLoginEnabled,
    ssoConfigured: isOAuthConfigured(),
    lentByRecovery: policy.recovery.active && !policy.passwordLoginEnabled,
  };
};

/** Turn password sign-in on or off for the instance. */
export const setPasswordLogin = async (
  enabled: boolean,
): Promise<LoginMethodsResult> => {
  let actor;
  try {
    actor = await requireOrgRole("admin");
  } catch (err) {
    if (err instanceof OrgRoleError) return { ok: false, error: err.message };
    throw err;
  }

  try {
    await setPasswordLoginEnabled({
      enabled,
      ssoAvailable: isOAuthConfigured(),
      actor: { userId: actor.userId, userEmail: actor.userEmail },
    });
  } catch (err) {
    if (err instanceof LastLoginMethodError) {
      return { ok: false, error: err.message };
    }
    throw err;
  }

  return { ok: true };
};
