import { db } from "@onecli/db";
import { logger } from "../lib/logger";

/**
 * The instance sign-up gate. It lives here rather than in Better Auth's
 * `disableSignUp` so an admin can change the setting at runtime.
 *
 * Every path out of this module that is not an explicit, recognised permission
 * denies: unreadable row, database error, unknown value.
 */

export const SIGNUP_MODES = ["closed", "sso-only", "open"] as const;
export type SignupMode = (typeof SIGNUP_MODES)[number];

/** How an identity is trying to provision itself. */
export type SignupKind = "password" | "sso";

const isSignupMode = (value: string): value is SignupMode =>
  (SIGNUP_MODES as readonly string[]).includes(value);

/**
 * The persisted mode, or `"closed"` if it cannot be established for any reason.
 * A missing row and an unreachable database are not distinguished — both refuse
 * to provision strangers.
 */
export const getSignupMode = async (): Promise<SignupMode> => {
  try {
    const row = await db.instanceSetting.findUnique({
      where: { id: "instance" },
      select: { signupMode: true },
    });
    if (!row) return "closed";
    if (!isSignupMode(row.signupMode)) {
      // A value this build does not recognise. Logged loudly, because it is a
      // silent lockout otherwise.
      logger.error(
        { signupMode: row.signupMode },
        "unrecognised signupMode; denying sign-up",
      );
      return "closed";
    }
    return row.signupMode;
  } catch (err) {
    logger.error({ err }, "signupMode read failed; denying sign-up");
    return "closed";
  }
};

/**
 * Whether a self-provisioning attempt of this kind is permitted right now.
 *
 * `sso` is permitted under both `sso-only` and `open`; `password` only under
 * `open`. Note this answers "may this identity be PROVISIONED", not "may it
 * sign in" — an existing user signing in is not a sign-up and never reaches
 * this gate.
 */
export const isSignupAllowed = async (kind: SignupKind): Promise<boolean> => {
  const mode = await getSignupMode();
  if (mode === "open") return true;
  if (mode === "sso-only") return kind === "sso";
  return false;
};

/**
 * Set the mode. Returns the previous value so the caller can audit both sides:
 * this setting's audit entry is uninterpretable without the old value.
 */
export const setSignupMode = async (
  mode: SignupMode,
  updatedByUserId: string,
): Promise<{ previous: SignupMode; next: SignupMode }> => {
  const previous = await getSignupMode();
  await db.instanceSetting.upsert({
    where: { id: "instance" },
    create: { id: "instance", signupMode: mode, updatedByUserId },
    update: { signupMode: mode, updatedByUserId },
  });
  return { previous, next: mode };
};
