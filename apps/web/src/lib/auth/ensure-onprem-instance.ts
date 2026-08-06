import { findOrCreateSharedOrg } from "@onecli/api/services/organization-service";
import { seedBootstrapAdminFromEnv } from "@/lib/auth/bootstrap-admin";

/**
 * Eager boot init: the shared organization, and the bootstrap administrator if
 * one is configured in the environment.
 *
 * The operator org API key is NOT minted here. It is minted with the
 * administrator, because `ApiKey.user` is `ON DELETE RESTRICT` — whoever owns
 * it can never be deleted, so it must belong to a real, loginable account
 * rather than to a synthetic row conjured to hold it. With no environment seed
 * there is nobody to own it yet, and it appears when the first admin is
 * claimed.
 *
 * Idempotent, and safe on every boot: a configured seed is applied only while
 * the instance has no administrator.
 */
export const ensureOnpremInstance = async (): Promise<void> => {
  const org = await findOrCreateSharedOrg();

  // Operators need the org id for org-scoped API calls (e.g. the authorize
  // `?org=` override) — surface it once per boot.
  console.info(`[onecli] Shared organization id: ${org.id}`);

  const admin = await seedBootstrapAdminFromEnv();
  if (admin) {
    console.info(
      `[onecli] Seeded bootstrap administrator: ${admin.email}` +
        (admin.mustChangePassword
          ? " (must change password at first login)"
          : ""),
    );
    return;
  }

  console.info(
    "[onecli] No administrator yet. Claim one at /setup within 15 minutes of " +
      "this start, or set BOOTSTRAP_ADMIN_EMAIL with " +
      "BOOTSTRAP_ADMIN_PASSWORD_HASH and restart.",
  );
};
