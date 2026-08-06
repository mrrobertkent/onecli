import { findOrCreateSharedOrg } from "@onecli/api/services/organization-service";
import { seedBootstrapAdminFromEnv } from "@/lib/auth/bootstrap-admin";

/**
 * Eager boot init: the shared organization, and the bootstrap administrator if
 * one is configured in the environment.
 *
 * The operator org API key is minted with the administrator, not here:
 * `ApiKey.user` is `ON DELETE RESTRICT`, so its owner must be a real loginable
 * account rather than a synthetic row.
 *
 * Idempotent and safe on every boot: a configured seed is applied only while
 * the instance has no administrator.
 */
export const ensureOnpremInstance = async (): Promise<void> => {
  const org = await findOrCreateSharedOrg();

  // Operators need the org id for org-scoped API calls, so surface it once.
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
