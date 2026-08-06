import { initRoleResolver, initSessionEnforcer } from "@onecli/api/providers";
import { eeOverrides } from "@/lib/init/api";

/**
 * Provider registration for the Next server runtime, which never reaches
 * `createApiApp`. Without the role resolver `canAccessProjectAsUser` denies
 * everyone; without the enforcer the access gate isn't applied here at all.
 * Sourced from `eeOverrides` so the two runtimes cannot drift.
 */
if (eeOverrides?.roleResolver) initRoleResolver(eeOverrides.roleResolver);
if (eeOverrides?.sessionEnforcer)
  initSessionEnforcer(eeOverrides.sessionEnforcer);
