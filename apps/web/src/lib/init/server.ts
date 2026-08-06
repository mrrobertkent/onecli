import { initRoleResolver, initSessionEnforcer } from "@onecli/api/providers";
import { eeOverrides } from "@/lib/init/api";

/**
 * Provider registration for the Next server runtime (server actions, RSC),
 * which never reaches `createApiApp` and so gets none of its registrations.
 *
 * Both matter: without a role resolver `canAccessProjectAsUser` denies
 * everyone, and without the enforcer the access gate is not applied here at
 * all. Sourced from `eeOverrides` so the two runtimes cannot drift.
 */
if (eeOverrides?.roleResolver) initRoleResolver(eeOverrides.roleResolver);
if (eeOverrides?.sessionEnforcer)
  initSessionEnforcer(eeOverrides.sessionEnforcer);
