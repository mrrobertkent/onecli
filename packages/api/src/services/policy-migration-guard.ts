import { db } from "@onecli/db";
import { logger } from "../lib/logger";

/**
 * Boot check for scopes that still carry old-model rules but have no
 * materialized v2 policy — the v2 engine decides allow on an empty rule set, so
 * those scopes silently enforce nothing.
 *
 * On OSS it runs after `services/policy-legacy-migration/`, so anything it
 * reports is what the conversion could not cover. Never migrates, and never
 * throws into boot.
 */
export const guardUnmigratedPolicy = async (): Promise<void> => {
  try {
    // Distinct scopes that still carry old-model rules. A scope counts as
    // migrated once it has a published v2 Default Rule.
    const [legacyProjects, legacyOrgs] = await Promise.all([
      db.policyRule.findMany({
        where: { projectId: { not: null } },
        distinct: ["projectId"],
        select: { projectId: true },
      }),
      db.policyRule.findMany({
        where: { scope: "organization", organizationId: { not: null } },
        distinct: ["organizationId"],
        select: { organizationId: true },
      }),
    ]);
    if (legacyProjects.length === 0 && legacyOrgs.length === 0) return;

    const stranded: string[] = [];
    for (const { projectId } of legacyProjects) {
      if (!projectId) continue;
      const migrated = await db.policyRuleV2.findFirst({
        where: {
          scope: "project",
          projectId,
          isDefault: true,
          status: "published",
        },
        select: { id: true },
      });
      if (!migrated) stranded.push(`project:${projectId}`);
    }
    for (const { organizationId } of legacyOrgs) {
      if (!organizationId) continue;
      const migrated = await db.policyRuleV2.findFirst({
        where: {
          scope: "organization",
          organizationId,
          isDefault: true,
          status: "published",
        },
        select: { id: true },
      });
      if (!migrated) stranded.push(`organization:${organizationId}`);
    }
    if (stranded.length === 0) return;

    const shown = stranded.slice(0, 20).join(", ");
    logger.error(
      `[policy-migration-guard] ${stranded.length} scope(s) have legacy policy rules but no materialized v2 policy — the gateway will NOT enforce their policies (it decides allow-all on an empty rule set). On OSS the boot conversion runs immediately before this check, so these are scopes it could not cover: look for a preceding [policy-legacy-migration] error, or an organization-scoped legacy rule (OSS has no org policy). Re-author the affected policy in the Policy console. The old tables are retained, so nothing is lost. Affected: ${shown}${stranded.length > 20 ? " …" : ""}`,
    );
  } catch (err) {
    // Best-effort only — a diagnostic must never take down boot.
    logger.error({ err }, "[policy-migration-guard] check failed (ignored)");
  }
};
