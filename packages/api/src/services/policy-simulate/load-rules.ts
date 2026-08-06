import { db, Prisma } from "@onecli/db";
import type { PolicyScopeBase } from "../../services/policy-service";

// The rule read behind the reflections, mirroring the gateway's load rather
// than the editor's `listPolicyRules`: enabled rules only, persisted Default
// Rules included, published pinned to the active max generation. A missing
// default means "this level contributes no verdict".

const SIM_INCLUDE = {
  identities: true,
  targets: true,
} satisfies Prisma.PolicyRuleV2Include;

export type SimRuleRow = Prisma.PolicyRuleV2GetPayload<{
  include: typeof SIM_INCLUDE;
}>;

const loadRules = async (
  base: PolicyScopeBase,
  status: "draft" | "published",
  includeEquipment: boolean,
): Promise<SimRuleRow[]> => {
  const where: Prisma.PolicyRuleV2WhereInput = {
    ...base,
    status,
    enabled: true,
    ...(includeEquipment ? {} : { source: { not: "equipment" } }),
  };
  if (status === "published") {
    const agg = await db.policyRuleV2.aggregate({
      where: { ...base, status: "published" },
      _max: { generation: true },
    });
    if (agg._max.generation === null) return [];
    where.generation = agg._max.generation;
  }
  return db.policyRuleV2.findMany({
    where,
    include: SIM_INCLUDE,
    orderBy: [{ priority: "asc" }, { id: "asc" }],
  });
};

/** The decision set — what block/allow evaluates; `equipment` rows are
 * dropped. */
export const loadRulesForSimulation = (
  base: PolicyScopeBase,
  status: "draft" | "published",
): Promise<SimRuleRow[]> => loadRules(base, status, false);

/**
 * The injection set — which credentials a selective agent receives. Keeps
 * `equipment` rows: they inject a credential without permitting its host, so
 * they belong here and not in the decision set.
 */
export const loadInjectionRules = (
  base: PolicyScopeBase,
  status: "draft" | "published",
): Promise<SimRuleRow[]> => loadRules(base, status, true);
