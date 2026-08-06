/**
 * The one-shot legacy → v2 policy migration — see ./README.md.
 *
 * Runs on every OSS web-server boot and converts any project that still carries
 * old-model policy but never materialized v2: its custom rules, app-permission
 * rows, enabled blocklist, per-agent credential grants and the org's
 * `policyMode` become one published `policy_rules_v2` generation.
 *
 * Idempotent — a project with a published generation is skipped — and
 * best-effort: a failure is logged rather than crashing the web server, and the
 * old rows are retained so a failed run is recoverable by rebooting.
 */
import { db } from "@onecli/db";
import {
  backfillPublishScope,
  type BackfillRuleInput,
} from "../policy-service";
import {
  OSS_MIGRATED_DEFAULT_DESCRIPTION,
  ossCanonRule,
  ossProjectDefaultRule,
  translateOssEquipment,
  translateOssProjectRules,
  type OssOldRule,
} from "./translate";
import {
  OSS_OLD_RULE_SELECT,
  readOssEquipment,
  reconstructOssRule,
} from "./read-legacy";

export interface OssCutoverResult {
  /** `diverged` still leaves a generation published and enforcing. A thrown
   * error is counted by the caller, not returned. */
  status: "cut" | "skipped" | "diverged";
  ruleCount: number;
  /** Set on a skip where a user publish pre-empted the conversion: the project
   * has legacy rules but its active generation was not written here, so those
   * rules were never translated and the skip-if-published idempotency will
   * never retry. The remedy is to re-author the policy in the console. */
  preempted?: boolean;
}

/** Build the project's full initial v2 set: the ordered policy rules
 * (customs + app-permission-derived + enabled blocklist), the equipment rules
 * appended after, and the Default Rule last. */
const buildProjectRules = async (
  projectId: string,
  policyMode: string,
): Promise<{
  rules: BackfillRuleInput[];
  droppedSessionPolicies: { agentId: string; appConnectionId: string }[];
}> => {
  const oldRows = await db.policyRule.findMany({
    where: { projectId },
    select: OSS_OLD_RULE_SELECT,
    orderBy: { createdAt: "asc" },
  });
  const policySet = translateOssProjectRules(oldRows as OssOldRule[]);
  const { rules: equipment, droppedSessionPolicies } = translateOssEquipment(
    await readOssEquipment(db, projectId),
  );
  equipment.forEach((r, i) => {
    r.priority = policySet.length + i;
  });
  const defaultRule = ossProjectDefaultRule(policyMode);
  defaultRule.priority = policySet.length + equipment.length;
  return {
    rules: [...policySet, ...equipment, defaultRule],
    droppedSessionPolicies,
  };
};

/** Verify the freshly-published generation preserves the translation exactly:
 * re-read in the gateway's order and compare canon-by-index (unique priorities
 * make the alignment exact). */
const verifyProject = async (
  projectId: string,
  generation: number,
  written: BackfillRuleInput[],
): Promise<boolean> => {
  // Pinned to the generation this run wrote: a concurrent replica can publish a
  // newer one in the commit-to-verify window, and an unpinned read would report
  // a false divergence.
  const stored = await db.policyRuleV2.findMany({
    where: { scope: "project", projectId, status: "published", generation },
    include: { identities: true, targets: true },
    orderBy: [{ priority: "asc" }, { id: "asc" }],
  });
  if (stored.length !== written.length) return false;
  const expected = [...written].sort((a, b) => a.priority - b.priority);
  return stored.every(
    (row, i) =>
      expected[i] !== undefined &&
      ossCanonRule(reconstructOssRule(row)) === ossCanonRule(expected[i]),
  );
};

/** A project with a published generation needs no conversion — unless a user
 * published it before the migration ran, in which case its legacy rules were
 * never translated and a plain idempotency skip would hide that forever.
 * Detected via the migration marker on the active generation's Default Rule. */
const skipAlreadyPublished = async (
  projectId: string,
): Promise<OssCutoverResult> => {
  const legacyCount = await db.policyRule.count({ where: { projectId } });
  if (legacyCount === 0) return { status: "skipped", ruleCount: 0 };
  const activeDefault = await db.policyRuleV2.findFirst({
    where: {
      scope: "project",
      projectId,
      status: "published",
      isDefault: true,
    },
    orderBy: { generation: "desc" },
    select: { description: true },
  });
  if (activeDefault?.description === OSS_MIGRATED_DEFAULT_DESCRIPTION) {
    return { status: "skipped", ruleCount: 0 };
  }
  // Deleting the v2 rows to force a re-run is not a remedy: there is no legacy
  // engine behind them, so a project with no published generation enforces
  // nothing until the next boot completes.
  console.error(
    `[policy-legacy-migration] PREEMPTED project=${projectId}: this project's v2 policy was published before the migration ran, so ${legacyCount} legacy rule(s) were NOT carried over. They are still readable in \`policy_rules\` — re-author them in the Policy console. Do not delete the project's policy_rules_v2 rows: nothing would be enforced until it is republished.`,
  );
  return { status: "skipped", ruleCount: 0, preempted: true };
};

/** Cut one project over. Idempotent; the generation is kept on divergence. */
export const cutoverOssProject = async (
  projectId: string,
  policyMode: string,
): Promise<OssCutoverResult> => {
  // Fast path: this walks every project on every boot, long after the last
  // instance has converted, so decide from one count before translating
  // anything.
  const published = await db.policyRuleV2.count({
    where: { scope: "project", projectId, status: "published" },
  });
  if (published > 0) return skipAlreadyPublished(projectId);

  const { rules, droppedSessionPolicies } = await buildProjectRules(
    projectId,
    policyMode,
  );
  for (const drop of droppedSessionPolicies) {
    console.warn(
      `[policy-legacy-migration] dropping stored sessionPolicy (never enforced in OSS): project=${projectId} agent=${drop.agentId} connection=${drop.appConnectionId}`,
    );
  }
  const result = await backfillPublishScope({ projectId }, rules);
  // Lost a race with a concurrent replica between the count above and the
  // scope-locked write — same question, same answer.
  if (result.skipped) return skipAlreadyPublished(projectId);
  if (await verifyProject(projectId, result.generation ?? 1, rules)) {
    return { status: "cut", ruleCount: rules.length };
  }
  // Divergence can only mean a translator bug. The written generation is kept
  // rather than deleted: an empty rule set decides Allow, so deleting would
  // turn a policy that merely failed to round-trip into no policy at all. The
  // legacy rows are retained so it can be diagnosed and republished by hand.
  console.error(
    `[policy-legacy-migration] DIVERGENCE project=${projectId} — the published v2 generation does not match the translation. It is being KEPT and IS enforcing (deleting it would enforce nothing at all). Compare it against the project's \`policy_rules\` rows and republish from the Policy console if it is wrong.`,
  );
  return { status: "diverged", ruleCount: rules.length };
};

/**
 * The full boot pass: every org, then every project, in createdAt order, with
 * per-project failure isolation so one bad project cannot stop the rest.
 */
export const runLegacyPolicyMigration = async (): Promise<void> => {
  const orgs = await db.organization.findMany({
    select: {
      id: true,
      policyMode: true,
      projects: { select: { id: true }, orderBy: { createdAt: "asc" } },
    },
    orderBy: { createdAt: "asc" },
  });
  let cut = 0;
  let skipped = 0;
  let failed = 0;
  // Counted separately: a preempted project is neither converted nor broken,
  // and folding it into `skipped` would let the summary read clean.
  let preempted = 0;
  for (const org of orgs) {
    for (const project of org.projects) {
      try {
        const result = await cutoverOssProject(project.id, org.policyMode);
        if (result.status === "cut") {
          cut += 1;
          console.log(
            `[policy-legacy-migration] cut project=${project.id} rules=${result.ruleCount}`,
          );
        } else if (result.status === "skipped") {
          if (result.preempted) preempted += 1;
          else skipped += 1;
        } else {
          failed += 1;
        }
      } catch (err) {
        failed += 1;
        console.error(
          `[policy-legacy-migration] project=${project.id} failed:`,
          err,
        );
      }
    }
  }
  const summary = `[policy-legacy-migration] done: ${cut} converted, ${skipped} already converted, ${failed} failed${preempted > 0 ? `, ${preempted} PREEMPTED (see the errors above — their legacy rules were not carried over)` : ""}`;
  if (failed > 0 || preempted > 0) console.error(summary);
  else console.log(summary);
};
