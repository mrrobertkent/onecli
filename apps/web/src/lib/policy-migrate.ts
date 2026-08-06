import { runLegacyPolicyMigration } from "@onecli/api/services/policy-legacy-migration";
import { guardUnmigratedPolicy } from "@onecli/api/services/policy-migration-guard";
import { runGrantConversion } from "@onecli/api/services/policy-grant-conversion";

/**
 * The OSS boot policy seam. The gateway reads only `policy_rules_v2` and
 * decides Allow on an empty rule set, so an upgrading instance has to be
 * converted before it serves a request or its blocks stop applying.
 *
 * Each pass is idempotent, so this is a no-op on every boot after the first.
 * The order is load-bearing: the legacy pass materializes grants as equipment
 * rules, and the grant conversion then normalizes those into grant stacks.
 *
 * Both migrations are temporary; each service's README carries its removal
 * checklist.
 */
export const runPolicyMigration = async (): Promise<void> => {
  await runLegacyPolicyMigration();
  await guardUnmigratedPolicy();
  await runGrantConversion();
};
