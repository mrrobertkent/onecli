import { db } from "@onecli/db";
import { getCrypto } from "../providers";
import { ServiceError } from "./errors";
import { logger } from "../lib/logger";
import type { InjectionConfig } from "../validations/secret";

interface MigrateImported {
  secrets: number;
  agents: number;
  agentSecrets: number;
  rules: number;
}

interface MigrateSkipped {
  type: string;
  name: string;
  reason: string;
}

interface MigrateResult {
  imported: MigrateImported;
  skipped: MigrateSkipped[];
}

/**
 * Export all account data and send it directly to OneCLI Cloud.
 * Decrypts secrets locally and transmits over HTTPS — plaintext never
 * leaves the server process or reaches the caller.
 */
export const exportToCloud = async (
  projectId: string,
  cloudApiKey: string,
  cloudUrl: string,
): Promise<MigrateResult> => {
  // ── Gather data ───────────────────────────────────────────────

  // Secrets and agents only. The legacy grant tables and `policy_rules` are
  // frozen, and `policy_rules_v2` has no import contract yet — so live policy
  // is counted and reported in `skipped[]` rather than dropped in silence.
  const [secrets, agents, policyRuleCount] = await Promise.all([
    db.secret.findMany({
      where: { projectId },
      select: {
        name: true,
        type: true,
        valueSource: true,
        encryptedValue: true,
        hostPattern: true,
        pathPattern: true,
        injectionConfig: true,
        metadata: true,
      },
    }),
    db.agent.findMany({
      where: { projectId },
      select: {
        name: true,
        identifier: true,
        isDefault: true,
        secretMode: true,
      },
    }),
    // What the user authored: the project's draft rules minus the Default Rule,
    // the rows another surface owns, and credential grants.
    db.policyRuleV2.count({
      where: {
        scope: "project",
        projectId,
        status: "draft",
        isDefault: false,
        source: { notIn: ["blocklist", "equipment", "grant"] },
      },
    }),
  ]);

  const skippedPolicy: MigrateSkipped[] =
    policyRuleCount > 0
      ? [
          {
            type: "policy",
            name: `${policyRuleCount} policy rule${policyRuleCount === 1 ? "" : "s"}`,
            reason:
              "Not migrated — policy does not travel with a migration yet. " +
              "Re-author these rules in the destination's Policy console.",
          },
        ]
      : [];

  if (secrets.length === 0 && agents.length === 0) {
    return {
      imported: { secrets: 0, agents: 0, agentSecrets: 0, rules: 0 },
      skipped: skippedPolicy,
    };
  }

  // ── Decrypt secrets ───────────────────────────────────────────
  // 1Password-sourced secrets have no stored plaintext (the value lives in
  // 1Password and its connection is environment-specific), so they can't be
  // carried in the migration — skip and report them for the user to re-add.
  const skippedExternal: MigrateSkipped[] = secrets
    .filter((s) => s.valueSource === "onepassword")
    .map((s) => ({
      type: s.type,
      name: s.name,
      reason:
        "Sourced from 1Password — reconnect 1Password and re-add this secret after migrating",
    }));

  const decryptedSecrets = await Promise.all(
    secrets
      .filter((s) => s.valueSource !== "onepassword" && s.encryptedValue)
      .map(async ({ encryptedValue, ...rest }) => {
        const value = await getCrypto().decrypt(encryptedValue ?? "");
        return { ...rest, value };
      }),
  );

  // ── Build payload ─────────────────────────────────────────────

  const payload = {
    version: 1 as const,
    secrets: decryptedSecrets.map((s) => ({
      name: s.name,
      type: s.type,
      value: s.value,
      hostPattern: s.hostPattern,
      pathPattern: s.pathPattern,
      // Pass the stored config through faithfully — it is already canonical
      // (normalized by buildInjectionConfig on create): header, param, or path.
      injectionConfig: s.injectionConfig as InjectionConfig | null,
      metadata: s.metadata as Record<string, unknown> | null,
    })),
    agents: agents
      .filter((a) => a.identifier)
      .map((a) => ({
        name: a.name,
        identifier: a.identifier!,
        isDefault: a.isDefault,
        secretMode: a.secretMode as "all" | "selective",
      })),
  };

  // ── Send to cloud ─────────────────────────────────────────────

  const response = await fetch(`${cloudUrl}/v1/migrate/import`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${cloudApiKey}`,
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errorBody = (await response.json().catch(() => ({}))) as {
      error?: string;
    };
    const msg = errorBody.error ?? `Cloud returned ${response.status}`;
    logger.error(
      { status: response.status, msg },
      "migration import request failed",
    );
    throw new ServiceError("BAD_REQUEST", `Cloud import failed: ${msg}`);
  }

  const result = (await response.json()) as MigrateResult;
  return {
    ...result,
    skipped: [...skippedExternal, ...skippedPolicy, ...result.skipped],
  };
};
