import { randomBytes } from "crypto";
import { readFileSync } from "node:fs";
import { db } from "@onecli/db";
import { logger } from "../lib/logger";
import type { ResourceScope } from "./resource-scope";
import { scopeWhere, scopeCreate, isOrgScope } from "./resource-scope";

export const generateApiKey = (scope?: ResourceScope) => {
  const prefix = scope && isOrgScope(scope) ? "oc_org_" : "oc_";
  return `${prefix}${randomBytes(32).toString("hex")}`;
};

export const regenerateApiKey = async (
  userId: string,
  scope: ResourceScope,
) => {
  const key = generateApiKey(scope);

  const existing = await db.apiKey.findFirst({
    where: { userId, ...scopeWhere(scope) },
    select: { id: true },
  });

  if (existing) {
    await db.apiKey.update({
      where: { id: existing.id },
      data: { key },
    });
  } else {
    const user = await db.user.findUniqueOrThrow({
      where: { id: userId },
      select: { email: true },
    });
    await db.apiKey.create({
      data: { key, userId, userEmail: user.email, ...scopeCreate(scope) },
    });
  }

  return { apiKey: key };
};

/**
 * Return the user's API key for `scope`, lazily creating one if none exists.
 * Idempotent. Keys are personal — they carry the user's identity for audit
 * attribution — so this never surfaces another user's.
 *
 * `created` is `true` only when a key was actually minted, so callers can audit
 * the first provision without logging every read.
 */
export const ensureApiKey = async (
  userId: string,
  scope: ResourceScope,
): Promise<{ apiKey: string; created: boolean }> => {
  const existing = await db.apiKey.findFirst({
    where: { userId, ...scopeWhere(scope) },
    select: { key: true },
  });
  if (existing) return { apiKey: existing.key, created: false };

  const user = await db.user.findUniqueOrThrow({
    where: { id: userId },
    select: { email: true },
  });
  const key = generateApiKey(scope);
  await db.apiKey.create({
    data: { key, userId, userEmail: user.email, ...scopeCreate(scope) },
  });
  return { apiKey: key, created: true };
};

/**
 * Canonical org API key shape: `oc_org_` + 32 random bytes hex (lowercase),
 * matching `generateApiKey({ organizationId })`. Used to validate an
 * operator-supplied bootstrap key.
 */
export const ORG_API_KEY_REGEX = /^oc_org_[0-9a-f]{64}$/;

export const isValidOrgApiKey = (value: string): boolean =>
  ORG_API_KEY_REGEX.test(value);

/**
 * An operator-supplied bootstrap org API key, from `ONECLI_ORG_API_KEY` or the
 * file at `ONECLI_ORG_API_KEY_FILE`. Env wins over the file; `undefined` when
 * neither is set.
 */
export const resolveConfiguredOrgApiKey = (): string | undefined => {
  const direct = process.env.ONECLI_ORG_API_KEY?.trim();
  if (direct) return direct;
  const file = process.env.ONECLI_ORG_API_KEY_FILE?.trim();
  if (file) {
    let fromFile: string;
    try {
      fromFile = readFileSync(file, "utf8").trim();
    } catch (err) {
      throw new Error(
        `ONECLI_ORG_API_KEY_FILE could not be read (${file}): ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
    if (fromFile) return fromFile;
  }
  return undefined;
};

/**
 * Ensure the shared organization has its single bootstrap org-scoped API key,
 * creating it once. Idempotent: an existing org-scoped key is returned
 * unchanged, never rotated.
 *
 * An operator-supplied key (`ONECLI_ORG_API_KEY` / `_FILE`) is used when set and
 * throws if malformed, rather than silently substituting a generated one.
 * A generated value is logged once so it can be retrieved; a supplied value is
 * never logged. The key is attributed to `userId`.
 */
export const ensureBootstrapOrgApiKey = async ({
  organizationId,
  userId,
  userEmail,
}: {
  organizationId: string;
  userId: string;
  userEmail: string;
}): Promise<{
  apiKey: string;
  created: boolean;
  source: "existing" | "env" | "generated";
}> => {
  const existing = await db.apiKey.findFirst({
    where: { organizationId, scope: "organization" },
    select: { key: true },
  });
  if (existing) {
    return { apiKey: existing.key, created: false, source: "existing" };
  }

  const configured = resolveConfiguredOrgApiKey();
  if (configured !== undefined && !isValidOrgApiKey(configured)) {
    throw new Error(
      "ONECLI_ORG_API_KEY is malformed — expected an 'oc_org_' prefix followed " +
        "by 64 lowercase hex chars (generate one with: oc_org_$(openssl rand -hex 32)).",
    );
  }
  const source: "env" | "generated" = configured ? "env" : "generated";
  const key = configured ?? generateApiKey({ organizationId });

  try {
    await db.apiKey.create({
      data: { key, userId, userEmail, ...scopeCreate({ organizationId }) },
    });
  } catch (err) {
    // Concurrent first-join race (the unique `key` loses if two joins seed the
    // same supplied value): re-read and use whatever landed.
    const raced = await db.apiKey.findFirst({
      where: { organizationId, scope: "organization" },
      select: { key: true },
    });
    if (raced) return { apiKey: raced.key, created: false, source: "existing" };
    throw err;
  }

  if (source === "generated") {
    logger.warn(
      `Generated bootstrap org API key: ${key}\n` +
        "  Save it now — shown only once. Set ONECLI_ORG_API_KEY to pin a known " +
        "value, and rotate it if your container logs are shipped.",
    );
  } else {
    logger.info("Seeded bootstrap org API key from ONECLI_ORG_API_KEY.");
  }

  return { apiKey: key, created: true, source };
};
