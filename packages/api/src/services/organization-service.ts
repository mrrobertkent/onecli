import { db } from "@onecli/db";
import { generateApiKey, ensureBootstrapOrgApiKey } from "./api-key-service";
import { generateAccessToken } from "./agent-service";
import { DEFAULT_AGENT_NAME, DEFAULT_AGENT_IDENTIFIER } from "../lib/constants";
import { generateProjectId, generateOrganizationId } from "../lib/ids";
import { getNewOrgPolicySeeder } from "../providers";
import type { OrgRole } from "../providers/types";
import { logger } from "../lib/logger";

export const slugify = (raw: string) =>
  raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");

/**
 * Membership filter for access-granting reads: suspended members are treated as
 * non-members by authorization checks.
 *
 * Not for display lists, seat counts, or provisioning existence guards —
 * filtering those would re-mint memberships for suspended users.
 */
export const activeMembershipWhere = {
  status: { not: "suspended" },
} as const;

/**
 * Resolve the user's default project: first organization → first project.
 * Returns null when the user has no organization or no project. Creates
 * nothing.
 */
export const findUserDefaultProject = async (
  userId: string,
): Promise<{ id: string; organizationId: string } | null> => {
  const membership = await db.organizationMember.findFirst({
    where: { userId, ...activeMembershipWhere },
    select: { organizationId: true },
    orderBy: { createdAt: "asc" },
  });
  if (!membership) return null;

  return db.project.findFirst({
    where: {
      organizationId: membership.organizationId,
      createdByUserId: userId,
    },
    select: { id: true, organizationId: true },
    orderBy: { createdAt: "asc" },
  });
};

/**
 * Nested-write seeds every new project is born with: one API key + the default
 * agent. Spread into `project.create` data; `ensureProjectSeeds` below is the
 * guarded variant for projects that already exist.
 */
export const defaultProjectSeed = (userId: string, userEmail: string) => ({
  apiKeys: { create: { key: generateApiKey(), userId, userEmail } },
  agents: {
    create: {
      name: DEFAULT_AGENT_NAME,
      identifier: DEFAULT_AGENT_IDENTIFIER,
      accessToken: generateAccessToken(),
      isDefault: true,
      // Set explicitly at every creation site: the schema default is still
      // "all", but new agents start selective.
      secretMode: "selective",
    },
  },
});

/**
 * Create an organization with a default project, API key, and default agent for
 * a user who has no organization yet. Returns the created project and org.
 */
export const bootstrapOrganization = async (
  userId: string,
  userEmail: string,
  displayName?: string,
) => {
  const orgName = displayName || userEmail.split("@")[0] || "Personal";
  const baseSlug = slugify(orgName) || "personal";
  const orgSlug = `${baseSlug}-${userId.slice(0, 8)}`;

  const org = await db.organization.create({
    data: {
      id: generateOrganizationId(),
      name: orgName,
      slug: orgSlug,
      members: { create: { userId, userEmail, role: "owner" } },
    },
    select: { id: true },
  });

  const project = await db.project.create({
    data: {
      id: generateProjectId(),
      name: "Default",
      slug: "default",
      organizationId: org.id,
      createdByUserId: userId,
      createdByUserEmail: userEmail,
      ...defaultProjectSeed(userId, userEmail),
      // Creator's ProjectAccess binding. Inert in OSS (nothing reads bindings
      // without RBAC); load-bearing in cloud.
      accessBindings: { create: { userId, role: "owner" } },
    },
    select: { id: true, organizationId: true },
  });

  // Best-effort: a failure must not fail onboarding. The org then has no
  // published generation and the engine allows until one is authored.
  try {
    await getNewOrgPolicySeeder().seed(org.id, project.id);
  } catch (err) {
    logger.warn({ err, organizationId: org.id }, "new-org policy seed failed");
  }

  return { project, organization: org };
};

/** The single shared organization for onprem (`single-org-shared` tenancy). */
export const SHARED_ORG_SLUG = "default";
export const SHARED_ORG_NAME = "Default";

/**
 * Find-or-create the single shared organization. Race-safe via the unique slug:
 * the loser of a concurrent create catches the violation and re-reads.
 */
export const findOrCreateSharedOrg = async (): Promise<{ id: string }> => {
  const existing = await db.organization.findUnique({
    where: { slug: SHARED_ORG_SLUG },
    select: { id: true },
  });
  if (existing) return existing;
  try {
    return await db.organization.create({
      data: {
        id: generateOrganizationId(),
        name: SHARED_ORG_NAME,
        slug: SHARED_ORG_SLUG,
      },
      select: { id: true },
    });
  } catch {
    return db.organization.findUniqueOrThrow({
      where: { slug: SHARED_ORG_SLUG },
      select: { id: true },
    });
  }
};

/**
 * Ensure the shared organization exists and the user is a member of it at the
 * given role, without any project. Idempotent and concurrency-safe.
 *
 * `role` is required with no default so no caller silently mints an owner.
 * An existing role is preserved on re-entry — role changes belong to the
 * login-time role writer or an admin, not to a bootstrap helper.
 */
export const ensureSharedOrgMembership = async (
  userId: string,
  userEmail: string,
  role: OrgRole,
): Promise<{ id: string }> => {
  const org = await findOrCreateSharedOrg();

  await db.organizationMember.upsert({
    where: { organizationId_userId: { organizationId: org.id, userId } },
    create: { organizationId: org.id, userId, userEmail, role },
    update: {},
  });

  // Best-effort and idempotent, like the per-user-org bootstrap above.
  try {
    await getNewOrgPolicySeeder().seed(org.id);
  } catch (err) {
    logger.warn(
      { err, organizationId: org.id },
      "shared-org policy seed failed",
    );
  }

  return org;
};

/**
 * The org-level part of the instance bootstrap: the shared organization, its
 * owner, and the operator bootstrap org API key — no project. Run at boot so
 * the instance is usable via the org key before anyone opens the web app.
 *
 * Kept separate from the plain membership helper because `ApiKey.user` is
 * `ON DELETE RESTRICT`: whoever owns the bootstrap key cannot be deleted. Right
 * for a bootstrap admin, wrong for an ordinary joiner.
 */
export const ensureSharedOrgBootstrap = async (
  userId: string,
  userEmail: string,
): Promise<{ id: string }> => {
  const org = await ensureSharedOrgMembership(userId, userEmail, "owner");

  // Operator-supplied via ONECLI_ORG_API_KEY / _FILE, else generated.
  // Idempotent — no-ops once seeded.
  await ensureBootstrapOrgApiKey({ organizationId: org.id, userId, userEmail });

  return org;
};

/**
 * Single-org first-login join: ensure the shared org + the user's membership at
 * the given role, then give the user their own default project inside it.
 * Idempotent and concurrency-safe. Mirrors `bootstrapOrganization`'s return
 * shape; the project's apiKey + default agent are seeded by the caller's
 * `ensureProjectSeeds`.
 *
 * Does not seed the bootstrap org API key — that belongs to
 * `ensureSharedOrgBootstrap` alone, since owning it makes a user undeletable.
 */
export const joinSharedOrganization = async (
  userId: string,
  userEmail: string,
  role: OrgRole,
) => {
  const org = await ensureSharedOrgMembership(userId, userEmail, role);

  // Slugs are unique per org and every user shares this one org, so the slug
  // carries the full user id rather than a prefix.
  let project = await db.project.findFirst({
    where: { organizationId: org.id, createdByUserId: userId },
    select: { id: true, organizationId: true },
    orderBy: { createdAt: "asc" },
  });
  if (!project) {
    project = await db.project.create({
      data: {
        id: generateProjectId(),
        name: "Default",
        slug: `default-${userId}`,
        organizationId: org.id,
        createdByUserId: userId,
        createdByUserEmail: userEmail,
        // Creator's ProjectAccess binding. Inert in OSS.
        accessBindings: { create: { userId, role: "owner" } },
      },
      select: { id: true, organizationId: true },
    });
    // A no-op for an org-scoped seeder; load-bearing for a project-scoped one.
    try {
      await getNewOrgPolicySeeder().seed(org.id, project.id);
    } catch (err) {
      logger.warn(
        { err, organizationId: org.id, projectId: project.id },
        "shared-org project policy seed failed",
      );
    }
  }

  return { project, organization: org };
};

export const validateOrgName = (raw: string): string => {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 255) {
    throw new Error("Organization name must be 1-255 characters");
  }
  return trimmed;
};

/**
 * Ensure a project has an API key for the given user and a default agent.
 * Idempotent — skips creation if they already exist.
 */
export const ensureProjectSeeds = async (
  projectId: string,
  userId: string,
  userEmail: string,
) => {
  const hasKey = await db.apiKey.findFirst({
    where: { userId, projectId },
    select: { id: true },
  });
  if (!hasKey) {
    await db.apiKey.create({
      data: { key: generateApiKey(), userId, userEmail, projectId },
    });
  }

  const hasDefaultAgent = await db.agent.findFirst({
    where: { projectId, isDefault: true },
    select: { id: true },
  });
  if (!hasDefaultAgent) {
    await db.agent.create({
      data: {
        name: DEFAULT_AGENT_NAME,
        identifier: DEFAULT_AGENT_IDENTIFIER,
        accessToken: generateAccessToken(),
        isDefault: true,
        secretMode: "selective",
        projectId,
      },
    });
  }
};
