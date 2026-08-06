import { Hono } from "hono";
import { db } from "@onecli/db";
import { getSessionProvider, getSessionEnforcer } from "../providers";
import type { SessionUser } from "../providers/types";
import { logger } from "../lib/logger";
import {
  findUserDefaultProject,
  bootstrapOrganization,
  joinSharedOrganization,
  ensureProjectSeeds,
} from "../services/organization-service";
import { CAPS } from "../lib/env";

/** Extra attributes to spread into the user upsert (create + update). */
type SessionAttributes = Record<string, unknown>;

/** The DB user a conflicting session's email already belongs to. */
export interface ExistingIdentity {
  id: string;
  email: string;
  externalAuthId: string;
}

/** Single user-facing message for a rejected identity relink (409). */
export const IDENTITY_CONFLICT_ERROR =
  "This email is already associated with a different sign-in identity. Sign in with your original method.";

export interface SessionHooks {
  getSessionAttributes(request: Request): SessionAttributes;
  /**
   * Fires once when the session upsert created a new user row, on every flow.
   * `context.bootstrappedOrg` distinguishes an organic signup from a user
   * joining an existing org by invitation, claim link or JIT membership.
   */
  onUserCreated(
    user: { email: string; name: string | null },
    attributes: SessionAttributes,
    context: { request: Request; bootstrappedOrg: boolean },
  ): void;
  shouldBootstrapOrg(request: Request): boolean;
  augmentSessionResponse(userId: string): Promise<Record<string, unknown>>;
  /**
   * Decide what happens when a session's email already belongs to a user with
   * a different `externalAuthId`: "link" re-points the user to the session's
   * identity, "reject" refuses the sign-in with a 409. Defaults to "link".
   */
  resolveIdentityConflict(
    existing: ExistingIdentity,
    session: SessionUser,
  ): "link" | "reject" | Promise<"link" | "reject">;
  /**
   * Ensure edition-specific org membership (e.g. SSO JIT join) before the
   * org-bootstrap decision. Runs on every session, so it must be idempotent
   * and must not throw. Defaults to a no-op.
   */
  ensureSessionMembership(
    session: SessionUser,
    user: { id: string; email: string; name: string | null },
  ): Promise<void>;
}

const defaultHooks: SessionHooks = {
  getSessionAttributes: () => ({}),
  onUserCreated: () => {},
  shouldBootstrapOrg: () => true,
  augmentSessionResponse: async () => ({}),
  resolveIdentityConflict: () => "link",
  ensureSessionMembership: async () => {},
};

let _hooks: SessionHooks = defaultHooks;

export const initSessionHooks = (hooks: Partial<SessionHooks>) => {
  _hooks = { ...defaultHooks, ...hooks };
};

/**
 * GET /auth/session — the full auth-to-DB sync: read the session, upsert the
 * user, ensure they have an Organization + Project + ApiKey + Agent, and return
 * the profile with its projectId. 401 when no valid session exists.
 *
 * Called by the login page after auth and by the dashboard layout on mount.
 */
export const authSessionRoutes = () => {
  const app = new Hono();

  app.get("/", async (c) => {
    try {
      const session = getSessionProvider();
      const user = await session.getSession(c.req.raw);
      if (!user || !user.email) {
        return c.json({ error: "Not authenticated" }, 401);
      }

      const extra = _hooks.getSessionAttributes(c.req.raw);

      const existingUser = await db.user.findUnique({
        where: { email: user.email },
        select: { id: true, email: true, externalAuthId: true },
      });

      if (existingUser && existingUser.externalAuthId !== user.id) {
        const decision = await _hooks.resolveIdentityConflict(
          existingUser,
          user,
        );
        if (decision === "reject") {
          return c.json({ error: IDENTITY_CONFLICT_ERROR }, 409);
        }
      }

      const dbUser = await db.user.upsert({
        where: { email: user.email },
        create: {
          externalAuthId: user.id,
          email: user.email,
          name: user.name,
          lastLoginAt: new Date(),
          ...extra,
        },
        update: {
          externalAuthId: user.id,
          name: user.name,
          lastLoginAt: new Date(),
          ...extra,
        },
        select: {
          id: true,
          email: true,
          name: true,
          mustChangePassword: true,
        },
      });

      // Runs before project resolution so a just-created membership's project
      // is what the session lands on, and the bootstrap branch below self-skips.
      await _hooks.ensureSessionMembership(user, dbUser);

      // After the JIT join, so a first SSO login joins and then passes. Denials
      // return inline; a throw would land in the catch below as a 500.
      const enforcer = getSessionEnforcer();
      if (enforcer) {
        const denial = await enforcer(user, dbUser);
        if (denial) {
          return c.json({ error: denial.error, code: denial.code }, 401);
        }
      }

      let defaultProject = await findUserDefaultProject(dbUser.id);

      // Project absence is the whole condition — both provisioning calls below
      // are find-or-create, so re-entering is a no-op. It must not also test
      // `!existingUser`: where the auth library creates the user row at login,
      // that is permanently false and nobody ever gets a project.
      // `shouldBootstrapOrg` is the veto for invitation-only identities.
      const bootstrappedOrg =
        !defaultProject && _hooks.shouldBootstrapOrg(c.req.raw);

      if (bootstrappedOrg) {
        const result =
          CAPS.tenancy === "single-org-shared"
            ? // The floor for a joiner `ensureSessionMembership` did not cover:
              // under shared tenancy an unmapped identity must not land as an
              // owner. A membership it already created keeps its own role.
              await joinSharedOrganization(dbUser.id, dbUser.email, "member")
            : await bootstrapOrganization(
                dbUser.id,
                dbUser.email,
                dbUser.name ?? undefined,
              );
        defaultProject = result.project;
      }

      // Outside the bootstrap branch so invitation and claim flows reach the
      // hook too. Editions whose auth library creates the row first never get
      // here and hook creation in the library instead.
      if (!existingUser) {
        _hooks.onUserCreated(
          { email: dbUser.email, name: dbUser.name },
          extra,
          { request: c.req.raw, bootstrappedOrg },
        );
      }

      if (defaultProject) {
        const projectId = defaultProject.id;

        await ensureProjectSeeds(projectId, dbUser.id, dbUser.email);

        return c.json({
          id: dbUser.id,
          email: dbUser.email,
          name: dbUser.name,
          // A credential the user did not choose has to be rotated before
          // anything else is reachable; the client redirects on this.
          mustChangePassword: dbUser.mustChangePassword,
          projectId,
          organizationId: defaultProject.organizationId,
        });
      }

      const responseExtra = await _hooks.augmentSessionResponse(dbUser.id);

      return c.json({
        id: dbUser.id,
        email: dbUser.email,
        name: dbUser.name,
        mustChangePassword: dbUser.mustChangePassword,
        ...responseExtra,
      });
    } catch (err) {
      logger.error(
        { err, route: "GET /v1/auth/session" },
        "session sync failed",
      );
      return c.json({ error: "Internal server error" }, 500);
    }
  });

  return app;
};
