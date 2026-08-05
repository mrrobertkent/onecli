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
   * Fires once when the session upsert created a new user row — for every
   * flow, not just organic signups. `context.bootstrappedOrg` says whether
   * the default org bootstrap ran for this user; editions use it (and the
   * request) to tell organic signups apart from users who join an existing
   * org (invitation, claim link, JIT membership).
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
   * a DIFFERENT auth identity (`externalAuthId` mismatch): "link" re-points
   * the user to the session's identity; "reject" refuses the sign-in (409).
   * The default preserves the historical behavior (always link) — editions
   * with untrusted identity sources override this with a real policy.
   */
  resolveIdentityConflict(
    existing: ExistingIdentity,
    session: SessionUser,
  ): "link" | "reject" | Promise<"link" | "reject">;
  /**
   * Ensure edition-specific org membership for the session's identity (e.g.
   * enterprise-SSO JIT join) before the default org-bootstrap decision. Runs
   * on every session and must be idempotent and non-throwing — membership is
   * best-effort; session resolution is not. The default is a no-op.
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
 * GET /auth/session
 *
 * Single endpoint that handles the full auth -> DB sync flow:
 * 1. Reads the auth session (cookie/token)
 * 2. Upserts the user in the database
 * 3. Ensures the user has an Organization + Project + ApiKey + Agent
 * 4. Returns the user profile with projectId
 *
 * Called by the login page after auth and by the dashboard layout on mount.
 * Returns 401 if no valid session exists.
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
        select: { id: true, email: true, name: true },
      });

      // Edition membership (e.g. SSO JIT join) runs before the default
      // project resolution so a just-created membership's project is what
      // the session lands on — and the bootstrap branch below self-skips.
      await _hooks.ensureSessionMembership(user, dbUser);

      // Edition session policy (e.g. enterprise "require SSO") — after JIT
      // so a first SSO login joins and then trivially passes. Denials MUST
      // return inline: a throw would land in the catch below as a 500.
      const enforcer = getSessionEnforcer();
      if (enforcer) {
        const denial = await enforcer(user, dbUser);
        if (denial) {
          return c.json({ error: denial.error, code: denial.code }, 401);
        }
      }

      let defaultProject = await findUserDefaultProject(dbUser.id);

      // "This session has no project of its own" is the whole condition, and
      // deliberately so.
      //
      // It used to also require `!existingUser` — "the row did not exist before
      // this request's upsert" — as a proxy for "this identity is new". Under
      // D-10 that proxy is dead: the auth library creates the user row at first
      // login, so by the time this endpoint runs the row ALWAYS exists, the
      // condition is always false, and no user is ever provisioned a project.
      // The session then resolves without one and the gateway 401s with "no
      // project found".
      //
      // Project absence is the correct predicate independently of that: it is
      // what the branch actually repairs, it is edition-neutral, and it is
      // idempotent — both `joinSharedOrganization` and `bootstrapOrganization`
      // look for an existing project before creating one, so a repeated call
      // returns the same project rather than a second one. `shouldBootstrapOrg`
      // remains the edition's veto for identities that must join an org by
      // invitation instead (cloud), which is the case `!existingUser` was
      // conflated with.
      const bootstrappedOrg =
        !defaultProject && _hooks.shouldBootstrapOrg(c.req.raw);

      if (bootstrappedOrg) {
        const result =
          CAPS.tenancy === "single-org-shared"
            ? // "member", never "owner" (design D-11). `ensureSessionMembership`
              // runs above and is where a claim-resolved role is written; if it
              // already created the membership this call preserves that role.
              // This literal is the floor for a joiner it did not cover — under
              // shared tenancy an unmapped identity must not land as an owner.
              await joinSharedOrganization(dbUser.id, dbUser.email, "member")
            : await bootstrapOrganization(
                dbUser.id,
                dbUser.email,
                dbUser.name ?? undefined,
              );
        defaultProject = result.project;
      }

      // No user row existed for this email before the upsert → it was created
      // by this request. Fires outside the bootstrap branch so non-bootstrap
      // signups (invitation/claim flows) reach the hook too.
      //
      // This is the one place `!existingUser` still means what it says, and it
      // is no longer coupled to the provisioning decision above. Note it can
      // therefore never fire in OSS under D-10, where the auth library creates
      // the row first — OSS registers no `onUserCreated`, and anything that
      // needs the creation moment there belongs in the library's own create
      // hook, which is where the sign-up gate now lives.
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
          projectId,
          organizationId: defaultProject.organizationId,
        });
      }

      const responseExtra = await _hooks.augmentSessionResponse(dbUser.id);

      return c.json({
        id: dbUser.id,
        email: dbUser.email,
        name: dbUser.name,
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
