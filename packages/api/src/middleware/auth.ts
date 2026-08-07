import { createMiddleware } from "hono/factory";
import type { AuthContext, OrgRole } from "../providers";
import { getStrictApiKeyAuth } from "../providers";
import { resolveOrgRoleAtLeast } from "../services/org-authorization";
import { ServiceError } from "../services/errors";
import type { ApiEnv } from "../types";
import { authenticateApiKey } from "./auth/api-key";
import { authenticateSession } from "./auth/session";

export interface AuthOptions {
  requireProject?: boolean;
  role?: OrgRole;
}

const UNAUTHORIZED = {
  error: {
    message: "Invalid API key or token.",
    type: "authentication_error",
  },
} as const;

const MISSING_PROJECT_HEADER = {
  error: {
    message: "X-Project-Id header is required",
    type: "authentication_error",
  },
} as const;

const FORBIDDEN_NOT_MEMBER = {
  error: {
    message: "Not a member of this organization",
    type: "authentication_error",
  },
} as const;

const FORBIDDEN_INSUFFICIENT = {
  error: {
    message: "Insufficient permissions",
    type: "authentication_error",
  },
} as const;

export const auth = (options?: AuthOptions) => {
  const requireProject = options?.requireProject ?? true;
  const minimumRole = options?.role;

  return createMiddleware<ApiEnv>(async (c, next) => {
    // A browser navigation cannot set request headers, so it carries its scope
    // in the query string (_token/_project/_org). Bridge those into the headers
    // every auth path reads. Real headers always win, so an API key or a
    // header-scoped request keeps precedence.
    let request = c.req.raw;
    const queryToken = c.req.query("_token");
    const queryProject = c.req.query("_project");
    const queryOrg = c.req.query("_org");
    if (queryToken || queryProject || queryOrg) {
      try {
        const headers = new Headers(request.headers);
        if (queryToken && !headers.has("authorization")) {
          headers.set("authorization", `Bearer ${queryToken}`);
        }
        if (queryProject && !headers.has("x-project-id")) {
          headers.set("x-project-id", queryProject);
        }
        if (queryOrg && !headers.has("x-organization-id")) {
          headers.set("x-organization-id", queryOrg);
        }
        // Header-only clone for the auth resolvers; `c.req` and its body are
        // left untouched.
        request = new Request(c.req.url, { headers });
      } catch {
        // A scope param that is not a valid header value makes `Headers.set`
        // throw; resolve as if the param were absent rather than 500.
        request = c.req.raw;
      }
    }

    // 1. API key (project or org)
    const apiKeyAuth = await authenticateApiKey(request, requireProject);
    let authResult: AuthContext | null =
      typeof apiKeyAuth === "string" ? null : apiKeyAuth;

    // In strict mode an `oc_` bearer commits to API-key auth: a failed key 401s
    // instead of falling through to session auth, where an ambient local session
    // would silently resolve the caller to their default project.
    if (getStrictApiKeyAuth()) {
      if (apiKeyAuth === "missing-project") {
        return c.json(MISSING_PROJECT_HEADER, 401);
      }
      if (apiKeyAuth === "invalid-key") {
        return c.json(UNAUTHORIZED, 401);
      }
    }

    // 2. Session — cloud reads the JWT from Authorization; local/onprem is ambient
    if (!authResult) {
      const sessionAuth = await authenticateSession(request, requireProject);
      if (sessionAuth && "denied" in sessionAuth) {
        // The session enforcer rejected a valid session; surface its reason
        // rather than the generic 401.
        return c.json(
          {
            error: {
              message: sessionAuth.denied.error,
              type: "authentication_error",
              code: sessionAuth.denied.code,
            },
          },
          401,
        );
      }
      authResult = sessionAuth;
    }

    if (!authResult) {
      return c.json(UNAUTHORIZED, 401);
    }

    // 4. Role check (only when role option is specified)
    if (minimumRole) {
      const decision = await resolveOrgRoleAtLeast(
        authResult.userId,
        authResult.organizationId,
        minimumRole,
      );
      if (!decision.ok) {
        return c.json(
          decision.reason === "insufficient"
            ? FORBIDDEN_INSUFFICIENT
            : FORBIDDEN_NOT_MEMBER,
          403,
        );
      }
      authResult.role = decision.role;
    }

    c.set("auth", authResult);
    return next();
  });
};

export const authMiddleware = auth();

export const requireProjectId = (auth: AuthContext): string => {
  if (!auth.projectId)
    throw new ServiceError("BAD_REQUEST", "X-Project-Id header is required");
  return auth.projectId;
};
