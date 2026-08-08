import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { encryptionKeyStatus } from "@onecli/api/lib/crypto-key";
import { CAPS, IS_CLOUD, SECRET_ENCRYPTION_KEY } from "@/lib/env";
import { PROJECT_PATH_RE, ORG_PATH_RE } from "@/lib/navigation";
import { isConnectOnlyAllowed } from "@/lib/connect-surface";

type SetupErrorCode = "missing-encryption-key" | "malformed-encryption-key";

/** Kept in step with `app/auth/recovery/` and the gateway's printed link. */
const RECOVERY_PATH = "/auth/recovery";

/**
 * Returns the first configuration error found, or null if setup is valid.
 *
 * No identity provider is not one: password login covers a first run, and this
 * runs before the database that stores the setting is reachable.
 */
const getSetupError = (): SetupErrorCode | null => {
  if (IS_CLOUD) return null;

  // A wrong-length key is not missing, so an emptiness check passes it through
  // and it fails later, at the first secret stored.
  const key = encryptionKeyStatus(SECRET_ENCRYPTION_KEY);
  if (key === "missing") return "missing-encryption-key";
  if (key === "malformed") return "malformed-encryption-key";

  return null;
};

export const proxy = (request: NextRequest) => {
  const { pathname } = request.nextUrl;

  const error = getSetupError();

  if (pathname.startsWith("/setup-error")) {
    if (!error) {
      return NextResponse.redirect(new URL("/auth/login", request.url));
    }
    return NextResponse.next();
  }

  // Recovery is exempt from the configuration gate: it is the way back into an
  // instance whose configuration is the problem, so it must not be the thing a
  // configuration error takes away.
  if (error && !pathname.startsWith(RECOVERY_PATH)) {
    return NextResponse.redirect(
      new URL(`/setup-error?code=${error}`, request.url),
    );
  }

  // Connect-only editions (onprem-slim) expose only the app-connection surface —
  // redirect anything outside it to the connect landing.
  if (CAPS.webSurface === "connect-only" && !isConnectOnlyAllowed(pathname)) {
    return NextResponse.redirect(new URL("/app-connect", request.url));
  }

  const requestHeaders = new Headers(request.headers);

  // The app-connect popup is a top-level window with no scoped path, so it
  // carries scope in the query string. Bridge that to the same headers for
  // every edition, ahead of the flat-edition handling below: flat editions
  // still resolve per-user projects, so the popup's ?projectId must reach
  // resolveProjectContext or the connect page reads the wrong project.
  const { searchParams } = request.nextUrl;
  const fromQuery = pathname.startsWith("/app-connect");

  const projectId =
    pathname.match(PROJECT_PATH_RE)?.[1] ||
    (fromQuery ? searchParams.get("projectId") : null);
  if (projectId) {
    requestHeaders.set("x-project-id", projectId);
  }

  const orgId =
    pathname.match(ORG_PATH_RE)?.[1] ||
    (fromQuery ? searchParams.get("orgId") : null);
  if (orgId) {
    requestHeaders.set("x-organization-id", orgId);
  }

  // Flat editions don't namespace URLs by org/project, so strip any prefix;
  // scope only ever arrives via the query bridge above.
  if (!CAPS.orgScopedUI) {
    const scopeStripped = pathname
      .replace(PROJECT_PATH_RE, "")
      .replace(ORG_PATH_RE, "");
    if (scopeStripped !== pathname) {
      const url = request.nextUrl.clone();
      url.pathname = scopeStripped || "/";
      return NextResponse.redirect(url);
    }
  }

  return NextResponse.next({
    request: { headers: requestHeaders },
  });
};

export const config = {
  matcher: [
    // Match all routes except static files, _next, and api routes
    "/((?!_next/static|_next/image|favicon.ico|v1|api|.*\\.).*)",
  ],
};
