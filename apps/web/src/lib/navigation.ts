import { CAPS } from "@/lib/env";

/** Matches `/p/<projectId>` at the start of a pathname and captures the id. */
export const PROJECT_PATH_RE = /^\/p\/([^/]+)(?=\/|$)/;

/**
 * Whether `pathname` is inside a project scope. Under `orgScopedUI` only
 * `/p/<id>` routes are; in flat editions every dashboard page is, since the
 * gateway resolves the caller's default project server-side.
 *
 * Distinct from `getProjectId()`, which answers which project id the URL
 * carries and is `undefined` in flat editions.
 */
export const hasProjectContext = (pathname: string): boolean =>
  CAPS.orgScopedUI ? PROJECT_PATH_RE.test(pathname) : true;

/** Matches `/org/<orgId>` at the start of a pathname and captures the id. */
export const ORG_PATH_RE = /^\/org\/([^/]+)(?=\/|$)/;

/**
 * Prefix an absolute dashboard path with `/p/<projectId>` if the current
 * pathname is already inside a project scope, so shared dashboard components
 * keep the prefix instead of jumping to the bare top-level path. A no-op in
 * OSS, where no `/p/<id>/` URLs exist.
 */
export const withProjectPrefix = (
  currentPathname: string,
  targetPath: string,
): string => {
  const match = currentPathname.match(PROJECT_PATH_RE);
  if (!match) return targetPath;
  return `/p/${match[1]}${targetPath}`;
};

/** The agent detail page, scoped to the current edition. The bare path 404s in
 * cloud. */
export const agentPath = (currentPathname: string, agentId: string): string =>
  withProjectPrefix(currentPathname, `/agents/${agentId}`);

/** The last-visited org, written on org pages and read by the Get Started
 * button on account routes. Inert in OSS, which has no account paths. */
export const DEFAULT_ORG_COOKIE = "onecli-default-org";

export const readDefaultOrgCookie = (): string | undefined =>
  document.cookie
    .split("; ")
    .find((c) => c.startsWith(`${DEFAULT_ORG_COOKIE}=`))
    ?.split("=")[1];

/**
 * Resolve a path inside the connections section for the current edition and
 * page, so callers never hardcode the bare `/connections...` path, which 404s
 * in cloud.
 *
 * - OSS:           `/connections{sub}`
 * - Cloud project: `/p/<id>/connections{sub}`
 * - Cloud org:     `<basePath>{sub}`
 *
 * `sub` is the path under the connections root, e.g. `/apps/<provider>`.
 */
export const connectionsPath = (
  { pathname, basePath }: { pathname: string; basePath?: string },
  sub = "",
): string =>
  basePath
    ? `${basePath}${sub}`
    : withProjectPrefix(pathname, `/connections${sub}`);
