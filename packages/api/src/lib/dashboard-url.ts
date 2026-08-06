import { APP_URL } from "./env";
import { configuredAppUrl } from "./app-origin";

/**
 * Absolute URL to a dashboard page.
 *
 * `fallbackOrigin` is used only when no `APP_URL` was configured. Pass the
 * caller's request origin when there is a request in scope, so self-hosted
 * deployments stop handing out unreachable localhost links; omit it when the
 * link must reach the dashboard even though this process may be answering on a
 * different origin (third-party redirect URLs, for instance).
 */
export const dashboardUrl = (
  path: string,
  scope?: { projectId?: string; organizationId?: string },
  fallbackOrigin?: string,
): string => {
  const base = configuredAppUrl() ?? fallbackOrigin ?? APP_URL;
  if (scope?.projectId) return `${base}/p/${scope.projectId}${path}`;
  if (scope?.organizationId)
    return `${base}/org/${scope.organizationId}${path}`;
  return `${base}${path}`;
};
