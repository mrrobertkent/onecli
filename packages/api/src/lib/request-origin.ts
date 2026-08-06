import { IS_CLOUD } from "./env";
import { getSelfUrl } from "../providers/self-url";
import {
  configuredAppUrl,
  normalizeOrigin,
  originFromHeaders,
} from "./app-origin";

/**
 * The public origin (scheme + host) that served this request, from the
 * reverse-proxy headers or `Host`. On cloud that is the API domain, not the
 * dashboard's — for somewhere to send a browser, use `getAppOrigin`.
 */
export const getRequestOrigin = (request: Request): string => {
  if (IS_CLOUD) return getSelfUrl();

  // Self-hosted: an explicitly configured APP_URL keeps OAuth redirect URIs
  // stable behind a proxy.
  const configured = configuredAppUrl();
  if (configured) return configured;

  return (
    originFromHeaders(
      request.headers,
      request.url.startsWith("https") ? "https" : "http",
    ) ?? getSelfUrl()
  );
};

/**
 * Origin to send a browser to for a dashboard page. Use this, not
 * `getRequestOrigin`, whenever the result becomes a `Location` header or a link
 * a human will click: a deployment can split the API and the dashboard across
 * hosts, so a configured `APP_URL` always wins.
 *
 * `signedOrigin` is an origin recovered from data signed earlier in the same
 * flow (the OAuth state minted at the authenticated `/authorize`). It is
 * preferred over `request` because the OAuth callback is unauthenticated, so a
 * forged `X-Forwarded-Host` there must not steer where the browser lands.
 */
export const getAppOrigin = (
  request: Request,
  signedOrigin?: unknown,
): string =>
  configuredAppUrl() ??
  normalizeOrigin(signedOrigin) ??
  getRequestOrigin(request);
