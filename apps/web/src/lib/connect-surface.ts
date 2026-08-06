/**
 * The web paths a connect-only edition serves: the app-connection flow and its
 * prerequisites. proxy.ts redirects anything outside this set to /app-connect.
 *
 * `/v1` and `/api` are already exempt from the middleware matcher. Edge-safe —
 * string logic only.
 */
const CONNECT_ONLY_PREFIXES = ["/auth", "/app-connect", "/setup-error"];

export const isConnectOnlyAllowed = (pathname: string): boolean => {
  if (pathname === "/") return true;
  return CONNECT_ONLY_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(prefix + "/"),
  );
};
