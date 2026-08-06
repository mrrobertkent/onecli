// Gateway connect-cache invalidation, so agents pick up secret, rule and
// connection changes without waiting out the TTL.
//
// Hits the gateway directly rather than the typed JSON API, so it goes through
// the gateway-auth seam that authenticates as the acting user. The gateway
// scopes the flush to that principal's project.
import { getGatewayApiUrl } from "@/hooks/use-vault-status";
import { getGatewayFetchOptions } from "@/lib/gateway-auth";

/**
 * Flush the gateway cache for the current project. Fire-and-forget: a failed
 * flush must never break the UI, and the cache also expires on its own TTL.
 */
export const invalidateGatewayCache = async (): Promise<void> => {
  try {
    const { headers, credentials } = await getGatewayFetchOptions();
    await fetch(`${getGatewayApiUrl()}/v1/cache/invalidate`, {
      method: "POST",
      headers,
      credentials,
    });
  } catch {
    // Gateway unreachable — ignore.
  }
};
