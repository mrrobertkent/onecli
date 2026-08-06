import type { GatewayFetchOptions } from "@/lib/gateway-auth-types";
import { getApiKey } from "@/lib/actions/api-key";

export type { GatewayFetchOptions };

/**
 * Auth options for browser → gateway HTTP API calls.
 *
 * The gateway tries `Authorization: Bearer oc_...` before any session check,
 * and in `local` mode that key is the only credential it accepts, so the
 * caller's key is always provisioned and attached here.
 */
export const getGatewayFetchOptions =
  async (): Promise<GatewayFetchOptions> => {
    const { apiKey } = await getApiKey();
    return {
      headers: { Authorization: `Bearer ${apiKey}` },
      credentials: "include",
    };
  };
