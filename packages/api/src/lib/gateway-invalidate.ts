import { db } from "@onecli/db";
import { GATEWAY_API_URL } from "./env";

export const invalidateGatewayCache = (request: Request) => {
  const authorization = request.headers.get("authorization");
  const cookie = request.headers.get("cookie");
  // The cloud gateway requires X-Project-Id for session auth or the flush 401s.
  // API-key auth ignores it, since the key carries its own project.
  const projectId = request.headers.get("x-project-id");

  const headers: Record<string, string> = {};
  if (authorization) headers["authorization"] = authorization;
  if (cookie) headers["cookie"] = cookie;
  if (projectId) headers["x-project-id"] = projectId;

  fetch(`${GATEWAY_API_URL}/v1/cache/invalidate`, {
    method: "POST",
    headers,
  }).catch(() => {});
};

/**
 * Flush the gateway's cached config for specific API keys directly. Use this
 * when the keys are about to be — or have just been — deleted, so they can no
 * longer be looked up from the database: capture them first, then flush.
 */
export const invalidateGatewayCacheForKeys = (keys: string[]) => {
  for (const key of keys) {
    fetch(`${GATEWAY_API_URL}/v1/cache/invalidate`, {
      method: "POST",
      headers: { authorization: `Bearer ${key}` },
    }).catch(() => {});
  }
};

export const invalidateGatewayCacheForAccount = (projectId: string) => {
  db.apiKey
    .findFirst({ where: { projectId }, select: { key: true } })
    .then((apiKey) => {
      if (!apiKey) return;
      invalidateGatewayCacheForKeys([apiKey.key]);
    })
    .catch(() => {});
};

export const invalidateGatewayCacheForOrg = (organizationId: string) => {
  db.apiKey
    .findMany({
      where: { project: { organizationId } },
      select: { key: true },
      distinct: ["projectId"],
    })
    .then((keys) => invalidateGatewayCacheForKeys(keys.map((k) => k.key)))
    .catch(() => {});
};
