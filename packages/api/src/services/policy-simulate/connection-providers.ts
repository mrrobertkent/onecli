import { db } from "@onecli/db";

/**
 * Providers of the acting org + project's app connections, keyed by connection
 * id, so a `connection` target can resolve to the provider whose catalog hosts
 * it gates. Mirrors the gateway's `find_connection_providers`.
 *
 * Fenced on both arms, so a foreign connection id is simply absent and leaves
 * its target unresolved. No status filter — the row's existence is the
 * reference.
 */
export const loadConnectionProviders = async (
  organizationId: string,
  projectId: string,
): Promise<Map<string, string>> => {
  const rows = await db.appConnection.findMany({
    where: {
      OR: [{ projectId }, { organizationId, scope: "organization" }],
    },
    select: { id: true, provider: true },
  });
  return new Map(rows.map((row) => [row.id, row.provider]));
};
