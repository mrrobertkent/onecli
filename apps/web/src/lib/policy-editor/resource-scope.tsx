"use client";

// Alias key on purpose — in EE builds this module is aliased away, so the
// import only ever resolves in the flat editions.
import { granularAccessConfigs } from "@/lib/granular-access";
import type { Connection } from "@/lib/api";

/**
 * The OSS resource-scope seam. Granular per-resource scoping is a OneCLI Cloud
 * capability: the OSS gateway has no guard for it and the API 422s it, so this
 * renders a locked capability hint wherever the real editor would appear.
 */

export interface ResourceScopeFieldsProps {
  connection: Connection;
  policy: Record<string, unknown> | null;
  onChange: (policy: Record<string, unknown> | null) => void;
  /** Read-only contexts never show an upsell hint. */
  readOnly?: boolean;
  /** Accepted for prop parity with the EE editor; OSS has no org scope, so
   * there is never a boundary to narrow within. */
  orgPolicy?: Record<string, unknown> | null;
}

export const ResourceScopeFields: (
  props: ResourceScopeFieldsProps,
) => React.JSX.Element | null = ({ connection, readOnly = false }) => {
  const meta = (connection.metadata as Record<string, unknown> | null) ?? {};
  const config = granularAccessConfigs.get(connection.provider);
  if (!config?.isSupported(meta) || readOnly) return null;
  return (
    <p className="text-muted-foreground rounded-md border border-dashed px-3 py-2 text-xs">
      Resource scoping (limit this connection to specific repositories or
      folders) is available on OneCLI Cloud.
    </p>
  );
};
