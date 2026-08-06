/**
 * Scope → display-label mapping for inherited connections and secrets. Unknown
 * scopes fall back to a capitalized form; callers may pass `overrides` to label
 * additional tiers.
 */
export type ScopeLabelMap = Record<string, string>;

const DEFAULT_SCOPE_LABELS: ScopeLabelMap = {
  organization: "Organization",
  project: "Project",
};

export const labelForScope = (
  scope: string | null | undefined,
  overrides?: ScopeLabelMap,
): string => {
  if (!scope) return "";
  return (
    overrides?.[scope] ??
    DEFAULT_SCOPE_LABELS[scope] ??
    scope.charAt(0).toUpperCase() + scope.slice(1)
  );
};
