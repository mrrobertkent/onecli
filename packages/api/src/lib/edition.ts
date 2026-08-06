/**
 * Build edition and its capability model. Pure and dependency-free, so it is
 * safe to import from any runtime.
 */

/** Distribution edition. */
export type Edition = "oss" | "cloud" | "onprem";

/** Sub-variant of an edition (e.g. a future onprem `slim` vs `full`). `null` when N/A. */
export type Variant = "slim" | "full" | null;

/** Parsed build edition + variant. */
export interface EditionInfo {
  edition: Edition;
  variant: Variant;
}

/** Parse the optional `-<variant>` segment (e.g. the `slim` in `onprem-slim`). */
const parseVariant = (raw: string | undefined): Variant =>
  raw === "slim" || raw === "full" ? raw : null;

/**
 * Normalize the raw `*_EDITION` env value into `{ edition, variant }`.
 *
 * Accepts `"<edition>"` or `"<edition>-<variant>"` (e.g. `"onprem-slim"`).
 * `oss` and `cloud` carry no variant; empty, `"oss"`, or any unrecognized
 * value → `oss`.
 */
export const parseEdition = (raw: string | undefined | null): EditionInfo => {
  const [edition, variant] = (raw ?? "").trim().toLowerCase().split("-");
  switch (edition) {
    case "cloud":
      return { edition: "cloud", variant: null };
    case "onprem":
      return { edition: "onprem", variant: parseVariant(variant) };
    default:
      return { edition: "oss", variant: null };
  }
};

/**
 * Capabilities derived from the edition. Branch on these rather than the raw
 * edition string, so a new edition is a data change here.
 */
export interface Capabilities {
  /** Identity backend. */
  auth: "cognito" | "local";
  /** Tenancy model. */
  tenancy: "multi-org" | "org-per-user" | "single-org-shared";
  /** Whether billing / plan-gating is active. */
  billing: boolean;
  /**
   * Whether the web serves the org-scoped surface (org routes, nav, namespaced
   * URLs) rather than the flat one. The one capability that varies by variant.
   */
  orgScopedUI: boolean;
  /**
   * Which web surface the edition serves: `"connect-only"` is just the
   * app-connection flow, `"full"` is the whole product UI.
   */
  webSurface: "connect-only" | "full";
  /**
   * Role-based access control is active: role enforcement in the access checks
   * and the member/role management UI. Distinct from the `tenancy` model.
   */
  rbac: boolean;
}

const CAPABILITIES: Record<Edition, Capabilities> = {
  // `single-org-shared` is only safe alongside `rbac: true`, a registered OSS
  // `RoleResolver`, and role-resolved membership creation
  // (`ensureSharedOrgMembership` taking an explicit role). Changing one without
  // the others opens a privilege-escalation hole.
  oss: {
    auth: "local",
    tenancy: "single-org-shared",
    billing: false,
    orgScopedUI: false,
    webSurface: "full",
    rbac: true,
  },
  cloud: {
    auth: "cognito",
    tenancy: "multi-org",
    billing: true,
    orgScopedUI: true,
    webSurface: "full",
    rbac: true,
  },
  onprem: {
    auth: "local",
    tenancy: "single-org-shared",
    billing: false,
    orgScopedUI: false,
    webSurface: "connect-only",
    rbac: false,
  },
};

/**
 * The capability set for a parsed edition. `onprem-full` extends the onprem base
 * with the org-scoped web surface; `onprem-slim` keeps the flat one.
 */
export const capabilitiesFor = (info: EditionInfo): Capabilities => {
  const base = CAPABILITIES[info.edition];
  if (info.edition === "onprem" && info.variant === "full") {
    return { ...base, orgScopedUI: true, webSurface: "full" };
  }
  return base;
};

/** Capabilities by edition (exported for tests / introspection). */
export { CAPABILITIES };
