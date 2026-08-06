import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const isCloud = process.env.NEXT_PUBLIC_EDITION === "cloud";
const isOnpremFull = process.env.NEXT_PUBLIC_EDITION === "onprem-full";
const isOnpremSlim = process.env.NEXT_PUBLIC_EDITION === "onprem-slim";

// Cloud stamps APP_VERSION (e.g. "1.38.0+f6cca6e5") as a build arg; everything
// else falls back to the monorepo root package.json. cwd is apps/web.
const resolveAppVersion = () => {
  if (process.env.APP_VERSION) return process.env.APP_VERSION;
  try {
    const pkg = JSON.parse(
      readFileSync(
        path.join(process.cwd(), "..", "..", "package.json"),
        "utf8",
      ),
    );
    return pkg.version || "dev";
  } catch {
    return "dev";
  }
};
const appVersion = resolveAppVersion();

// Bare dashboard paths cloud serves at the same URL as OSS. Anything not listed
// here is 404'd for cloud by the rewrites below.
const CLOUD_SHARED_DASHBOARD_PATHS = new Set([]);

// Bare OSS dashboard route segments, read from the filesystem at build time. The
// name pattern excludes route groups "(x)", private "_x", dynamic "[x]",
// parallel "@x", and files. cwd is apps/web.
const getOssDashboardSegments = () => {
  const dir = path.join(process.cwd(), "src", "app", "(dashboard)");
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && /^[a-z0-9][a-z0-9-]*$/.test(e.name))
      .map((e) => `/${e.name}`)
      .filter((p) => !CLOUD_SHARED_DASHBOARD_PATHS.has(p));
  } catch {
    return [];
  }
};

// EE editions resolve app credentials project → org → env, so the RSC seed
// (`checkAppConfigExists`) needs the org-aware variant.
const ORG_APP_CONFIG_ALIASES = {
  "@/lib/actions/app-config": "@/ee/actions/app-config",
};

// The boot-policy seam. OSS migrates legacy policy on boot; every EE edition
// swaps to a no-op and surfaces a report to an operator instead.
const POLICY_MIGRATE_ALIASES = {
  "@/lib/policy-migrate": "@/ee/policy-migrate",
};

// EE chrome for the shared policy editor: staged publish, the org identity
// picker, the granular resource-scope editor. Inert for the flat editions,
// which mount no org scope and never import the tree.
const POLICY_EDITOR_ALIASES = {
  "@/lib/policy-editor/editor-chrome": "@/ee/policy-editor/editor-chrome",
  "@/lib/policy-editor/identity-picker": "@/ee/policy-editor/identity-picker",
  "@/lib/policy-editor/resource-scope": "@/ee/policy-editor/resource-scope",
  "@/lib/policy-editor/publish-mode": "@/ee/policy-editor/publish-mode",
  // Every EE edition is entitled to the conditions builder; the OSS module is
  // the locked upsell card. Also listed in CLOUD_ALIASES.
  "@/lib/components/condition-builder": "@/ee/components/condition-builder",
};

// Import paths cloud swaps for cloud implementations via turbopack resolveAlias.
// onprem-full selects a subset below.
const CLOUD_ALIASES = {
  ...ORG_APP_CONFIG_ALIASES,
  ...POLICY_MIGRATE_ALIASES,
  ...POLICY_EDITOR_ALIASES,
  "@/lib/auth/auth-provider": "@/ee/auth/cognito-provider",
  "@/lib/auth/auth-server": "@/ee/auth/cognito-server",
  "@/lib/actions/resolve-user": "@/ee/auth/resolve-user",
  "@/lib/nav-config": "@/ee/nav-config",
  "@dashboard/dashboard-sidebar": "@/ee/dashboard/dashboard-sidebar",
  "@dashboard/dashboard-header": "@/ee/dashboard/dashboard-header",
  "@/lib/gateway-auth": "@/ee/gateway-auth",
  "@/lib/auth/login-content": "@/ee/auth/login-content",
  "@/lib/user-plan": "@/ee/user-plan",
  "@/lib/components/request-app-slot": "@/ee/apps/request-app-slot",
  "@/lib/home-redirect": "@/ee/home-redirect",
  "@/lib/components/pro-app-dialog": "@/ee/apps/pro-app-dialog",
  "@/lib/components/condition-builder": "@/ee/components/condition-builder",
  "@/lib/dashboard/session-redirect": "@/ee/dashboard/session-redirect",
  "@/lib/granular-access": "@/ee/granular-access",
  "@/lib/plan-gate": "@/ee/billing/plan-gate",

  // Cloud initialization (api, server actions, client)
  "@/lib/init/api": "@/ee/init/api",
  "@/lib/init/server": "@/ee/init/server",
  "@/lib/init/client": "@/ee/init/client",

  // Cloud API fetch (Bearer token auth for external api-server)
  "@/lib/api-fetch": "@/ee/api-fetch",
};

// Injects the cloud app definitions so cloud-only apps are connectable with the
// customer's own OAuth credentials, while keeping local crypto/auth.
const ONPREM_INIT_ALIASES = {
  "@/lib/init/api": "@/ee/onprem/init/api",
  "@/lib/init/server": "@/ee/onprem/init/server",
  "@/lib/init/client": "@/ee/onprem/init/client",
};

// Both onprem editions are fully entitled: report the top plan so premium apps
// and features aren't shown as locked.
const ONPREM_ENTITLEMENT_ALIASES = {
  "@/lib/user-plan": "@/ee/onprem/user-plan",
  "@/lib/granular-access": CLOUD_ALIASES["@/lib/granular-access"],
};

// onprem-full reuses the cloud org-UI implementations but keeps the OSS defaults
// for auth, resolve-user and billing.
const ONPREM_FULL_ALIASES = {
  ...ONPREM_INIT_ALIASES,
  ...ONPREM_ENTITLEMENT_ALIASES,
  ...ORG_APP_CONFIG_ALIASES,
  ...POLICY_MIGRATE_ALIASES,
  ...POLICY_EDITOR_ALIASES,
  "@/lib/nav-config": CLOUD_ALIASES["@/lib/nav-config"],
  "@dashboard/dashboard-sidebar": CLOUD_ALIASES["@dashboard/dashboard-sidebar"],
  "@dashboard/dashboard-header": CLOUD_ALIASES["@dashboard/dashboard-header"],
  "@/lib/dashboard/session-redirect":
    CLOUD_ALIASES["@/lib/dashboard/session-redirect"],
  "@/lib/home-redirect": CLOUD_ALIASES["@/lib/home-redirect"],
  // Local cookie auth + project-scoped headers, no bearer token.
  "@/lib/api-fetch": "@/ee/onprem/api-fetch",
};

// onprem-slim keeps the flat OSS surface and only adds the onprem init seam.
const ONPREM_SLIM_ALIASES = {
  ...ONPREM_INIT_ALIASES,
  ...ONPREM_ENTITLEMENT_ALIASES,
  ...ORG_APP_CONFIG_ALIASES,
  ...POLICY_MIGRATE_ALIASES,
  ...POLICY_EDITOR_ALIASES,
};

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  // These paths have no page of their own. Redirecting at the routing layer
  // rather than with an in-render `redirect()`, which can trip a React
  // hook-count mismatch on client soft-navigation. Cloud namespaces settings
  // under /org/<id>, so this is OSS-only.
  async redirects() {
    return isCloud
      ? []
      : [
          {
            source: "/settings",
            destination: "/settings/instance",
            permanent: false,
          },
          {
            source: "/connections/apps",
            destination: "/connections",
            permanent: false,
          },
          // `?create=anthropic|openai` goes to the LLM tab; the catch-all below
          // sends everything else to the custom tab.
          {
            source: "/connections/secrets",
            has: [
              {
                type: "query",
                key: "create",
                value: "(?<create>anthropic|openai)",
              },
            ],
            destination: "/connections/llms?create=:create",
            permanent: false,
          },
          {
            source: "/connections/secrets",
            destination: "/connections/custom",
            permanent: false,
          },
        ];
  },
  poweredByHeader: false,
  compress: !isCloud, // Cloud: CloudFront handles compression at the edge; OSS: Next.js compresses
  serverExternalPackages: ["@onecli/db", "@1password/sdk"],
  env: {
    NEXT_PUBLIC_EDITION: process.env.NEXT_PUBLIC_EDITION || "oss",
    // Baked in at build time so a runtime `-e NEXT_PUBLIC_ONECLI_DEMO=…` cannot
    // lift the demo caps. Only the slim-demo image builds with this set.
    NEXT_PUBLIC_ONECLI_DEMO: process.env.NEXT_PUBLIC_ONECLI_DEMO || "0",
    NEXT_PUBLIC_APP_VERSION: appVersion,
    NEXT_PUBLIC_API_URL: process.env.API_DOMAIN
      ? `${isCloud && process.env.NODE_ENV !== "development" ? "https" : "http"}://${process.env.API_DOMAIN}`
      : "http://localhost:10255",
    NEXT_PUBLIC_GATEWAY_API_URL: process.env.GATEWAY_API_DOMAIN
      ? `${isCloud && process.env.NODE_ENV !== "development" ? "https" : "http"}://${process.env.GATEWAY_API_DOMAIN}`
      : "http://localhost:10255",
  },
  turbopack: {
    resolveAlias: isCloud
      ? CLOUD_ALIASES
      : isOnpremFull
        ? ONPREM_FULL_ALIASES
        : isOnpremSlim
          ? ONPREM_SLIM_ALIASES
          : {},
  },
  async rewrites() {
    // Cloud and onprem-full ship the OSS bare dashboard routes but only serve
    // them namespaced under /p, /org, /account. Shadowing each bare path before
    // the filesystem route matches keeps the requested URL on the 404.
    if (!isCloud && !isOnpremFull) return [];
    const beforeFiles = getOssDashboardSegments().flatMap((seg) => [
      { source: seg, destination: "/_not-found" },
      { source: `${seg}/:path*`, destination: "/_not-found" },
    ]);
    return { beforeFiles };
  },
};

export default nextConfig;
