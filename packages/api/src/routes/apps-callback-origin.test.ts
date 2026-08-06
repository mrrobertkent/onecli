import { beforeAll, describe, expect, it, vi } from "vitest";
import type { Hono } from "hono";
import type { ApiEnv } from "../types";

/**
 * The OAuth callback's redirect origin when the API and the dashboard are
 * served on different hosts. A browser can arrive at this callback on the API
 * host, but `/app-connect/*` only exists on the dashboard host, so the last
 * redirect has to cross origins — which it can only do from a configured
 * `APP_URL`.
 *
 * Lives in its own file because the edition is read at module load and the
 * sibling `apps.test.ts` pins `onprem-slim` for the single-host cases.
 */

const API_ORIGIN = "https://api.example.com";
const APP_ORIGIN = "https://app.example.com";

// Literals, not the consts above: vi.hoisted runs before they initialize.
vi.hoisted(() => {
  process.env.NEXT_PUBLIC_EDITION = "cloud";
  process.env.SECRET_ENCRYPTION_KEY = "test-oauth-state-secret";
  process.env.OAUTH_STATE_SECRET = "test-oauth-state-secret";
  // A split-host deployment sets APP_URL to the dashboard host on every
  // process.
  process.env.APP_URL = "https://app.example.com";
});

vi.mock("@onecli/db", () => ({ Prisma: {}, db: {} }));

vi.mock("../apps/registry", () => ({
  getApp: (id: string) =>
    id === "signedapp"
      ? { id, name: id, available: true, connectionMethod: { type: "oauth" } }
      : undefined,
  getApps: () => [],
}));

import { createApiApp } from "../app";
import { signOAuthState, generateNonce } from "../lib/oauth-state";

describe("oauth callback redirect origin (split API/dashboard hosts)", () => {
  let app: Hono<ApiEnv>;

  beforeAll(() => {
    // A standalone host declares its own address via `selfUrl`, so
    // getRequestOrigin() resolves to the API origin here.
    app = createApiApp(
      { getSession: async () => null },
      { selfUrl: API_ORIGIN },
    );
  });

  // Using the request origin here would send the browser to the API host,
  // where /app-connect/* does not exist.
  it("sends the browser to the dashboard host, not the API host it arrived on", async () => {
    const res = await app.request("/v1/apps/nosuchprovider/callback", {
      headers: { host: "api.example.com" },
    });

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `${APP_ORIGIN}/app-connect/nosuchprovider?status=error&message=Invalid%20provider`,
    );
    expect(res.headers.get("location")).not.toContain(API_ORIGIN);
  });

  // An origin signed into the state must not override the configured APP_URL.
  it("keeps APP_URL ahead of an origin signed into the state", async () => {
    const state = signOAuthState({
      provider: "signedapp",
      nonce: generateNonce(),
      origin: API_ORIGIN,
    });

    const res = await app.request(
      `/v1/apps/signedapp/callback?state=${encodeURIComponent(state)}`,
      { headers: { host: "api.example.com" } },
    );

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `${APP_ORIGIN}/app-connect/signedapp?status=error&message=Missing%20project%20in%20state`,
    );
    expect(res.headers.get("location")).not.toContain(API_ORIGIN);
  });
});
