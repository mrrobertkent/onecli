import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Hono } from "hono";
import type { ApiEnv } from "../types";

/**
 * The OAuth callback is unauthenticated, so anyone can call it with whatever
 * headers they like. These tests pin that once a state verifies, the
 * post-consent destination comes from what `/authorize` signed into it rather
 * than from the callback's own headers. Driven through the real app and the
 * real `signOAuthState`.
 */

vi.hoisted(() => {
  process.env.NEXT_PUBLIC_EDITION = "onprem-slim";
  process.env.SECRET_ENCRYPTION_KEY = "test-oauth-state-secret";
  process.env.OAUTH_STATE_SECRET = "test-oauth-state-secret";
});

vi.mock("@onecli/db", () => ({ Prisma: {}, db: {} }));

// Two providers: a plain OAuth one, enough to walk the callback down to the
// state check without touching the database, and a fragment-callback one whose
// token comes back in the URL fragment, so the first hit carries no token
// param and gets the fragment-bridge page instead of a redirect.
vi.mock("../apps/registry", () => ({
  getApp: (id: string) =>
    id === "signedapp"
      ? { id, name: id, available: true, connectionMethod: { type: "oauth" } }
      : id === "fragmentapp"
        ? {
            id,
            name: id,
            available: true,
            connectionMethod: {
              type: "oauth",
              fragmentCallback: { paramName: "token" },
            },
          }
        : undefined,
  getApps: () => [],
}));

import { createApiApp } from "../app";
import { signOAuthState, generateNonce } from "../lib/oauth-state";

const SIGNED_ORIGIN = "https://signed.example.com";
const FORGED_HOST = "forged.example.com";

// No projectId, so the handler stops at "Missing project in state" — the first
// redirect after the origin is resolved from the verified state, and it keeps
// the test off the database entirely.
const stateWithout = (extra: Record<string, unknown> = {}) =>
  signOAuthState({ provider: "signedapp", nonce: generateNonce(), ...extra });

const MISSING_PROJECT =
  "/app-connect/signedapp?status=error&message=Missing%20project%20in%20state";

describe("oauth callback origin comes from the signed state", () => {
  let app: Hono<ApiEnv>;

  beforeAll(() => {
    app = createApiApp({ getSession: async () => null });
  });

  const orig = process.env.APP_URL;
  afterEach(() => {
    if (orig === undefined) delete process.env.APP_URL;
    else process.env.APP_URL = orig;
  });

  const callback = (state: string, headers: Record<string, string> = {}) =>
    app.request(
      `/v1/apps/signedapp/callback?state=${encodeURIComponent(state)}`,
      {
        headers: { host: "api.example.com", ...headers },
      },
    );

  it("ignores a forged X-Forwarded-Host when the state carries an origin", async () => {
    delete process.env.APP_URL;

    const res = await callback(stateWithout({ origin: SIGNED_ORIGIN }), {
      "x-forwarded-host": FORGED_HOST,
      "x-forwarded-proto": "https",
    });

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `${SIGNED_ORIGIN}${MISSING_PROJECT}`,
    );
    expect(res.headers.get("location")).not.toContain(FORGED_HOST);
  });

  // A signed origin must not become a way to override the setting that makes
  // split API/dashboard host deploys work.
  it("still lets a configured APP_URL win over the signed origin", async () => {
    process.env.APP_URL = "https://configured.example.com";

    const res = await callback(stateWithout({ origin: SIGNED_ORIGIN }));

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `https://configured.example.com${MISSING_PROJECT}`,
    );
  });

  it("falls back to the request origin when the state has no origin", async () => {
    delete process.env.APP_URL;

    const res = await callback(stateWithout(), {
      "x-forwarded-host": "proxy.example.com",
      "x-forwarded-proto": "https",
    });

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `https://proxy.example.com${MISSING_PROJECT}`,
    );
  });

  it("ignores a signed origin that is not a usable origin", async () => {
    delete process.env.APP_URL;

    const res = await callback(
      stateWithout({ origin: "javascript:alert(1)" }),
      { "x-forwarded-host": "proxy.example.com", "x-forwarded-proto": "https" },
    );

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `https://proxy.example.com${MISSING_PROJECT}`,
    );
  });

  // The fragment-bridge page embeds this origin inside a <script> block, so it
  // is the worst place to trust a header. The state reaches it via the
  // `oauth_state` cookie /authorize set on this path.
  it("uses the signed origin on the fragment-bridge page, taking the state from the cookie", async () => {
    delete process.env.APP_URL;

    const state = signOAuthState({
      provider: "fragmentapp",
      nonce: generateNonce(),
      origin: SIGNED_ORIGIN,
    });

    const res = await app.request("/v1/apps/fragmentapp/callback", {
      headers: {
        host: "api.example.com",
        "x-forwarded-host": FORGED_HOST,
        "x-forwarded-proto": "https",
        cookie: `oauth_state=${state}`,
      },
    });

    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(`${SIGNED_ORIGIN}/app-connect/fragmentapp`);
    expect(html).not.toContain(FORGED_HOST);
  });

  it("ignores an origin signed for a different provider", async () => {
    delete process.env.APP_URL;

    const otherProvider = signOAuthState({
      provider: "fragmentapp",
      nonce: generateNonce(),
      origin: SIGNED_ORIGIN,
    });

    const res = await callback(otherProvider, {
      "x-forwarded-host": "proxy.example.com",
      "x-forwarded-proto": "https",
    });

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      "https://proxy.example.com/app-connect/signedapp?status=error&message=Invalid%20state%20parameter",
    );
    expect(res.headers.get("location")).not.toContain(SIGNED_ORIGIN);
  });

  it("uses the request origin for errors raised before the state is checked", async () => {
    delete process.env.APP_URL;

    const res = await app.request("/v1/apps/signedapp/callback", {
      headers: { host: "api.example.com" },
    });

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      "http://api.example.com/app-connect/signedapp?status=error&message=Missing%20state%20parameter",
    );
  });
});
