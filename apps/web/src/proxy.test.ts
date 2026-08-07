import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * The boot gate. It runs before anything can read the database, so it decides
 * from configuration alone whether the app is reachable at all — which makes
 * "no identity provider" the case worth pinning: that is an ordinary first run,
 * not a misconfiguration, and gating it locks an operator out of the setup page
 * they need in order to have any login at all.
 */

const ENCRYPTION_KEY = "0".repeat(44);

const proxyFor = async (env: Record<string, string | undefined>) => {
  vi.resetModules();
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  const { proxy } = await import("./proxy");
  return proxy;
};

const requestFor = (path: string) =>
  new NextRequest(`https://onecli.example${path}`);

/** Where the response sends the caller, or null when it passes through. */
const destinationOf = (response: Response): string | null => {
  const location = response.headers.get("location");
  return location
    ? new URL(location).pathname + new URL(location).search
    : null;
};

const BASE = {
  NEXT_PUBLIC_EDITION: "oss",
  SECRET_ENCRYPTION_KEY: ENCRYPTION_KEY,
  AUTH_SECRET: "proxy-test-secret",
  GOOGLE_CLIENT_ID: undefined,
  OIDC_ISSUER: undefined,
  OIDC_CLIENT_ID: undefined,
  OIDC_CLIENT_SECRET: undefined,
};

afterEach(() => {
  vi.resetModules();
});

describe("the boot gate", () => {
  it("lets a password-only instance reach setup, with no identity provider configured", async () => {
    const proxy = await proxyFor(BASE);

    expect(destinationOf(proxy(requestFor("/setup")))).toBeNull();
    expect(destinationOf(proxy(requestFor("/auth/login")))).toBeNull();
  });

  it("still refuses to run without an encryption key", async () => {
    const proxy = await proxyFor({
      ...BASE,
      SECRET_ENCRYPTION_KEY: undefined,
    });

    expect(destinationOf(proxy(requestFor("/setup")))).toBe(
      "/setup-error?code=missing-encryption-key",
    );
  });

  it("keeps recovery reachable through a configuration error", async () => {
    const proxy = await proxyFor({
      ...BASE,
      SECRET_ENCRYPTION_KEY: undefined,
    });

    expect(destinationOf(proxy(requestFor("/auth/recovery?key=k")))).toBeNull();
  });
});
