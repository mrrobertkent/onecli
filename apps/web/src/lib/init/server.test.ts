import { beforeAll, describe, expect, it } from "vitest";

/**
 * Server actions bypass the API app, so `createApiApp`'s provider registrations
 * are absent unless this module repeats them. Neither is a soft failure: with
 * no role resolver `canAccessProjectAsUser` denies everyone, and with no
 * enforcer the access gate is skipped entirely.
 */

type Providers = typeof import("@onecli/api/providers");

let providers: Providers;

beforeAll(async () => {
  providers = await import("@onecli/api/providers");
  // Registration happens as an import side effect.
  await import("./server");
});

describe("the Next server runtime's provider registration", () => {
  it("registers a role resolver", () => {
    expect(providers.getRoleResolver()).not.toBeNull();
  });

  it("registers the session enforcer", () => {
    expect(providers.getSessionEnforcer()).not.toBeNull();
  });

  it("registers the same providers the Hono app gets", async () => {
    const { eeOverrides } = await import("./api");

    expect(providers.getRoleResolver()).toBe(eeOverrides?.roleResolver);
    expect(providers.getSessionEnforcer()).toBe(eeOverrides?.sessionEnforcer);
  });
});
