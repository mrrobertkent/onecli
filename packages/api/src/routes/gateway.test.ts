import { describe, expect, it } from "vitest";
import { Hono } from "hono";
import { gatewayUrlRoutes } from "./gateway";
import { GATEWAY_API_URL } from "../lib/env";

// GET /v1/gateway-url is a public bootstrap endpoint: it must answer for any
// caller, including an org key that carries no project.
describe("gateway-url route", () => {
  const mount = () => new Hono().route("/gateway-url", gatewayUrlRoutes());

  it("is public — returns the gateway URL with no auth", async () => {
    const res = await mount().request("/gateway-url");

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ url: GATEWAY_API_URL });
  });

  it("does not 401 for an org key with no project (the reported scenario)", async () => {
    const res = await mount().request("/gateway-url", {
      headers: { authorization: "Bearer oc_org_anything" },
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ url: GATEWAY_API_URL });
  });
});
