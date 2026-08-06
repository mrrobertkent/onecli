import { Hono } from "hono";
import { GATEWAY_API_URL } from "../lib/env";
import { loadCaCertificate } from "../lib/gateway-ca";

// Public discovery endpoint — no auth, like the `/gateway/ca` sibling below.
// It returns only the deployment's gateway proxy URL, a static config value
// identical for every caller, which clients need before they hold a project or
// org context. The project-requiring auth middleware would 401 them.
export const gatewayUrlRoutes = () => {
  const app = new Hono();

  app.get("/", (c) => c.json({ url: GATEWAY_API_URL }));

  return app;
};

export const gatewayCaRoutes = () => {
  const app = new Hono();

  app.get("/ca", (c) => {
    const pem = loadCaCertificate();

    if (!pem) {
      return c.json(
        {
          error:
            "CA certificate not available. Start the gateway first to generate it.",
        },
        503,
      );
    }

    return c.body(pem, 200, {
      "content-type": "application/x-pem-file",
      "content-disposition": 'attachment; filename="onecli-gateway-ca.pem"',
    });
  });

  return app;
};
