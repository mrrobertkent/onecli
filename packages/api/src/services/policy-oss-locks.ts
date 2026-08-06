import { ServiceError } from "./errors";
import type { PolicyValidator } from "../providers";
import { getApp } from "../apps/registry";

/**
 * The OSS edition's policy locks.
 *
 * `validate` rejects granular resource scoping outright: OSS would otherwise
 * store `{repositories}`/`{folders}` its gateway never enforces.
 *
 * `validateTargets` rejects app targets naming a cloud-only provider, whose
 * rules would be dead against the OSS gateway's base catalog. App targets only
 * — no OSS flow can mint an EE-provider connection. Unknown provider strings
 * stay accepted.
 */
export const ossPolicyValidator: PolicyValidator = {
  validate: async () => {
    throw new ServiceError(
      "UNPROCESSABLE",
      "Granular resource scoping (repositories/folders) is available on OneCLI Cloud.",
    );
  },
  validateTargets: async (targets) => {
    for (const t of targets) {
      if (t.kind !== "app") continue;
      const app = getApp(t.provider);
      if (app?.available === false) {
        throw new ServiceError(
          "UNPROCESSABLE",
          `${app.name} connections are available on OneCLI Cloud.`,
        );
      }
    }
  },
};
