import { apiGet } from "./client";

// The project-scoped read backing the connect-picker filter. The org config
// surface is EE (`@/ee/app-availability/api`).

/**
 * The apps available to the current project. `restricted:false` means
 * unfiltered.
 */
export interface AvailableApps {
  restricted: boolean;
  providers: string[];
}

/** Project-scoped: the apps this project may connect. */
export const available = () => apiGet<AvailableApps>("/v1/apps/available");
