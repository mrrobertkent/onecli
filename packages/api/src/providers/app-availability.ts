import type { AppAvailabilityProvider } from "./types";

// With no provider registered, availability is never restricted and the connect
// picker shows every app. EE editions register one that reads the org allowlist.
let _appAvailability: AppAvailabilityProvider | null = null;

export const initAppAvailability = (
  provider: AppAvailabilityProvider | null,
) => {
  _appAvailability = provider;
};

export const getAppAvailability = (): AppAvailabilityProvider | null =>
  _appAvailability;
