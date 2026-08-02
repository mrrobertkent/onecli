import { getRuntimeConfig } from "@/lib/runtime-config";

export type AuthMode = "cloud" | "oauth" | "local";

export interface AuthProviderInfo {
  id: string;
  name: string;
  /** Optional brand logo URL / data URI for the login button. */
  logo: string;
  /** Optional brand colour (hex) for the login button. */
  color: string;
}

export const getAuthMode = (): AuthMode => getRuntimeConfig().authMode;

export const isOAuthConfigured = (): boolean =>
  getRuntimeConfig().oauthConfigured;

export const getAuthProvider = (): AuthProviderInfo => {
  const { authProviderId, authProviderName, authProviderLogo, authProviderColor } =
    getRuntimeConfig();
  return {
    id: authProviderId,
    name: authProviderName,
    logo: authProviderLogo ?? "",
    color: authProviderColor ?? "",
  };
};
