import { getRuntimeConfig } from "@/lib/runtime-config";

export type AuthMode = "cloud" | "oauth" | "local";

export interface AuthProviderInfo {
  id: string;
  name: string;
  /** Optional brand logo URL / data URI for the login button. */
  logo: string;
  /** Optional brand colour (hex) for the login button. */
  color: string;
  /** Optional explicit foreground; derived from `color` when empty. */
  textColor: string;
  /** True when `logo` is a full lockup and should replace the label. */
  logoOnly: boolean;
}

export const getAuthMode = (): AuthMode => getRuntimeConfig().authMode;

export const isOAuthConfigured = (): boolean =>
  getRuntimeConfig().oauthConfigured;

export const getAuthProvider = (): AuthProviderInfo => {
  const {
    authProviderId,
    authProviderName,
    authProviderLogo,
    authProviderColor,
    authProviderTextColor,
    authProviderLogoOnly,
  } = getRuntimeConfig();
  return {
    id: authProviderId,
    name: authProviderName,
    logo: authProviderLogo ?? "",
    color: authProviderColor ?? "",
    textColor: authProviderTextColor ?? "",
    logoOnly: authProviderLogoOnly ?? false,
  };
};
