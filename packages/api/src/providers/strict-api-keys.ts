// Whether an `oc_` bearer commits to API-key auth (a failed key 401s) instead of
// falling through to session auth. Editions with an ambient local session enable
// it, so a failed org key cannot resolve to the user's default project.
let _strictApiKeyAuth = false;

export const initStrictApiKeyAuth = (strict: boolean) => {
  _strictApiKeyAuth = strict;
};

export const getStrictApiKeyAuth = (): boolean => _strictApiKeyAuth;
