import type { Metadata } from "next";
import { headers } from "next/headers";
import {
  configuredAppUrl,
  originFromHeaders,
} from "@onecli/api/lib/app-origin";
import { PageHeader } from "@dashboard/page-header";
import { APP_URL } from "@/lib/env";
import {
  getLoginMethods,
  type LoginMethods,
} from "@/lib/actions/login-methods";
import { PublicUrlCard } from "./_components/public-url-card";
import { BuildVersionCard } from "./_components/build-version-card";
import { LoginMethodsCard } from "./_components/login-methods-card";

export const metadata: Metadata = {
  title: "Instance",
};

export default async function InstancePage() {
  // Resolve exactly the way the OAuth callback does, so the card reports the
  // address actually in use rather than the `lib/env.ts` localhost default —
  // which, on an unconfigured instance, is a value nothing consults.
  const configured = configuredAppUrl();
  const appUrl = configured ?? originFromHeaders(await headers()) ?? APP_URL;

  // Administrator-only, so a member sees the page without the card rather than
  // an error. The actions behind it make the same check for themselves.
  let methods: LoginMethods | null = null;
  try {
    methods = await getLoginMethods();
  } catch {
    methods = null;
  }

  return (
    <div className="flex flex-1 flex-col gap-4">
      <PageHeader
        title="Instance"
        description="Instance configuration for your self-hosted deployment."
      />
      {methods && <LoginMethodsCard methods={methods} />}
      <PublicUrlCard appUrl={appUrl} autoDetected={!configured} />
      <BuildVersionCard />
    </div>
  );
}
