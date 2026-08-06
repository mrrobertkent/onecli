import { headers } from "next/headers";
import { auth } from "@/lib/auth/better-auth-config";
import { db } from "@onecli/db";
import {
  findUserDefaultProject,
  bootstrapOrganization,
  joinSharedOrganization,
} from "@onecli/api/services/organization-service";
import { CAPS } from "@/lib/env";
import { getAuthMode } from "./auth-mode";
import type { AuthUser } from "./types";
import { LOCAL_AUTH_ID, LOCAL_USER } from "./local-user";

let localUserEnsured = false;

const ensureLocalUser = async () => {
  if (localUserEnsured) return;

  const user = await db.user.upsert({
    where: { externalAuthId: LOCAL_AUTH_ID },
    create: {
      externalAuthId: LOCAL_AUTH_ID,
      email: LOCAL_USER.email,
      name: LOCAL_USER.name,
    },
    update: {},
    select: { id: true },
  });

  const existing = await findUserDefaultProject(user.id);
  if (!existing) {
    // Mirrors the /v1/auth/session gate. The local-auth identity is the sole
    // operator of a single-user instance, so `owner` is correct; this is the
    // only place outside the bootstrap path that may ask for it.
    if (CAPS.tenancy === "single-org-shared") {
      await joinSharedOrganization(user.id, LOCAL_USER.email, "owner");
    } else {
      await bootstrapOrganization(user.id, LOCAL_USER.email, LOCAL_USER.name);
    }
  }

  localUserEnsured = true;
};

export const getServerSessionImpl = async (): Promise<AuthUser | null> => {
  if (getAuthMode() === "local") {
    await ensureLocalUser();
    return LOCAL_USER;
  }

  const session = await auth.api.getSession({ headers: await headers() });
  if (!session?.user?.email) return null;

  // `session.user.id` is `users.id`, and the create hook keeps
  // `externalAuthId` equal to it, so this still resolves through the session
  // middleware's `externalAuthId` lookup.
  return {
    id: session.user.id,
    email: session.user.email,
    name: session.user.name ?? undefined,
    // Declared in `packages/api` long before the column existed to back it.
    emailVerified: session.user.emailVerified,
  };
};
