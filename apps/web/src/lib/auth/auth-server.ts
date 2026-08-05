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
    // Mirror the /v1/auth/session gate: single shared org joins the one shared
    // org, while per-user tenancy bootstraps its own.
    //
    // This is the LOCAL-auth identity — the sole operator of a single-user
    // instance — so `owner` is the correct role here and is the one place
    // outside the bootstrap path that may ask for it (design D-11). Task 5
    // replaces this synthetic identity with a real Better Auth account (D-12).
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

  // Under D-10 `session.user.id` IS `users.id`, and the create hook keeps
  // `externalAuthId` equal to it — so the `SessionUser.id` this returns still
  // resolves through `middleware/auth/session.ts`'s `externalAuthId` lookup.
  return {
    id: session.user.id,
    email: session.user.email,
    name: session.user.name ?? undefined,
    // Finally populated: declared in `packages/api`, never written until D-10
    // added the column.
    emailVerified: session.user.emailVerified,
  };
};
