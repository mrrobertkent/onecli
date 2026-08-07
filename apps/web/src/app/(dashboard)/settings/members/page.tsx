import type { Metadata } from "next";
import { PageHeader } from "@dashboard/page-header";
import { readOrgViewer } from "@/lib/actions/require-org-role";
import { AdministratorOnly } from "../_components/administrator-only";
import { MembersCard } from "./_components/members-card";

export const metadata: Metadata = {
  title: "Members",
};

export default async function MembersPage() {
  // Read once here so the page can explain the controls it will not offer, and
  // know which row is the viewer's own. Every action still checks for itself.
  const viewer = await readOrgViewer();
  const isAdmin = viewer?.role === "admin" || viewer?.role === "owner";

  return (
    <div className="flex flex-1 flex-col gap-4">
      <PageHeader
        title="Members"
        description="Everyone with an account on this instance, and what they can do."
      />
      {isAdmin && viewer ? (
        <MembersCard viewer={viewer} />
      ) : (
        <AdministratorOnly what="Membership" />
      )}
    </div>
  );
}
