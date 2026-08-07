import type { Metadata } from "next";
import { PageHeader } from "@dashboard/page-header";
import { readOrgViewer } from "@/lib/actions/require-org-role";
import { AdministratorOnly } from "../_components/administrator-only";
import { GroupsCard } from "./_components/groups-card";

export const metadata: Metadata = {
  title: "Groups",
};

export default async function GroupsPage() {
  const viewer = await readOrgViewer();
  const isAdmin = viewer?.role === "admin" || viewer?.role === "owner";

  return (
    <div className="flex flex-1 flex-col gap-4">
      <PageHeader
        title="Groups"
        description="Your own grouping of people, and the projects they reach."
      />
      {isAdmin ? <GroupsCard /> : <AdministratorOnly what="Groups" />}
    </div>
  );
}
