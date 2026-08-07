import type { Metadata } from "next";
import { PageHeader } from "@dashboard/page-header";
import { readOrgViewer } from "@/lib/actions/require-org-role";
import { AdministratorOnly } from "../_components/administrator-only";
import { RoleMappingsCard } from "./_components/role-mappings-card";

export const metadata: Metadata = {
  title: "Role mappings",
};

export default async function RoleMappingsPage() {
  // An admin may read the mappings and may not write them, so the page needs
  // the exact role rather than "is an admin".
  const viewer = await readOrgViewer();
  const isAdmin = viewer?.role === "admin" || viewer?.role === "owner";

  return (
    <div className="flex flex-1 flex-col gap-4">
      <PageHeader
        title="Role mappings"
        description="Which identity provider group makes someone an admin or a member here."
      />
      {isAdmin && viewer ? (
        <RoleMappingsCard canWrite={viewer.role === "owner"} />
      ) : (
        <AdministratorOnly what="Role mapping" />
      )}
    </div>
  );
}
