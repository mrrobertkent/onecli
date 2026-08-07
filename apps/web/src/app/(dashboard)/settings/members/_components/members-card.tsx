"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@onecli/ui/components/card";
import { Skeleton } from "@onecli/ui/components/skeleton";
import {
  Table,
  TableBody,
  TableHead,
  TableHeader,
  TableRow,
} from "@onecli/ui/components/table";
import { orgMembers } from "@/lib/api";
import type { OrgMemberListRow } from "@/lib/api";
import type { OrgViewer } from "@/lib/actions/require-org-role";
import { MemberRow } from "./member-row";

export interface MembersCardProps {
  viewer: OrgViewer;
}

export const MembersCard = ({ viewer }: MembersCardProps) => {
  const [rows, setRows] = useState<OrgMemberListRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const page = await orgMembers.list({ limit: 200 });
      setRows(page.data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load members.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const onChanged = (message: string) => {
    toast.success(message);
    void load();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Members</CardTitle>
        <CardDescription>
          Roles come from the identity provider at each sign-in, so a change
          here lasts until the directory next says otherwise.{" "}
          {viewer.role === "owner"
            ? "As an owner you can appoint another owner; you cannot change your own row."
            : "An owner's row can only be changed by another owner."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="space-y-2">
            <Skeleton className="h-9 w-full" />
            <Skeleton className="h-9 w-full" />
            <Skeleton className="h-9 w-full" />
          </div>
        ) : error ? (
          <p className="text-destructive text-sm" role="alert">
            {error}
          </p>
        ) : rows.length === 0 ? (
          <p className="text-muted-foreground text-sm">No members yet.</p>
        ) : (
          <div className="overflow-hidden rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Person</TableHead>
                  <TableHead className="w-40">Role</TableHead>
                  <TableHead className="w-32">Status</TableHead>
                  <TableHead className="w-32 text-right">Access</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((row) => (
                  <MemberRow
                    key={row.userId}
                    member={row}
                    viewer={viewer}
                    onChanged={onChanged}
                    onError={setError}
                  />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
