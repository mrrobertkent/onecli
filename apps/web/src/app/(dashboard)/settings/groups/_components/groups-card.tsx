"use client";

import { useCallback, useEffect, useState } from "react";
import { Plus } from "lucide-react";
import { toast } from "sonner";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@onecli/ui/components/card";
import { Button } from "@onecli/ui/components/button";
import { Skeleton } from "@onecli/ui/components/skeleton";
import {
  Table,
  TableBody,
  TableHead,
  TableHeader,
  TableRow,
} from "@onecli/ui/components/table";
import { groups } from "@/lib/api";
import type { GroupRow } from "@/lib/api";
import { GroupDialog } from "./group-dialog";
import { GroupTableRow } from "./group-table-row";
import { GroupMembersDialog } from "./group-members-dialog";

export const GroupsCard = () => {
  const [rows, setRows] = useState<GroupRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<GroupRow | null>(null);
  const [creating, setCreating] = useState(false);
  const [managing, setManaging] = useState<GroupRow | null>(null);

  const load = useCallback(async () => {
    try {
      const page = await groups.list({ limit: 200 });
      setRows(page.data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load groups.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const onSaved = (message: string) => {
    toast.success(message);
    void load();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Groups</CardTitle>
        <CardDescription>
          A group is whatever you want it to be — your name, your members, your
          projects. The two &ldquo;all&rdquo; settings keep applying to people
          and projects created later, with nothing to re-sync.
        </CardDescription>
        <CardAction>
          <Button size="sm" onClick={() => setCreating(true)}>
            <Plus className="size-4" />
            New group
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="space-y-2">
            <Skeleton className="h-9 w-full" />
            <Skeleton className="h-9 w-full" />
          </div>
        ) : error ? (
          <p className="text-destructive text-sm" role="alert">
            {error}
          </p>
        ) : rows.length === 0 ? (
          <p className="text-muted-foreground text-sm">
            No groups yet. A group named for one of your identity
            provider&rsquo;s groups is what a role mapping points at.
          </p>
        ) : (
          <div className="overflow-hidden rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead className="w-44">Members</TableHead>
                  <TableHead className="w-48">Project access</TableHead>
                  <TableHead className="w-32 text-right">Manage</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((group) => (
                  <GroupTableRow
                    key={group.id}
                    group={group}
                    onEdit={() => setEditing(group)}
                    onManageMembers={() => setManaging(group)}
                    onChanged={onSaved}
                    onError={setError}
                  />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>

      {(creating || editing) && (
        <GroupDialog
          group={editing}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
          onSaved={onSaved}
        />
      )}
      {managing && (
        <GroupMembersDialog
          group={managing}
          onClose={() => setManaging(null)}
          onSaved={onSaved}
        />
      )}
    </Card>
  );
};
