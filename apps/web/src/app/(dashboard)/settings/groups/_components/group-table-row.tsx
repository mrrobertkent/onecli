"use client";

import { useState } from "react";
import { Badge } from "@onecli/ui/components/badge";
import { Button } from "@onecli/ui/components/button";
import { TableCell, TableRow } from "@onecli/ui/components/table";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@onecli/ui/components/alert-dialog";
import { groups } from "@/lib/api";
import type { GroupRow } from "@/lib/api";

export interface GroupTableRowProps {
  group: GroupRow;
  onEdit: () => void;
  onManageMembers: () => void;
  onChanged: (message: string) => void;
  onError: (message: string) => void;
}

export const GroupTableRow = ({
  group,
  onEdit,
  onManageMembers,
  onChanged,
  onError,
}: GroupTableRowProps) => {
  const [busy, setBusy] = useState(false);
  const everyone = group.membershipMode === "all-users";
  const everywhere = group.projectAccessMode === "all-projects";

  const remove = async () => {
    setBusy(true);
    try {
      await groups.remove(group.id);
      onChanged(`${group.name} deleted.`);
    } catch (err) {
      onError(err instanceof Error ? err.message : "Could not delete.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <TableRow>
      <TableCell>
        <div className="flex items-center gap-2">
          <span className="text-sm">{group.name}</span>
          {group.source !== "manual" && (
            <Badge variant="outline">{group.source}</Badge>
          )}
        </div>
      </TableCell>
      <TableCell>
        <button
          type="button"
          onClick={onManageMembers}
          className="text-left text-sm hover:underline"
        >
          {everyone ? (
            <span>
              Everyone
              <span className="text-muted-foreground">
                {" "}
                ({group.memberCount})
              </span>
            </span>
          ) : (
            <span>
              {group.memberCount}{" "}
              {group.memberCount === 1 ? "person" : "people"}
            </span>
          )}
        </button>
      </TableCell>
      <TableCell>
        <span className="text-sm">
          {everywhere ? "Every project" : "Selected projects"}
        </span>
      </TableCell>
      <TableCell className="text-right">
        <div className="flex justify-end gap-1">
          <Button variant="ghost" size="sm" disabled={busy} onClick={onEdit}>
            Edit
          </Button>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="ghost" size="sm" disabled={busy}>
                Delete
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete {group.name}?</AlertDialogTitle>
                <AlertDialogDescription>
                  Its members, its project access and any role mapping pointing
                  at it go with it. The people themselves are untouched.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={() => void remove()}>
                  Delete group
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </TableCell>
    </TableRow>
  );
};
