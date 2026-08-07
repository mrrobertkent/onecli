"use client";

import { useState } from "react";
import { Badge } from "@onecli/ui/components/badge";
import { Button } from "@onecli/ui/components/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@onecli/ui/components/select";
import { TableCell, TableRow } from "@onecli/ui/components/table";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@onecli/ui/components/tooltip";
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
import { orgMembers } from "@/lib/api";
import type { OrgMemberListRow } from "@/lib/api";
import type { OrgViewer } from "@/lib/actions/require-org-role";

export interface MemberRowProps {
  member: OrgMemberListRow;
  viewer: OrgViewer;
  onChanged: (message: string) => void;
  onError: (message: string) => void;
}

/** Why this row is not editable, or null when it is. */
const lockReason = (
  member: OrgMemberListRow,
  viewer: OrgViewer,
): string | null => {
  if (member.userId === viewer.userId) {
    return "You cannot change your own role or access.";
  }
  if (member.role === "owner" && viewer.role !== "owner") {
    return "Only an owner can change another owner.";
  }
  return null;
};

export const MemberRow = ({
  member,
  viewer,
  onChanged,
  onError,
}: MemberRowProps) => {
  const [busy, setBusy] = useState(false);
  const locked = lockReason(member, viewer);
  const suspended = member.status === "suspended";

  // Only an owner may appoint one, so the option is absent for an admin rather
  // than offered and refused.
  const roles =
    viewer.role === "owner"
      ? ["owner", "admin", "member"]
      : ["admin", "member"];

  const run = async (work: () => Promise<string>) => {
    setBusy(true);
    try {
      onChanged(await work());
    } catch (err) {
      onError(err instanceof Error ? err.message : "That did not work.");
    } finally {
      setBusy(false);
    }
  };

  const changeRole = (role: string) =>
    run(async () => {
      if (role !== "owner" && role !== "admin" && role !== "member") {
        throw new Error("Unknown role");
      }
      await orgMembers.update(member.userId, { role });
      return `${member.email} is now ${role === "owner" ? "an owner" : role === "admin" ? "an admin" : "a member"}.`;
    });

  const setStatus = (status: "active" | "suspended") =>
    run(async () => {
      const result = await orgMembers.update(member.userId, { status });
      if (status === "active") return `${member.email} can sign in again.`;
      return result.sessionsRevoked > 0
        ? `${member.email} revoked, and ${result.sessionsRevoked} session${result.sessionsRevoked === 1 ? "" : "s"} ended.`
        : `${member.email} revoked. They had no active sessions.`;
    });

  const roleControl =
    locked || member.role === "owner" ? (
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="text-muted-foreground cursor-default text-sm capitalize">
            {member.role}
          </span>
        </TooltipTrigger>
        <TooltipContent>
          {locked ?? "An owner's role is changed from the owner row."}
        </TooltipContent>
      </Tooltip>
    ) : (
      <Select
        value={member.role}
        disabled={busy}
        onValueChange={(value) => void changeRole(value)}
      >
        <SelectTrigger
          className="h-8 w-32"
          aria-label={`Role for ${member.email}`}
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {roles.map((role) => (
            <SelectItem key={role} value={role} className="capitalize">
              {role}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    );

  return (
    <TableRow>
      <TableCell>
        <div className="flex flex-col">
          <span className="text-sm">{member.email}</span>
          {member.name && (
            <span className="text-muted-foreground text-xs">{member.name}</span>
          )}
        </div>
      </TableCell>
      <TableCell>{roleControl}</TableCell>
      <TableCell>
        <Badge variant={suspended ? "destructive" : "secondary"}>
          {suspended ? "Revoked" : "Active"}
        </Badge>
      </TableCell>
      <TableCell className="text-right">
        {locked ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="text-muted-foreground text-xs">—</span>
            </TooltipTrigger>
            <TooltipContent>{locked}</TooltipContent>
          </Tooltip>
        ) : suspended ? (
          <Button
            variant="outline"
            size="sm"
            disabled={busy}
            onClick={() => void setStatus("active")}
          >
            Restore
          </Button>
        ) : (
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="outline" size="sm" disabled={busy}>
                Revoke
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Revoke {member.email}?</AlertDialogTitle>
                <AlertDialogDescription>
                  They lose access immediately and every session they have open
                  ends. Their account stays, so you can restore it later.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={() => void setStatus("suspended")}>
                  Revoke access
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        )}
      </TableCell>
    </TableRow>
  );
};
