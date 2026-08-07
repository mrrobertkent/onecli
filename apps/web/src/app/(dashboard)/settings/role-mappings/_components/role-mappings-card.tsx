"use client";

import { useCallback, useEffect, useState } from "react";
import { ArrowDown, ArrowUp, Lock, Plus } from "lucide-react";
import { toast } from "sonner";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@onecli/ui/components/card";
import { Badge } from "@onecli/ui/components/badge";
import { Button } from "@onecli/ui/components/button";
import { Skeleton } from "@onecli/ui/components/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@onecli/ui/components/table";
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
import { roleMappings } from "@/lib/api";
import type { RoleMappingRow } from "@/lib/api";
import { CreateMappingDialog } from "./create-mapping-dialog";

export interface RoleMappingsCardProps {
  /** False for an admin: the mappings are owner-only to write (D-16). */
  canWrite: boolean;
}

export const RoleMappingsCard = ({ canWrite }: RoleMappingsCardProps) => {
  const [rows, setRows] = useState<RoleMappingRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setRows(await roleMappings.list());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load mappings.");
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

  const move = async (index: number, delta: number) => {
    const next = [...rows];
    const target = index + delta;
    const a = next[index];
    const b = next[target];
    if (!a || !b) return;
    next[index] = b;
    next[target] = a;

    setBusy(true);
    setRows(next);
    try {
      await roleMappings.reorder(next.map((m) => m.id));
      toast.success("Order saved.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not reorder.");
      await load();
    } finally {
      setBusy(false);
    }
  };

  const remove = async (mapping: RoleMappingRow) => {
    setBusy(true);
    try {
      await roleMappings.remove(mapping.id);
      onSaved(`${mapping.groupName} no longer confers a role.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Role mappings</CardTitle>
        <CardDescription>
          At each sign-in the first mapping matching one of the person&rsquo;s
          identity provider groups decides their role. Someone who matches
          nothing is not admitted.
        </CardDescription>
        <CardAction>
          {canWrite ? (
            <Button size="sm" onClick={() => setCreating(true)}>
              <Plus className="size-4" />
              New mapping
            </Button>
          ) : null}
        </CardAction>
      </CardHeader>
      <CardContent className="space-y-4">
        {!canWrite && (
          <div className="bg-muted/50 flex items-start gap-3 rounded-lg border p-3">
            <Lock className="text-muted-foreground mt-0.5 size-4 shrink-0" />
            <div className="space-y-1">
              <p className="text-sm font-medium">
                Only an owner can edit these
              </p>
              <p className="text-muted-foreground text-sm">
                A mapping grants admin, and an admin who could edit one could
                grant themselves admin through a group they can join in the
                directory. Ask an owner for the change.
              </p>
            </div>
          </div>
        )}

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
            No mappings yet, so nobody from the identity provider can sign in.
            {canWrite
              ? " Create one against a group named exactly as your provider names it."
              : ""}
          </p>
        ) : (
          <div className="overflow-hidden rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-20">Order</TableHead>
                  <TableHead>Group</TableHead>
                  <TableHead className="w-32">Role</TableHead>
                  <TableHead className="w-28">Members</TableHead>
                  {canWrite && (
                    <TableHead className="w-28 text-right">Remove</TableHead>
                  )}
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((mapping, index) => (
                  <TableRow key={mapping.id}>
                    <TableCell>
                      {canWrite ? (
                        <div className="flex gap-0.5">
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-7"
                            aria-label={`Move ${mapping.groupName} up`}
                            disabled={busy || index === 0}
                            onClick={() => void move(index, -1)}
                          >
                            <ArrowUp className="size-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-7"
                            aria-label={`Move ${mapping.groupName} down`}
                            disabled={busy || index === rows.length - 1}
                            onClick={() => void move(index, 1)}
                          >
                            <ArrowDown className="size-3.5" />
                          </Button>
                        </div>
                      ) : (
                        <span className="text-muted-foreground text-sm tabular-nums">
                          {index + 1}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-sm">
                      {mapping.groupName}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          mapping.role === "admin" ? "default" : "secondary"
                        }
                      >
                        {mapping.role}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {mapping.memberCount}
                    </TableCell>
                    {canWrite && (
                      <TableCell className="text-right">
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button variant="ghost" size="sm" disabled={busy}>
                              Delete
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>
                                Stop {mapping.groupName} conferring{" "}
                                {mapping.role}?
                              </AlertDialogTitle>
                              <AlertDialogDescription>
                                Anyone who relies on this mapping and matches no
                                other one loses access at their next sign-in.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => void remove(mapping)}
                              >
                                Delete mapping
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>

      {creating && (
        <CreateMappingDialog
          onClose={() => setCreating(false)}
          onSaved={onSaved}
        />
      )}
    </Card>
  );
};
