"use client";

import { useEffect, useState } from "react";
import { Button } from "@onecli/ui/components/button";
import { Checkbox } from "@onecli/ui/components/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@onecli/ui/components/dialog";
import { ScrollArea } from "@onecli/ui/components/scroll-area";
import { Skeleton } from "@onecli/ui/components/skeleton";
import { groups, orgMembers } from "@/lib/api";
import type { GroupMemberRow, GroupRow, OrgMemberListRow } from "@/lib/api";

export interface GroupMembersDialogProps {
  group: GroupRow;
  onClose: () => void;
  onSaved: (message: string) => void;
}

export const GroupMembersDialog = ({
  group,
  onClose,
  onSaved,
}: GroupMembersDialogProps) => {
  const everyone = group.membershipMode === "all-users";
  const [people, setPeople] = useState<OrgMemberListRow[]>([]);
  const [computed, setComputed] = useState<GroupMemberRow[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        if (everyone) {
          // Nothing to choose: the membership is resolved, not stored.
          setComputed((await groups.members(group.id, { limit: 200 })).data);
        } else {
          const [directory, current] = await Promise.all([
            orgMembers.list({ limit: 200, status: "active" }),
            groups.members(group.id, { limit: 200 }),
          ]);
          setPeople(directory.data);
          setSelected(new Set(current.data.map((m) => m.userId)));
        }
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Could not load people.");
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, [group.id, everyone]);

  const toggle = (userId: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(userId)) next.delete(userId);
      else next.add(userId);
      return next;
    });
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const result = await groups.setMembers(group.id, [...selected]);
      onSaved(
        `${group.name}: ${result.added} added, ${result.removed} removed.`,
      );
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{group.name}</DialogTitle>
          <DialogDescription>
            {everyone
              ? "This group is everyone. Its members are worked out as people are added to the instance, so there is no list to edit — change it to “the people I choose” to pick them."
              : "Only active members of this instance can be added."}
          </DialogDescription>
        </DialogHeader>

        {loading ? (
          <div className="space-y-2">
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
          </div>
        ) : (
          <ScrollArea className="max-h-72 pr-3">
            <ul className="space-y-1">
              {everyone
                ? computed.map((person) => (
                    <li
                      key={person.userId}
                      className="text-muted-foreground flex h-9 items-center px-1 text-sm"
                    >
                      {person.email}
                    </li>
                  ))
                : people.map((person) => (
                    <li key={person.userId}>
                      <label className="hover:bg-accent flex h-9 cursor-pointer items-center gap-3 rounded-md px-1 text-sm">
                        <Checkbox
                          checked={selected.has(person.userId)}
                          onCheckedChange={() => toggle(person.userId)}
                        />
                        <span>{person.email}</span>
                      </label>
                    </li>
                  ))}
            </ul>
          </ScrollArea>
        )}

        {error && (
          <p className="text-destructive text-sm" role="alert">
            {error}
          </p>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={saving}>
            {everyone ? "Close" : "Cancel"}
          </Button>
          {!everyone && (
            <Button onClick={() => void save()} disabled={saving || loading}>
              {saving ? "Saving..." : "Save members"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
