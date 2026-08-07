"use client";

import { useState } from "react";
import { Button } from "@onecli/ui/components/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@onecli/ui/components/dialog";
import { Input } from "@onecli/ui/components/input";
import { Label } from "@onecli/ui/components/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@onecli/ui/components/select";
import { groups } from "@/lib/api";
import type { GroupRow, UpdateGroupInput } from "@/lib/api";

export interface GroupDialogProps {
  /** Null creates a new group. */
  group: GroupRow | null;
  onClose: () => void;
  onSaved: (message: string) => void;
}

type Membership = NonNullable<UpdateGroupInput["membershipMode"]>;
type ProjectAccess = NonNullable<UpdateGroupInput["projectAccessMode"]>;

export const GroupDialog = ({ group, onClose, onSaved }: GroupDialogProps) => {
  const [name, setName] = useState(group?.name ?? "");
  const [membership, setMembership] = useState<Membership>(
    group?.membershipMode ?? "explicit",
  );
  const [access, setAccess] = useState<ProjectAccess>(
    group?.projectAccessMode ?? "selected",
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      if (group) {
        await groups.update(group.id, {
          name,
          membershipMode: membership,
          projectAccessMode: access,
        });
        onSaved(`${name} saved.`);
      } else {
        await groups.create(name, {
          membershipMode: membership,
          projectAccessMode: access,
        });
        onSaved(`${name} created.`);
      }
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
          <DialogTitle>{group ? "Edit group" : "New group"}</DialogTitle>
          <DialogDescription>
            To map an identity provider group to a role, name this group exactly
            as the provider does.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="group-name">Name</Label>
            <Input
              id="group-name"
              value={name}
              autoFocus
              onChange={(e) => setName(e.target.value)}
              placeholder="Platform engineers"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="group-membership">Members</Label>
            <Select
              value={membership}
              onValueChange={(v) => setMembership(v as Membership)}
            >
              <SelectTrigger id="group-membership" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="explicit">The people I choose</SelectItem>
                <SelectItem value="all-users">
                  Everyone, now and in future
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="group-access">Project access</Label>
            <Select
              value={access}
              onValueChange={(v) => setAccess(v as ProjectAccess)}
            >
              <SelectTrigger id="group-access" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="selected">
                  Only projects it is added to
                </SelectItem>
                <SelectItem value="all-projects">
                  Every project, now and in future
                </SelectItem>
              </SelectContent>
            </Select>
            <p className="text-muted-foreground text-xs">
              Every project reaches every project&rsquo;s data without making
              anyone an admin.
            </p>
          </div>

          {error && (
            <p className="text-destructive text-sm" role="alert">
              {error}
            </p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={() => void save()} disabled={saving || !name.trim()}>
            {saving ? "Saving..." : group ? "Save" : "Create group"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
