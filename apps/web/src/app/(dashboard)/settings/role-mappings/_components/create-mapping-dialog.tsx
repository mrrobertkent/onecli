"use client";

import { useEffect, useState } from "react";
import { Button } from "@onecli/ui/components/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@onecli/ui/components/dialog";
import { Label } from "@onecli/ui/components/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@onecli/ui/components/select";
import { groups, roleMappings } from "@/lib/api";
import type { GroupRow } from "@/lib/api";

export interface CreateMappingDialogProps {
  onClose: () => void;
  onSaved: (message: string) => void;
}

type MappedRole = "admin" | "member";

export const CreateMappingDialog = ({
  onClose,
  onSaved,
}: CreateMappingDialogProps) => {
  const [available, setAvailable] = useState<GroupRow[]>([]);
  const [groupId, setGroupId] = useState("");
  const [role, setRole] = useState<MappedRole>("member");
  const [impact, setImpact] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [all, mapped] = await Promise.all([
          groups.list({ limit: 200 }),
          roleMappings.list(),
        ]);
        // One mapping per group, so a group that already has one is not offered.
        const taken = new Set(mapped.map((m) => m.groupId));
        setAvailable(all.data.filter((g) => !taken.has(g.id)));
      } catch (err) {
        setError(err instanceof Error ? err.message : "Could not load groups.");
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, []);

  // A dry run of the same resolution sign-in performs, so the owner sees the
  // blast radius before committing to it.
  useEffect(() => {
    if (!groupId) {
      setImpact(null);
      return;
    }
    let current = true;
    roleMappings
      .preview({ groupId, role })
      .then((result) => {
        if (current) setImpact(result.affectedCount);
      })
      .catch(() => {
        if (current) setImpact(null);
      });
    return () => {
      current = false;
    };
  }, [groupId, role]);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await roleMappings.create({ groupId, role });
      const group = available.find((g) => g.id === groupId);
      onSaved(`${group?.name ?? "Group"} now confers ${role}.`);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New role mapping</DialogTitle>
          <DialogDescription>
            The group must be named exactly as your identity provider names it —
            that name is what arrives in the sign-in claim.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="mapping-group">Group</Label>
            <Select
              value={groupId}
              disabled={loading || available.length === 0}
              onValueChange={setGroupId}
            >
              <SelectTrigger id="mapping-group" className="w-full">
                <SelectValue
                  placeholder={
                    loading
                      ? "Loading..."
                      : available.length === 0
                        ? "Every group already maps to a role"
                        : "Choose a group"
                  }
                />
              </SelectTrigger>
              <SelectContent>
                {available.map((group) => (
                  <SelectItem key={group.id} value={group.id}>
                    {group.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="mapping-role">Role</Label>
            <Select
              value={role}
              onValueChange={(v) => setRole(v as MappedRole)}
            >
              <SelectTrigger id="mapping-role" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="member">Member</SelectItem>
                <SelectItem value="admin">Admin</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-muted-foreground text-xs">
              Owner is never conferred from the directory — anyone who can edit
              a group there would otherwise take the instance.
            </p>
          </div>

          {impact !== null && (
            <p className="text-muted-foreground text-sm">
              {impact === 0
                ? "No one's role changes at their next sign-in."
                : `${impact} ${impact === 1 ? "person changes" : "people change"} role at their next sign-in.`}
            </p>
          )}

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
          <Button onClick={() => void save()} disabled={saving || !groupId}>
            {saving ? "Creating..." : "Create mapping"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
