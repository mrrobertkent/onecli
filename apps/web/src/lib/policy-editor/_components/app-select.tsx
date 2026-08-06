"use client";

import { useMemo, useState } from "react";
import { Check, ChevronDown } from "lucide-react";
import { Button } from "@onecli/ui/components/button";
import { Input } from "@onecli/ui/components/input";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@onecli/ui/components/popover";
import { getApp, getApps } from "@onecli/api/apps/registry";
import { AppIcon } from "@/app/(dashboard)/connections/_components/app-icon";
import { TeamBadge } from "@/lib/components/team-badge";

/**
 * True when the registry knows the app but this edition can't connect it, the
 * same `available` key the Connections list locks on. Only OSS carries
 * `available: false`, so this is false in every other edition.
 *
 * Ignores plan-gating: that is a billing concern the Connections page enforces
 * at connect time.
 */
export const isCloudOnlyApp = (id: string): boolean =>
  getApp(id)?.available === false;

export interface AppSelectProps {
  /** The selected provider id, or "" for none. */
  value: string;
  onChange: (id: string) => void;
  id?: string;
  /** Show the invalid (destructive) border — e.g. required-but-empty on submit. */
  invalid?: boolean;
}

/**
 * A single-select, searchable combobox over the app catalog. Clicking a row
 * selects it and closes the popover.
 */
export const AppSelect = ({ value, onChange, id, invalid }: AppSelectProps) => {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");

  const apps = useMemo(
    () => [...getApps()].sort((a, b) => a.name.localeCompare(b.name)),
    [],
  );
  const selectedApp = apps.find((a) => a.id === value);

  const needle = q.trim().toLowerCase();
  const filtered = needle
    ? apps.filter((a) => a.name.toLowerCase().includes(needle))
    : apps;

  const select = (appId: string) => {
    onChange(appId);
    setOpen(false);
    setQ("");
  };

  return (
    // `modal`: PopoverContent portals to <body>, outside the rule-form Sheet's
    // scroll-lock subtree, so without it the list could never scroll.
    <Popover
      modal
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        // Reset the search when closing so a reopen starts from the full list.
        if (!next) setQ("");
      }}
    >
      <PopoverTrigger asChild>
        <Button
          id={id}
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          aria-invalid={invalid ? true : undefined}
          className="bg-card hover:bg-card aria-invalid:border-destructive w-full justify-between gap-2 font-normal"
        >
          <span className="flex min-w-0 items-center gap-2">
            {selectedApp ? (
              <>
                <AppIcon
                  icon={selectedApp.icon}
                  darkIcon={selectedApp.darkIcon}
                  name={selectedApp.name}
                  size={18}
                />
                <span className="truncate">{selectedApp.name}</span>
                {!selectedApp.available && <TeamBadge />}
              </>
            ) : (
              <span className="text-muted-foreground">Select an app…</span>
            )}
          </span>
          <ChevronDown className="size-4 shrink-0 opacity-50" aria-hidden />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align="start"
        className="w-(--radix-popover-trigger-width) max-w-[90vw] p-0"
      >
        <div className="border-b p-2">
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search apps…"
            aria-label="Search apps"
            className="h-8"
            autoFocus
          />
        </div>
        <div className="max-h-64 overflow-y-auto overscroll-contain p-1">
          {filtered.length === 0 ? (
            <p className="text-muted-foreground px-2 py-6 text-center text-xs">
              No apps found.
            </p>
          ) : (
            filtered.map((a) => (
              <button
                key={a.id}
                type="button"
                onClick={() => select(a.id)}
                className="hover:bg-muted flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left"
              >
                <AppIcon
                  icon={a.icon}
                  darkIcon={a.darkIcon}
                  name={a.name}
                  size={18}
                />
                <span className="min-w-0 flex-1 truncate text-sm">
                  {a.name}
                </span>
                {!a.available && <TeamBadge />}
                {a.id === value && (
                  <Check className="size-4 shrink-0" aria-hidden />
                )}
              </button>
            ))
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
};
