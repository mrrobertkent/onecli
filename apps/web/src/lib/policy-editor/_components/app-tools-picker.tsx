"use client";

import { useMemo, useState } from "react";
import { ChevronDown } from "lucide-react";
import { Button } from "@onecli/ui/components/button";
import { Checkbox } from "@onecli/ui/components/checkbox";
import { Input } from "@onecli/ui/components/input";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@onecli/ui/components/popover";
import { cn } from "@onecli/ui/lib/utils";
import type { AppToolGroupSummary } from "@onecli/api/apps/app-permissions/types";
import { useAppPermissionDefinitions } from "@/hooks/use-app-permissions";

export interface AppToolsPickerProps {
  /** The provider whose catalog tools to offer; empty until an app is picked. */
  provider: string;
  /** Selected catalog tool ids — concrete tools and/or a group's wildcard id
   * (e.g. `read_all`); [] = the whole app. */
  value: string[];
  onChange: (next: string[]) => void;
  id?: string;
}

// Mirrors app-permission-group.tsx.
const GROUP_LABELS: Record<string, string> = {
  read: "Read-only",
  write: "Write / delete",
};

/**
 * Grouped, searchable multi-select over a provider's catalog tools for the rule
 * dialog's App target. Empty selection = the whole app.
 *
 * A group whose wildcard is a verified superset of its tools (`wildcardComplete`)
 * renders its header as that umbrella: checking it stores the single wildcard id
 * and the concrete rows show as covered. A group with no wildcard, or an
 * incomplete one, keeps a plain select-all header so the picker never offers a
 * misleading "all X".
 */
export const AppToolsPicker = ({
  provider,
  value,
  onChange,
  id,
}: AppToolsPickerProps) => {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const { data: definitions = [], isPending } = useAppPermissionDefinitions();

  const groups = useMemo<AppToolGroupSummary[]>(
    () => definitions.find((d) => d.provider === provider)?.groups ?? [],
    [definitions, provider],
  );

  // Concrete tool ids only — the denominator for the "N of M" count.
  const allToolIds = useMemo(
    () => groups.flatMap((g) => g.tools.map((t) => t.id)),
    [groups],
  );
  // Every selectable id in catalog order, wildcard first per group. The stored
  // array is normalized to this, so rebuilding the set never drops a wildcard.
  const orderedAllIds = useMemo(
    () =>
      groups.flatMap((g) => [
        ...(g.wildcard ? [g.wildcard.id] : []),
        ...g.tools.map((t) => t.id),
      ]),
    [groups],
  );
  const selected = useMemo(() => new Set(value), [value]);

  const needle = q.trim().toLowerCase();
  // Filters only the rendered rows; header/count/toggle state still reads the
  // full group, so select-all can never act on a partial set.
  const visibleGroups = useMemo(
    () =>
      groups
        .map((group) => {
          const wildcardMatches =
            !!needle &&
            !!group.wildcard &&
            (group.wildcard.name.toLowerCase().includes(needle) ||
              group.wildcard.description.toLowerCase().includes(needle));
          const rows =
            needle && !wildcardMatches
              ? group.tools.filter(
                  (t) =>
                    t.name.toLowerCase().includes(needle) ||
                    t.description.toLowerCase().includes(needle),
                )
              : group.tools;
          return { group, rows, wildcardMatches };
        })
        .filter((g) => g.rows.length > 0 || g.wildcardMatches),
    [groups, needle],
  );

  const isWildcardOn = (g: AppToolGroupSummary): boolean =>
    !!g.wildcard && selected.has(g.wildcard.id);
  // True when the wildcard covers the whole group, or when an incomplete one is
  // already selected so it stays visible and uncheckable. An incomplete
  // wildcard is never offered fresh — it would author a misleading "all X".
  const umbrellaActive = (g: AppToolGroupSummary): boolean =>
    !!g.wildcard && (g.wildcardComplete === true || isWildcardOn(g));

  const toggleTool = (toolId: string) => {
    const next = new Set(selected);
    if (next.has(toolId)) next.delete(toolId);
    else next.add(toolId);
    onChange(orderedAllIds.filter((tid) => next.has(tid)));
  };

  // Operates on the full group, never the search-filtered rows.
  const toggleGroup = (group: AppToolGroupSummary, checked: boolean) => {
    const next = new Set(selected);
    if (group.wildcard && umbrellaActive(group)) {
      // Checking the umbrella drops the group's now-subsumed concrete ids.
      if (checked) {
        next.add(group.wildcard.id);
        group.tools.forEach((t) => next.delete(t.id));
      } else {
        next.delete(group.wildcard.id);
      }
    } else {
      const ids = new Set(group.tools.map((t) => t.id));
      if (checked) ids.forEach((tid) => next.add(tid));
      else ids.forEach((tid) => next.delete(tid));
    }
    onChange(orderedAllIds.filter((tid) => next.has(tid)));
  };

  // Zero when the umbrella is on, since selecting it drops the concrete ids.
  const groupSelectedCount = (group: AppToolGroupSummary): number =>
    group.tools.filter((t) => selected.has(t.id)).length;

  const noCatalog = !isPending && groups.length === 0;

  // Ids subsumed by a selected complete umbrella, excluded from the trigger's
  // "N more". An incomplete umbrella's concrete selections still count.
  const coveredConcreteIds = useMemo(
    () =>
      new Set(
        groups
          .filter(
            (g) =>
              g.wildcard &&
              g.wildcardComplete === true &&
              selected.has(g.wildcard.id),
          )
          .flatMap((g) => g.tools.map((t) => t.id)),
      ),
    [groups, selected],
  );

  // A selected wildcard is one id covering many ops, so it can't read as "N of
  // M"; name the umbrellas instead and append any extra concrete count. The
  // "of M" total is held back until the catalog settles so an edit never
  // flashes "N of 0".
  const selectedWildcardNames = groups
    .filter((g) => isWildcardOn(g))
    .map((g) => g.wildcard?.name)
    .filter((n): n is string => !!n);
  const concreteSelectedCount = value.filter(
    (v) => allToolIds.includes(v) && !coveredConcreteIds.has(v),
  ).length;
  const triggerLabel = (() => {
    if (value.length === 0) return "All tools";
    if (selectedWildcardNames.length === 0) {
      return allToolIds.length === 0
        ? `${value.length} tool${value.length === 1 ? "" : "s"}`
        : `${concreteSelectedCount} of ${allToolIds.length} tool${
            allToolIds.length === 1 ? "" : "s"
          }`;
    }
    const parts = [...selectedWildcardNames];
    if (concreteSelectedCount > 0) parts.push(`${concreteSelectedCount} more`);
    return parts.join(" · ");
  })();

  return (
    // `modal`: this popover opens inside the rule-form Sheet, and without it
    // the scrollable list can't wheel-scroll.
    <Popover
      modal
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
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
          disabled={noCatalog}
          className="bg-card hover:bg-card w-full justify-between gap-2 font-normal"
        >
          <span
            className={cn(
              "truncate",
              value.length === 0 && "text-muted-foreground",
            )}
          >
            {noCatalog ? "No tools to narrow" : triggerLabel}
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
            placeholder="Search tools…"
            aria-label="Search tools"
            className="h-8"
            autoFocus
          />
        </div>
        <div className="max-h-72 overflow-y-auto overscroll-contain p-1">
          {isPending ? (
            <p className="text-muted-foreground px-2 py-6 text-center text-xs">
              Loading tools…
            </p>
          ) : visibleGroups.length === 0 ? (
            <p className="text-muted-foreground px-2 py-6 text-center text-xs">
              {needle ? `No tools match “${q.trim()}”.` : "No tools."}
            </p>
          ) : (
            visibleGroups.map(({ group, rows }) => {
              const umbrella = umbrellaActive(group)
                ? group.wildcard
                : undefined;
              const wildOn = isWildcardOn(group);
              const inGroup = groupSelectedCount(group);
              const allConcrete =
                group.tools.length > 0 && inGroup === group.tools.length;
              const headerChecked = umbrella ? wildOn : allConcrete;
              const headerLabel = umbrella
                ? umbrella.name
                : (GROUP_LABELS[group.category] ?? group.category);
              const rowsCovered = wildOn && group.wildcardComplete === true;
              // A checked header whose rows aren't covered looks like a broken
              // umbrella, so the caption below explains the one-way affordance.
              const incompleteUmbrellaOn = !!umbrella && wildOn && !rowsCovered;
              return (
                <div key={group.category} className="mb-1">
                  <div className="flex items-center justify-between gap-2 px-2 pt-2 pb-1">
                    <span className="flex min-w-0 flex-col gap-0.5">
                      <span className="flex items-center gap-2 text-xs font-semibold">
                        {headerLabel}
                        <span className="bg-muted text-muted-foreground inline-flex items-center rounded-full px-1.5 py-0.5 text-[11px] font-medium tabular-nums">
                          {/* A fraction only while strictly partial; otherwise
                              the bare total. */}
                          {!rowsCovered && inGroup > 0 && !allConcrete
                            ? `${inGroup}/${group.tools.length}`
                            : group.tools.length}
                        </span>
                      </span>
                      {incompleteUmbrellaOn && (
                        <span className="text-muted-foreground text-[11px] italic">
                          Uncheck to choose tools individually
                        </span>
                      )}
                    </span>
                    <Checkbox
                      checked={headerChecked}
                      onCheckedChange={(c) => toggleGroup(group, c === true)}
                      aria-label={
                        umbrella
                          ? headerLabel
                          : `Select all ${headerLabel} tools`
                      }
                    />
                  </div>
                  {rows.map((tool) => {
                    const rowId = `tool-${provider}-${tool.id}`;
                    // Covered tools can't be cherry-picked out; excluding one
                    // takes a separate block rule.
                    const covered = rowsCovered;
                    const rowChecked = covered || selected.has(tool.id);
                    return (
                      <label
                        key={tool.id}
                        htmlFor={rowId}
                        className={cn(
                          "flex items-start gap-2.5 rounded-md px-2 py-1.5",
                          covered
                            ? "cursor-default"
                            : "hover:bg-muted cursor-pointer",
                        )}
                      >
                        <Checkbox
                          id={rowId}
                          className="mt-0.5"
                          checked={rowChecked}
                          disabled={covered}
                          onCheckedChange={() => {
                            if (!covered) toggleTool(tool.id);
                          }}
                        />
                        <span className="min-w-0">
                          {/* Dim the text, not the label, so the disabled
                              checkbox keeps its check-mark legible. */}
                          <span
                            className={cn(
                              "block text-sm leading-tight",
                              covered && "text-muted-foreground",
                            )}
                          >
                            {tool.name}
                            {covered && (
                              <span className="italic"> · included</span>
                            )}
                          </span>
                          {tool.description && (
                            <span className="text-muted-foreground block text-[11.5px] leading-tight">
                              {tool.description}
                            </span>
                          )}
                        </span>
                      </label>
                    );
                  })}
                </div>
              );
            })
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
};
