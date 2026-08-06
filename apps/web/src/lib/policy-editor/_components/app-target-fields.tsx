"use client";

import { Label } from "@onecli/ui/components/label";
import { Checkbox } from "@onecli/ui/components/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@onecli/ui/components/select";
import { cn } from "@onecli/ui/lib/utils";
import { getApp } from "@onecli/api/apps/registry";
import { AppSelect } from "./app-select";
import { AppToolsPicker } from "./app-tools-picker";
import { TeamBadge } from "@/lib/components/team-badge";
// Edition seam — imported by alias key on purpose; a relative import would
// bypass turbopack resolveAlias in EE builds.
import { ResourceScopeFields } from "@/lib/policy-editor/resource-scope";
import type { Connection } from "@/lib/api";

/** Display name for the locked callout; falls back to the raw id. */
const providerName = (id: string): string => getApp(id)?.name ?? id;

/** The App target's editable state. `specific` becomes `connection` targets;
 * `all` becomes one `app` target carrying a `connectionScope`. */
export interface AppTargetState {
  provider: string;
  mode: "specific" | "all";
  connectionIds: string[];
  /** Only meaningful for `mode === "all"`; the org/project level to inject. */
  level: "organization" | "project";
  /** Catalog tool ids the rule is narrowed to; [] = the whole app. Narrows
   * which endpoints match, never injection. */
  tools: string[];
  /** Per-resource scoping for a single specific connection, stored as the
   * rule's session-policy `conditions`. null = the whole connection. */
  sessionPolicy: Record<string, unknown> | null;
}

export interface AppTargetFieldsProps {
  value: AppTargetState;
  onChange: (next: AppTargetState) => void;
  /** Connections available at the rule's scope, already level-filtered. */
  connections: Connection[];
  /** An org rule may choose the injection level; a project rule is fixed to
   * its own project. */
  isOrgRule: boolean;
  /** A Block injects nothing, so the Resources picker only shows on `"allow"`. */
  action: "allow" | "block";
  /** A rule's `conditions` is either behavioral or a session policy, so the
   * Resources picker hides while behavioral conditions are present. */
  hasBehavioralConditions: boolean;
  /** The provider is a cloud-only app this edition can't connect; the dead
   * sub-fields are replaced by a locked callout. */
  cloudLocked: boolean;
  showError: boolean;
  error: string | null;
}

/**
 * The App target authoring surface: pick a provider, then either specific
 * connections of it or "all connections" at a chosen level. Mirrors
 * {@link SecretTargetFields}.
 */
export const AppTargetFields = ({
  value,
  onChange,
  connections,
  isOrgRule,
  action,
  hasBehavioralConditions,
  cloudLocked,
  showError,
  error,
}: AppTargetFieldsProps) => {
  // AppSelect lists the app catalog, not existing connections: an "all
  // connections at a level" rule must be authorable for an app with none at the
  // current scope. These only feed the specific-mode checkboxes below.
  const providerConnections = connections.filter(
    (c) => c.provider === value.provider,
  );
  const singleConnection =
    value.mode === "specific" && value.connectionIds.length === 1
      ? providerConnections.find((c) => c.id === value.connectionIds[0])
      : undefined;

  const toggleConnection = (id: string, checked: boolean) => {
    const next = checked
      ? [...value.connectionIds, id]
      : value.connectionIds.filter((c) => c !== id);
    // The session policy scopes one specific connection, so any selection
    // change invalidates it.
    onChange({ ...value, connectionIds: next, sessionPolicy: null });
  };

  return (
    <div className="space-y-3">
      <div className="space-y-1.5">
        <Label htmlFor="rule-app-provider">Provider</Label>
        <AppSelect
          id="rule-app-provider"
          value={value.provider}
          // Connections, tools and session policy are all provider-specific.
          onChange={(provider) =>
            onChange({
              ...value,
              provider,
              connectionIds: [],
              tools: [],
              sessionPolicy: null,
            })
          }
          invalid={showError && !value.provider}
        />
      </div>

      {/* The sub-fields below would author a dead rule for a cloud-only app. */}
      {cloudLocked ? (
        // role="status": the callout appears dynamically when a cloud-only app
        // is picked, so it needs announcing.
        <div
          role="status"
          className="flex items-center gap-2.5 rounded-md border border-dashed px-3 py-2.5"
        >
          <TeamBadge />
          <p className="text-muted-foreground text-xs">
            {providerName(value.provider)} connections are available on{" "}
            <a
              href="https://app.onecli.sh"
              target="_blank"
              rel="noopener noreferrer"
              className="underline"
            >
              OneCLI Cloud
            </a>
            .
          </p>
        </div>
      ) : (
        <>
          <div className="space-y-1.5">
            <Label htmlFor="rule-app-mode">Connections</Label>
            <Select
              value={value.mode}
              onValueChange={(mode) =>
                onChange({
                  ...value,
                  mode: mode === "all" ? "all" : "specific",
                  // The connection context changes with the mode.
                  sessionPolicy: null,
                })
              }
            >
              <SelectTrigger id="rule-app-mode" className="w-full bg-card">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="specific">Specific connection(s)</SelectItem>
                <SelectItem value="all">All connections</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {value.mode === "specific" ? (
            <fieldset className="space-y-2 rounded-lg border bg-card p-3">
              <legend className="px-1 text-xs text-muted-foreground">
                These connections
              </legend>
              {providerConnections.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  {value.provider
                    ? "No connections for this app in this scope."
                    : "Pick an app first."}
                </p>
              ) : (
                providerConnections.map((c) => {
                  const id = `conn-${c.id}`;
                  return (
                    <div key={c.id} className="flex items-center gap-2">
                      <Checkbox
                        id={id}
                        checked={value.connectionIds.includes(c.id)}
                        onCheckedChange={(checked) =>
                          toggleConnection(c.id, checked === true)
                        }
                      />
                      <Label htmlFor={id} className="font-normal">
                        {c.label ?? c.id}
                      </Label>
                    </div>
                  );
                })
              )}
            </fieldset>
          ) : (
            <div className="space-y-1.5">
              <Label htmlFor="rule-app-level">At level</Label>
              {isOrgRule ? (
                <Select
                  value={value.level}
                  onValueChange={(level) =>
                    onChange({
                      ...value,
                      level:
                        level === "organization" ? "organization" : "project",
                    })
                  }
                >
                  <SelectTrigger id="rule-app-level" className="w-full bg-card">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="organization">
                      Organization connections
                    </SelectItem>
                    <SelectItem value="project">
                      Project connections (each project uses its own)
                    </SelectItem>
                  </SelectContent>
                </Select>
              ) : (
                <p className="text-xs text-muted-foreground">
                  All of this project&apos;s {value.provider || "app"}{" "}
                  connections.
                </p>
              )}
            </div>
          )}

          {singleConnection &&
            action === "allow" &&
            !hasBehavioralConditions && (
              <ResourceScopeFields
                connection={singleConnection}
                policy={value.sessionPolicy}
                onChange={(sessionPolicy) =>
                  onChange({ ...value, sessionPolicy })
                }
              />
            )}

          {value.provider && (
            <div className="space-y-1.5">
              <Label htmlFor="rule-app-tools">Tools</Label>
              <AppToolsPicker
                id="rule-app-tools"
                provider={value.provider}
                value={value.tools}
                onChange={(tools) => onChange({ ...value, tools })}
              />
              <p className="text-xs text-muted-foreground">
                Empty covers the whole app; narrow to specific tools to limit
                which operations this rule matches.
              </p>
            </div>
          )}
        </>
      )}

      {showError && error && (
        <p className={cn("text-xs text-destructive")} role="alert">
          {error}
        </p>
      )}
    </div>
  );
};
