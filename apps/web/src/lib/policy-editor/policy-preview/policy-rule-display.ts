import type { LucideIcon } from "lucide-react";
import { KeyRound, ShieldBan, ShieldCheck } from "lucide-react";
import type {
  PolicyRuleSource,
  PolicyRuleTarget,
  ProjectionIdentity,
} from "@/lib/api";

// Pure render helpers shared by the read-only preview and the editable policy
// console. A rule's action is allow|block, with rate-limit and approval as
// modifiers.

/**
 * The minimal rule shape these helpers read, satisfied by `PolicyRuleV2` so the
 * console table and drawer share one vocabulary without casts.
 */
export interface PolicyRuleView {
  name: string;
  /** Absent on the read-only preview rows, which have no derived sources. */
  source?: PolicyRuleSource;
  isDefault: boolean;
  priority: number;
  identities: ProjectionIdentity[];
  targets: PolicyRuleTarget[];
  action: "allow" | "block";
  requireApproval: boolean;
  rateLimit: number | null;
  rateLimitWindow: "minute" | "hour" | "day" | null;
}

const WINDOW_SHORT: Record<string, string> = {
  minute: "min",
  hour: "hr",
  day: "day",
};

export interface ActionMeta {
  Icon: LucideIcon;
  label: string;
  className: string;
}

/** The primary verdict; modifiers render as separate chips.
 *
 * An `equipment` rule is injection-only and never permits anything, so it gets
 * its own verdict rather than the shared green "Allow". */
export const actionMeta = (
  rule: Pick<PolicyRuleView, "action"> & { source?: PolicyRuleSource },
): ActionMeta =>
  rule.source === "equipment"
    ? {
        Icon: KeyRound,
        label: "Attaches credential",
        className: "text-muted-foreground",
      }
    : rule.action === "block"
      ? { Icon: ShieldBan, label: "Block", className: "text-destructive" }
      : {
          Icon: ShieldCheck,
          label: "Allow",
          className: "text-emerald-700 dark:text-emerald-400",
        };

/** Short "100/min"-style label for a rate-limit modifier, or null. */
export const rateLimitLabel = (
  rule: Pick<PolicyRuleView, "rateLimit" | "rateLimitWindow">,
): string | null => {
  if (rule.rateLimit == null) return null;
  const window = rule.rateLimitWindow;
  return window
    ? `${rule.rateLimit}/${WINDOW_SHORT[window] ?? window}`
    : `${rule.rateLimit}`;
};

/** Plain-text identities, used for the filter query + accessible labels. */
export const identityText = (
  rule: Pick<PolicyRuleView, "identities">,
  identityName: (id: string) => string,
): string =>
  rule.identities.length === 0
    ? "All agents"
    : rule.identities.map((i) => identityName(i.id)).join(", ");

/** Plain-text target, used for the filter query + the chip label. */
export const targetText = (target: PolicyRuleTarget): string => {
  switch (target.kind) {
    case "network": {
      const method = target.method ? `${target.method} ` : "";
      return `${method}${target.hostPattern}${target.pathPattern ?? ""}`;
    }
    case "app": {
      // No tools = the whole app, never "0 tools", which would read as
      // matching nothing.
      const n = target.tools.length;
      if (target.connectionScope) {
        const level =
          target.connectionScope === "organization" ? "org" : "project";
        // Tools narrow which endpoints match; empty = all connections' traffic.
        if (n === 0) return `${target.provider} · all connections (${level})`;
        return `${target.provider} · ${n} tool${n === 1 ? "" : "s"} (${level})`;
      }
      if (n === 0) return `${target.provider} · whole app`;
      return `${target.provider} · ${n} tool${n === 1 ? "" : "s"}`;
    }
    case "connection": {
      // A specific connection injects itself and matches its provider's app,
      // narrowed to `tools` when set.
      const n = target.tools.length;
      if (n === 0) return "Connection";
      return `Connection · ${n} tool${n === 1 ? "" : "s"}`;
    }
    case "secret":
      // "All secrets at a level" vs a specific secret.
      if (target.secretScope) {
        const level = target.secretScope === "organization" ? "org" : "project";
        return `All secrets (${level})`;
      }
      return "Secret";
  }
};
