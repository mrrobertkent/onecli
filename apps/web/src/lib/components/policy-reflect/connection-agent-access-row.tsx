"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Ban,
  Bot,
  CircleCheck,
  CircleMinus,
  Hand,
  Settings2,
} from "lucide-react";
import { Button } from "@onecli/ui/components/button";
import { Switch } from "@onecli/ui/components/switch";
import { cn } from "@onecli/ui/lib/utils";
import type {
  AgentAccessStatus,
  EffectiveAgentEntry,
} from "@/lib/api/policy-visibility";
import {
  useDetachConnectionForAgent,
  useSetConnectionGrantForAgent,
} from "@/hooks/use-grants";
import { agentPath } from "@/lib/navigation";

// One agent row of the connection "Agent access" dialog, mirroring the agent
// page's row states: project-granted (detachable), org-granted (locked on),
// unattached (attachable).
//
// The row carries at most one status element, and only when it says something
// the switch cannot: a block, a narrowed tool count, an approval gate, or a
// catalog-less app.

const ACCESS_META = {
  usable: {
    label: "Can use",
    icon: CircleCheck,
    className:
      "bg-emerald-50 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-400",
  },
  limited: {
    label: "Limited",
    icon: CircleMinus,
    className:
      "bg-amber-50 text-amber-700 dark:bg-amber-950/50 dark:text-amber-400",
  },
  blocked: {
    label: "Blocked",
    icon: Ban,
    className: "bg-red-50 text-red-700 dark:bg-red-950/50 dark:text-red-400",
  },
  none: {
    label: "No access",
    className: "bg-muted text-muted-foreground",
  },
  unknown: {
    // Attached, but a custom app with no catalog — access is via network rules.
    label: "Network only",
    className: "bg-muted text-muted-foreground",
  },
} as const satisfies Record<
  AgentAccessStatus,
  { label: string; className: string; icon?: typeof CircleCheck }
>;

const AccessPill = ({ access }: { access: AgentAccessStatus }) => {
  const meta = ACCESS_META[access];
  const Icon = "icon" in meta ? meta.icon : undefined;
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium whitespace-nowrap",
        meta.className,
      )}
    >
      {Icon && <Icon className="size-3.5" aria-hidden="true" />}
      {meta.label}
    </span>
  );
};

/**
 * The secondary line under the agent name, for provenance the switch cannot
 * express. An ordinary project grant says nothing: its compiled rule name is an
 * internal identifier, so naming it here would be noise and a leak.
 */
const attachDetail = (orgGranted: boolean): string | null =>
  orgGranted ? "Via organization" : null;

interface ConnectionAgentAccessRowProps {
  connectionId: string;
  agent: EffectiveAgentEntry;
  /** agentId ∈ the connection's project grants (the grants API view). */
  projectGranted: boolean;
}

export const ConnectionAgentAccessRow = ({
  connectionId,
  agent,
  projectGranted,
}: ConnectionAgentAccessRowProps) => {
  const pathname = usePathname();
  const attach = useSetConnectionGrantForAgent();
  const detach = useDetachConnectionForAgent();
  const busy = attach.isPending || detach.isPending;

  // Injected by an org rule, so locked on and not detachable at project level.
  const orgGranted =
    !projectGranted &&
    agent.credential.status === "viaRule" &&
    agent.credential.provenance.some((p) => p.scope === "organization");

  const detail = attachDetail(orgGranted);

  // The one status element, first match wins. A block outranks a count, a
  // count outranks an approval note, and a working attachment says nothing.
  const decisions = agent.credential.status !== "none" ? agent.decisions : null;
  const narrowed =
    decisions !== null && decisions.allowedTools < decisions.totalTools;
  const status: "pill" | "count" | "approval" | null =
    agent.access === "blocked" || agent.access === "unknown"
      ? "pill"
      : narrowed
        ? "count"
        : decisions?.anyApproval
          ? "approval"
          : null;

  const manageHref = `${agentPath(pathname, agent.agentId)}?tab=apps&connection=${connectionId}&manage=1`;

  return (
    <div className="flex items-center justify-between gap-3 py-2.5">
      <span className="flex min-w-0 items-center gap-2.5">
        <span className="bg-muted flex size-6 shrink-0 items-center justify-center rounded-md">
          <Bot className="text-muted-foreground size-3.5" aria-hidden="true" />
        </span>
        <span className="min-w-0">
          <span className="block truncate text-sm">{agent.name}</span>
          {detail && (
            <span className="text-muted-foreground block truncate text-[11px]">
              {detail}
            </span>
          )}
        </span>
      </span>
      <span className="flex shrink-0 items-center gap-1.5">
        {status === "pill" && <AccessPill access={agent.access} />}
        {status === "count" && (
          <span className="text-muted-foreground inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[11px] tabular-nums">
            {decisions?.allowedTools} of {decisions?.totalTools}
            {decisions?.anyApproval && (
              <>
                <Hand className="size-3" aria-hidden="true" />
                <span className="sr-only">, some need approval</span>
              </>
            )}
            <span className="sr-only"> tools allowed</span>
          </span>
        )}
        {status === "approval" && (
          <span className="inline-flex shrink-0 items-center gap-1 rounded-md bg-blue-50 px-1.5 py-0.5 text-xs font-medium whitespace-nowrap text-blue-700 dark:bg-blue-950/50 dark:text-blue-400">
            <Hand className="size-3.5" aria-hidden="true" />
            Needs approval
          </span>
        )}
        {/* Below `sm` the dialog is only viewport-2rem wide, and this row's
            controls do not shrink — so the label collapses to its icon rather
            than widening the dialog's grid column and pushing the switch out
            of reach. The accessible name survives on the link either way. */}
        <Button variant="ghost" size="xs" asChild>
          <Link href={manageHref} aria-label={`Manage ${agent.name}'s access`}>
            <Settings2 className="size-3.5" />
            <span className="hidden sm:inline">Manage</span>
          </Link>
        </Button>
        <Switch
          size="sm"
          checked={projectGranted || orgGranted}
          disabled={busy || orgGranted}
          aria-label={`${projectGranted || orgGranted ? "Detach" : "Attach"} ${agent.name}`}
          onCheckedChange={(next) => {
            if (next) {
              attach.mutate({
                connectionId,
                agentId: agent.agentId,
                input: { access: "full" },
              });
            } else {
              detach.mutate({ connectionId, agentId: agent.agentId });
            }
          }}
        />
      </span>
    </div>
  );
};
