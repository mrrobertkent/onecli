"use client";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@onecli/ui/components/dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@onecli/ui/components/tooltip";
import { StatusBadge } from "./status-badge";
import { MethodBadge } from "./method-badge";
import { ProviderIcon } from "./provider-icon";
import { hasJsonData } from "@onecli/api/lib/format";
import {
  isBlockedRequest,
  isDefaultDenied,
  isOwnKey,
  isRateLimitedRequest,
  getBlockedByRule,
  getConnectionLabel,
  getMatchedRuleName,
  getMatchedRuleScope,
  type RequestLogEntry,
} from "@onecli/api/services/request-log-service";

interface ActivityDetailDialogProps {
  log: RequestLogEntry | null;
  onClose: () => void;
}

const Row = ({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) => (
  <div className="flex items-center justify-between py-2 border-b border-border/50 last:border-b-0">
    <span className="text-muted-foreground text-sm">{label}</span>
    <div className="text-sm">{children}</div>
  </div>
);

export const ActivityDetailDialog = ({
  log,
  onClose,
}: ActivityDetailDialogProps) => {
  const blocked = log ? isBlockedRequest(log) : false;
  const defaultDenied = log ? isDefaultDenied(log) : false;
  const rateLimited = log ? isRateLimitedRequest(log) : false;
  const blockedByRule = log ? getBlockedByRule(log) : null;
  const matchedRuleName = log ? getMatchedRuleName(log) : null;
  const matchedRuleScope = log ? getMatchedRuleScope(log) : null;
  const connectionLabel = log ? getConnectionLabel(log) : null;
  // Rule attributions below are plain text: a project member cannot edit the
  // rule, so there is nowhere useful to link.

  return (
    <Dialog open={!!log} onOpenChange={() => onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Request Details</DialogTitle>
        </DialogHeader>
        {log && (
          <div>
            <Row label="Method">
              <MethodBadge method={log.method} />
            </Row>
            <Row label="Host">
              <span className="font-medium">{log.host}</span>
            </Row>
            <Row label="Path">
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="max-w-[280px] truncate font-mono text-xs block text-right cursor-default">
                    {log.path || "/"}
                  </span>
                </TooltipTrigger>
                <TooltipContent
                  side="bottom"
                  className="max-w-sm break-all font-mono text-xs"
                >
                  {log.path || "/"}
                </TooltipContent>
              </Tooltip>
            </Row>
            <Row label="Provider">
              <div className="flex items-center gap-1.5">
                <ProviderIcon provider={log.provider} size={14} />
                <span>{log.provider}</span>
              </div>
            </Row>
            {connectionLabel && (
              <Row label="Account">
                <span>{connectionLabel}</span>
              </Row>
            )}
            {isOwnKey(log) && (
              <Row label="Credentials">
                <span className="text-muted-foreground">
                  Agent&apos;s own key
                </span>
              </Row>
            )}
            <Row label="Status">
              <StatusBadge
                status={log.status}
                blocked={blocked}
                defaultDenied={defaultDenied}
                rateLimited={rateLimited}
              />
            </Row>
            {defaultDenied && (
              <Row label="Reason">
                <span className="text-destructive">No matching allow rule</span>
              </Row>
            )}
            {(blocked || rateLimited) && blockedByRule && (
              <Row label={rateLimited ? "Limited by" : "Blocked by"}>
                <span className="text-destructive">{blockedByRule}</span>
              </Row>
            )}
            {matchedRuleName && !blockedByRule && !defaultDenied && (
              // Attribution for decisions no other row already names: allowed
              // and approval requests. Blocked and rate-limited rows show
              // "Blocked/Limited by"; default-denied rows show "Reason".
              <Row label="Decided by rule">
                <span>{matchedRuleName}</span>
              </Row>
            )}
            {!matchedRuleName &&
              matchedRuleScope === "organization" &&
              !blockedByRule &&
              !defaultDenied && (
                // An org rule decided, but the server redacts its name for
                // anyone who is not an org admin.
                <Row label="Decided by rule">
                  <span className="text-muted-foreground">
                    An organization rule
                  </span>
                </Row>
              )}
            <Row label="Latency">
              <span className="font-mono text-xs tabular-nums">
                {log.latencyMs}ms
              </span>
            </Row>
            <Row label="Agent">
              <span>{log.agentName ?? log.agentId}</span>
            </Row>
            {log.approvedBy && (
              <Row label="Decided by">
                <span>{log.approvedBy}</span>
              </Row>
            )}
            <Row label="Time">
              <span className="text-xs tabular-nums">
                {new Date(log.createdAt).toLocaleString()}
              </span>
            </Row>
            {hasJsonData(log.extraData) && !blockedByRule && (
              <div className="mt-3 space-y-1.5">
                <span className="text-muted-foreground text-xs font-medium">
                  Extra Data
                </span>
                <pre className="bg-muted overflow-x-auto rounded-md p-3 text-xs">
                  {JSON.stringify(log.extraData, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
};
