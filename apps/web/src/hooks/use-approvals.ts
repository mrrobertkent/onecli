"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { usePathname } from "next/navigation";
import { toast } from "sonner";
import {
  decide,
  listPending,
  type ApprovalDecisionInput,
  type PendingApproval,
} from "@/lib/api/approvals";
import { queryKeys } from "@/lib/api/keys";
import { hasProjectContext } from "@/lib/navigation";

/**
 * Live list of pending approvals for the active project.
 *
 * The gateway long-polls `GET /v1/approvals/pending`, holding ~30s while idle,
 * so `refetchInterval` re-issues shortly after each request settles. Runs only
 * where a project context exists, and pauses in background tabs.
 */
export const usePendingApprovals = () => {
  const pathname = usePathname();

  return useQuery({
    queryKey: queryKeys.approvals.list(),
    queryFn: ({ signal }) =>
      listPending({
        signal: AbortSignal.any([signal, AbortSignal.timeout(35_000)]),
      }),
    enabled: hasProjectContext(pathname),
    // An empty list is a real long-poll, so 1s is cheap. A non-empty one
    // returns immediately, so back off to 5s rather than busy-poll. Errors back
    // off to 30s — `initialData` keeps `data` defined, so without the status
    // check a dead gateway would be hammered on the 1s branch forever.
    refetchInterval: (query) =>
      query.state.status === "error"
        ? 30_000
        : query.state.data?.length
          ? 5_000
          : 1_000,
    refetchIntervalInBackground: false,
    staleTime: 0,
    // Seed empty so the popover shows its empty state instantly rather than a
    // skeleton during the gateway's idle long-poll hold.
    initialData: [],
  });
};

/**
 * Approve or deny a held request. Optimistically removes the item from the
 * pending list, rolls back on error, and refreshes activity + counts on settle.
 * No gateway-cache invalidation — a decision releases a held request, it does
 * not change gateway config (rules/secrets).
 */
export const useDecideApproval = () => {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: ({
      id,
      decision,
    }: {
      id: string;
      decision: ApprovalDecisionInput;
    }) => decide(id, decision),
    onMutate: async ({ id }) => {
      await qc.cancelQueries({ queryKey: queryKeys.approvals.all() });
      const previous = qc.getQueryData<PendingApproval[]>(
        queryKeys.approvals.list(),
      );
      qc.setQueryData<PendingApproval[]>(queryKeys.approvals.list(), (old) =>
        old?.filter((a) => a.id !== id),
      );
      return { previous };
    },
    onError: (_err, _vars, ctx) => {
      if (ctx?.previous) {
        qc.setQueryData(queryKeys.approvals.list(), ctx.previous);
      }
      toast.error("Failed to submit decision");
    },
    onSuccess: (_data, { decision }) => {
      toast.success(
        decision === "approve" ? "Request approved" : "Request rejected",
      );
    },
    onSettled: () => {
      // Only the pending list is a React Query resource; the Activity screen
      // refreshes via its own polling, and sidebar counts are unaffected.
      qc.invalidateQueries({ queryKey: queryKeys.approvals.all() });
    },
  });
};
