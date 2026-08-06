"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { grants } from "@/lib/api";
import type { ConnectionGrantInput } from "@/lib/api";
import { queryKeys } from "@/lib/api/keys";

// Grants routes flush the gateway cache and publish atomically server-side, so
// there is no client-side flush or afterPolicyWrite chaining here.

export const useAgentGrants = (agentId: string, enabled = true) =>
  useQuery({
    queryKey: queryKeys.grants.agent(agentId),
    queryFn: () => grants.forAgent(agentId),
    enabled: enabled && agentId.length > 0,
  });

export const useConnectionGrants = (connectionId: string, enabled = true) =>
  useQuery({
    queryKey: queryKeys.grants.connection(connectionId),
    queryFn: () => grants.forConnection(connectionId),
    enabled: enabled && connectionId.length > 0,
  });

/** The agents-list chips feed, keyed under the agents namespace so agent CRUD
 * invalidation reaches it. */
export const useGrantsSummary = () =>
  useQuery({
    queryKey: [...queryKeys.agents.all(), "grants-summary"],
    queryFn: grants.summary,
  });

const useInvalidateGrants = () => {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: queryKeys.grants.all() });
    // A grant is a policy write, and the reflections key under these shared
    // namespaces. A stale effective verdict reads as a security answer.
    void qc.invalidateQueries({ queryKey: queryKeys.policy.all() });
    void qc.invalidateQueries({ queryKey: queryKeys.agents.all() });
    void qc.invalidateQueries({ queryKey: queryKeys.connections.all() });
  };
};

export const useSetConnectionGrant = () => {
  const invalidate = useInvalidateGrants();
  return useMutation({
    mutationFn: ({
      agentId,
      connectionId,
      input,
    }: {
      agentId: string;
      connectionId: string;
      input: ConnectionGrantInput;
    }) => grants.setConnectionGrant(agentId, connectionId, input),
    onSuccess: () => invalidate(),
    onError: (err: Error) => toast.error(err.message),
  });
};

export const useDetachConnection = () => {
  const invalidate = useInvalidateGrants();
  return useMutation({
    mutationFn: ({
      agentId,
      connectionId,
    }: {
      agentId: string;
      connectionId: string;
    }) => grants.detachConnection(agentId, connectionId),
    onSuccess: () => {
      invalidate();
      toast.success("Access removed");
    },
    onError: (err: Error) => toast.error(err.message),
  });
};

export const useAttachSecret = () => {
  const invalidate = useInvalidateGrants();
  return useMutation({
    mutationFn: ({
      agentId,
      secretId,
    }: {
      agentId: string;
      secretId: string;
    }) => grants.attachSecret(agentId, secretId),
    onSuccess: () => invalidate(),
    onError: (err: Error) => toast.error(err.message),
  });
};

export const useDetachSecret = () => {
  const invalidate = useInvalidateGrants();
  return useMutation({
    mutationFn: ({
      agentId,
      secretId,
    }: {
      agentId: string;
      secretId: string;
    }) => grants.detachSecret(agentId, secretId),
    onSuccess: () => {
      invalidate();
      toast.success("Access removed");
    },
    onError: (err: Error) => toast.error(err.message),
  });
};

/** The connection-dialog twins. */
export const useSetConnectionGrantForAgent = () => {
  const invalidate = useInvalidateGrants();
  return useMutation({
    mutationFn: ({
      connectionId,
      agentId,
      input,
    }: {
      connectionId: string;
      agentId: string;
      input: ConnectionGrantInput;
    }) => grants.setForConnection(connectionId, agentId, input),
    onSuccess: () => invalidate(),
    onError: (err: Error) => toast.error(err.message),
  });
};

export const useDetachConnectionForAgent = () => {
  const invalidate = useInvalidateGrants();
  return useMutation({
    mutationFn: ({
      connectionId,
      agentId,
    }: {
      connectionId: string;
      agentId: string;
    }) => grants.detachForConnection(connectionId, agentId),
    onSuccess: () => {
      invalidate();
      toast.success("Access removed");
    },
    onError: (err: Error) => toast.error(err.message),
  });
};
