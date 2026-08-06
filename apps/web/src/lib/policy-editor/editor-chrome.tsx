"use client";

import type { PolicyDiff } from "@onecli/api/lib/policy-diff";
import type { PageScope } from "@/lib/api";

/**
 * The OSS editor chrome, empty by design. Staged publish, org guardrails and
 * directory name resolution are OneCLI Cloud capabilities; OSS's editor is
 * immediate-apply and project-scoped.
 */

const NO_DIRECTORY = (): undefined => undefined;

export const useDirectoryNames = (): ((id: string) => string | undefined) =>
  NO_DIRECTORY;

export interface StagedActionsProps {
  scope: PageScope;
  policyDiff: PolicyDiff | null;
}

export const StagedActions: (props: StagedActionsProps) => null = () => null;

export const StagedMeta: (props: { scope: PageScope }) => null = () => null;

/** OSS has no organization level, so the evaluation explainer describes the
 * single project list only. */
export const ORG_GUARDRAILS_AVAILABLE = false;
