import { GitBranch } from "lucide-react";
import type { GranularAccessConfig } from "../types";

export const githubAppConfig: GranularAccessConfig = {
  // Scopable whenever the installation grants all repositories (whose concrete
  // `repos` list may be empty or unenumerated) or already lists specific ones.
  // A connection with neither signal is un-scopable and stays hidden.
  isSupported: (meta) =>
    meta.repositorySelection === "all" ||
    (Array.isArray(meta.repos) && meta.repos.length > 0),
  getItems: (meta) =>
    ((meta.repos as string[]) ?? []).map((repo) => ({
      id: repo,
      label: repo.split("/").pop() ?? repo,
    })),
  buildPolicy: (repos) => (repos.length > 0 ? { repositories: repos } : {}),
  getSelectedItems: (policy) => (policy.repositories as string[]) ?? [],
  itemLabel: { singular: "repository", plural: "repositories" },
  Icon: GitBranch,
};
