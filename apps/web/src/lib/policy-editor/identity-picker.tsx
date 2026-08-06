"use client";

import type { ProjectionIdentity } from "@/lib/api";

/**
 * The OSS identity-picker seam. Directory identities are a OneCLI Cloud
 * capability and OSS mounts no org policy console, so this stub never renders;
 * it exists to keep the shared rule form compiling in an OSS build.
 */

export interface OrgIdentityPickerProps {
  value: ProjectionIdentity[];
  onChange: (next: ProjectionIdentity[]) => void;
  /** Id for the trigger, so a field <Label htmlFor> associates with the picker. */
  id?: string;
}

export const OrgIdentityPicker: (props: OrgIdentityPickerProps) => null = () =>
  null;
