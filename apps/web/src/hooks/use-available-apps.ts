"use client";

import { useQuery } from "@tanstack/react-query";
import { appAvailability } from "@/lib/api";
import type { PageScope } from "@/lib/api";
import { queryKeys } from "@/lib/api/keys";

// Backs the connect-picker filter. Availability is a per-project provisioning
// gate, so the org connect surface is never filtered. The response's
// `restricted` flag is the real gate: an open org returns false and the picker
// stays unfiltered.
export const useAvailableApps = (scope: PageScope) =>
  useQuery({
    queryKey: queryKeys.appAvailability.available(),
    queryFn: appAvailability.available,
    // A failed/absent availability read must never hide apps — degrade to
    // "unrestricted" rather than an empty picker.
    retry: false,
    enabled: scope === "project",
  });
