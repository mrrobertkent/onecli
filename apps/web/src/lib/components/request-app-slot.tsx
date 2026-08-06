import { Plus } from "lucide-react";

/**
 * OSS default "Request an app" slot, linking to the repo's issue form. Cloud
 * aliases this module to an in-app request dialog.
 *
 * Both variants accept optional controlled props so the parent can open the
 * dialog programmatically; OSS ignores them.
 */

export interface RequestAppSlotProps {
  requestOpen?: boolean;
  onRequestOpenChange?: (open: boolean) => void;
  initialName?: string;
  initialUrl?: string;
}

const ISSUE_BODY_TEMPLATE = `**Website:**

**How you'd use this with OneCLI:**
`;

const GITHUB_ISSUE_URL = `https://github.com/onecli/onecli/issues/new?${new URLSearchParams(
  {
    labels: "app request",
    title: "App request: ",
    body: ISSUE_BODY_TEMPLATE,
  },
).toString()}`;

export const RequestAppSlot = ({}: RequestAppSlotProps = {}) => (
  <a
    href={GITHUB_ISSUE_URL}
    target="_blank"
    rel="noopener noreferrer"
    className="group flex items-center justify-between rounded-xl border border-dashed border-muted-foreground/40 bg-card/40 px-4 py-3 transition-colors cursor-pointer hover:bg-accent/50 hover:border-solid"
  >
    <div className="flex items-center gap-3">
      <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-muted">
        <Plus className="size-4 text-muted-foreground transition-colors group-hover:text-foreground" />
      </div>
      <div className="flex flex-col">
        <span className="text-sm font-medium">Request an app</span>
        <span className="text-muted-foreground text-xs">
          Open an issue on GitHub
        </span>
      </div>
    </div>
  </a>
);
