# OneCLI

Cloud backend for OneCLI — manages authentication, integrations, and permissions for the OneCLI agent gateway.

## Commands

```bash
pnpm dev          # Start development
pnpm build        # Build all
pnpm check        # Lint + types + format
pnpm fix          # Auto-fix lint + format
pnpm db:generate  # Generate Prisma client
pnpm db:migrate   # Run migrations (dev)
pnpm db:studio    # Open Prisma Studio
```

## Structure

```
apps/web/         # Next.js 16 app (App Router)
packages/db/      # Prisma ORM + migrations
packages/infra/   # AWS CDK infrastructure
packages/ui/      # Shared components (shadcn/ui)
packages/eslint-config/
packages/typescript-config/
```

## Environment Variables

- `DATABASE_URL`: PostgreSQL connection string
- `AUTH_SECRET`, `APP_URL`: Better Auth signing key and origin
- `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`: generic OIDC login provider
- `BOOTSTRAP_ADMIN_*`: seeds the first administrator; `_FILE` variants supported
- `STRIPE_SECRET_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`: Third-party credentials

## Code Style

- **Use strong typing** - leverage types from external packages; avoid `any` and type assertions
- Prefer named exports over default exports (except Next.js pages/layouts where required)
- Use `@onecli/ui/*` for shared UI imports, `@/` for app-local imports
- Use `cn()` for class merging
- Mark client components with `"use client"`
- Prefer Tailwind utilities over custom CSS
- Use const arrow functions, not function declarations (for components and utilities)

## Component Structure

- **One component per file** - never put multiple components in the same file (includes page.tsx)
- **Page-specific components** - create `_components/` subdirectory in the route folder:
  ```
  app/(dashboard)/overview/
  ├── page.tsx
  └── _components/
      ├── overview-header.tsx
      └── recent-activity.tsx
  ```
- **Props typing** - use base types directly, only create named interface when adding custom props:

  ```tsx
  // ✓ No custom props - use base type directly
  export const Card = ({ className, children, ...props }: React.ComponentProps<"div">) => { ... };

  // ✓ Custom props - create interface
  export interface ServiceCardProps extends React.ComponentProps<"div"> {
    connected?: boolean;
  }
  ```

- **Multi-component features**: Create a directory with an `index.ts` barrel export

## IMPORTANT: shadcn/ui Components

Components in `packages/ui/src/components/` are from shadcn/ui.

**Allowed:**

- Adding new variants/sizes to CVA definitions
- Customizing via `className` when using components
- Wrapping in your own component

**NOT Allowed:**

- Changing existing variant styles
- Modifying component structure or logic
- Removing existing functionality

When adding components, use shadcn CLI or copy from ui.shadcn.com.

## Dependencies

- Use Radix UI only through shadcn/ui, never import directly
- Check shadcn for components before adding dependencies
- Keep bundle size small - prefer lightweight alternatives

## Web App Patterns

- Server components by default, add `"use client"` only when needed
- Pages export `default function` (async for data fetching)
- Auth: Better Auth (React context in `providers/`; instance in `lib/auth/better-auth-config.ts`)
- Server-side auth: `getServerSession()` from `lib/auth/server.ts`
- Validation: Zod for API inputs
- **Button loading states** - replace icon with spinner, update text (e.g., "Connecting..."), and disable
- **Verify library APIs are current** - check official docs for deprecated/legacy patterns before implementing

## Audit Logging

All state-changing operations (create, update, delete, regenerate) must be audited. Use the `withAudit` wrapper from `@/lib/services/audit-service`.

**Pattern:**

```typescript
import {
  withAudit,
  AUDIT_ACTIONS,
  AUDIT_SERVICES,
} from "@/lib/services/audit-service";

export const createAgent = async (name: string) => {
  const { userId, accountId } = await resolveUser();
  return withAudit(
    () => createAgentService(accountId, name),
    (agent) => ({
      accountId,
      userId,
      action: AUDIT_ACTIONS.CREATE,
      service: AUDIT_SERVICES.AGENT,
      metadata: { agentId: agent.id, name },
    }),
  );
};
```

**Available constants:**

- `AUDIT_ACTIONS`: `CREATE`, `UPDATE`, `DELETE`, `REGENERATE`
- `AUDIT_SERVICES`: `AGENT`, `SECRET`, `RULE`, `API_KEY`

**Metadata guidelines:**

- Include resource IDs (agentId, secretId, ruleId)
- Include relevant identifiers (name, type)
- Never include sensitive values (tokens, secrets, passwords)

**When to audit:**

- Actions layer (`lib/actions/`) - always use `withAudit`
- API routes (`app/api/`) - call audit service directly with `source: AUDIT_SOURCE.API` (when implemented)
- Read operations - do not audit

## Database (Prisma)

- Schema at `packages/db/prisma/schema.prisma`
- Always run `pnpm db:generate` after schema changes
- Migrations run automatically on container startup via `entrypoint.sh`

## Infrastructure & Deployment

- Environment passed via CDK context: `--context env=dev|prod`
- **IMPORTANT: Never modify AWS resources directly** — all changes go through CDK stacks and GitHub Actions workflows
- Both deploy workflows (`deploy-app.yml`, `deploy-infra.yml`) are manual with environment choice (dev/prod)
- **This fork deploys to one self-hosted host.** `DEPLOYMENT.md` holds its state and required
  environment. **Deploying is the operator's action, never an agent's** — build the image, ship it
  to the host, and stop.

## Auth and access control

Spec in `specs/auth-and-access-control/`: `tasks.md` for what is left, `design.md` for the
decisions, `requirements.md` for acceptance criteria, `research.md` for facts already verified.

`single-org-shared` tenancy needs `rbac: true`, a registered `RoleResolver` **and** role-resolved
membership creation — all together, or it is a privilege-escalation hole.

Traps that have each cost a debugging session:

- **A password account has no `id_token`.** `readIdpGroups` returns `null` for "no directory
  identity" and `[]` for "the directory grants nothing"; only `[]` revokes. Collapse the two and
  the bootstrap administrator is suspended at their next login.
- **The directory never suspends an `owner`**, or anyone who can edit an Authentik group takes the
  instance.
- **`instance_settings` is a singleton.** Suites reset only the column they own, restore any
  deliberately invalid value they park there, and a fixture that creates an administrator also
  removes the org API key it mints.
- **The gateway's proof tests run concurrently** against the one database — cargo has no
  serial-file equivalent, so each owns a row prefix. The TypeScript packages run serially.
- **The org API key's owner is undeletable** (`ApiKey.user` is `ON DELETE RESTRICT`), so it is
  minted with the administrator rather than at boot.
- **Authentik's built-in `email` mapping hardcodes `email_verified: False`**, so Better Auth
  refuses to link an SSO identity onto an existing row. Fixed with
  `accountLinking.trustedProviders`, never by editing the mapping — it is blueprint-managed and
  reverts whenever blueprints are applied.
- **Recovery stays exempt from `proxy.ts`'s configuration gate.** It is the way back into an
  instance whose configuration is the problem.

## Proving changes

Database behaviour is proven against real PostgreSQL, not mocks — `*.pg.test.ts` across
`apps/web` and `packages/api`, plus `access_proof_tests` in `apps/gateway/src/db.rs`.

```bash
pnpm db:up
POLICY_PROOF_DATABASE_URL="postgresql://onecli:onecli@127.0.0.1:5432/onecli" pnpm test
```

Skips without the variable locally, throws in CI.

- **Run every new suite against the unfixed code and confirm it fails.** One that passes either
  way proves nothing.
- **A green database is not a working feature.** Anything spanning a server action and the client
  is checked in the browser: a session can be real while the client never learns of it, and a
  guard can hold at the API while the control it governs is unreachable in the UI.

## Working standards

- **Comments and docs carry current state, not history.** Comments say what the code does not, in
  one to four lines — no spec identifiers, no bug history, no library tutorials, no rationale
  essays. Docs carry what is true now and what to do next: no superseded entries, no changelog, no
  status that goes stale. Git commits hold the reasoning and the history.
- **Grade options on security, manageability, UX and viability** — never effort, wall-clock, or
  distance from upstream.
- **Requests are pressure tests.** Push back with reasoning; say so if the framing is wrong.
- **Do not defer.** One release, no live user, no data to protect.
- Verify "comments only" edits with the TypeScript parser — strip comments from both revisions and
  compare, rather than matching comment markers line by line.

## Local environment

- `pnpm` via corepack. `cargo` is symlinked into `~/.local/bin` so non-interactive shells find it;
  `pnpm check` and `pnpm test` both run cargo tasks.
- The Rust LSP has no project model here — rust-analyzer's root has no `Cargo.toml`, only
  `apps/gateway/` does. Use `cargo clippy -- -D warnings` and `cargo test`.
- The Prisma MCP cannot run against 6.19; use `pnpm exec prisma`.
- The gateway's cloud edition does not compile in this tree. OSS only.
