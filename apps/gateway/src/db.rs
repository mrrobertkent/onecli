//! Direct database access via SQLx.
//!
//! Used when `DATABASE_URL` is set to query the PostgreSQL database directly,
//! bypassing the Next.js API. Vault connection state is managed by the gateway;
//! all other tables are read-only (Prisma / Next.js remains the writer).

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::{types::Json, FromRow, PgPool};

/// Create a PostgreSQL connection pool from `DATABASE_URL`.
pub(crate) async fn create_pool(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .context("connecting to PostgreSQL")
}

// ── Row types ───────────────────────────────────────────────────────────

/// An agent row from the `agents` table.
#[derive(Debug, FromRow)]
pub(crate) struct AgentRow {
    pub id: String,
    pub name: String,
    pub identifier: Option<String>,
    pub project_id: String,
    pub organization_id: String,
    pub subscription_status: String,
}

/// A secret row from the `secrets` table.
#[derive(Debug, FromRow)]
pub(crate) struct SecretRow {
    pub id: String,
    /// "project" | "organization" | "partner" — the secret's own scope, not how
    /// it was resolved. Read only by the cloud budget module.
    #[cfg_attr(not(edition_cloud), allow(dead_code))]
    pub scope: String,
    #[sqlx(rename = "type")]
    pub type_: String,
    /// "inline" (value stored in `encrypted_value`) | "onepassword" (value
    /// resolved from `op_ref` via the 1Password connection at request time).
    pub value_source: String,
    /// Present for inline secrets; `None` for 1Password-sourced ones.
    pub encrypted_value: Option<String>,
    /// `op://vault/item/field` reference, set for 1Password-sourced secrets.
    pub op_ref: Option<String>,
    pub host_pattern: String,
    pub path_pattern: Option<String>,
    pub injection_config: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
}

/// A user row from the `users` table.
#[cfg(not(edition_oss))]
#[derive(Debug, FromRow)]
pub(crate) struct UserRow {
    pub id: String,
}

/// An API key row from the `api_keys` table (project-scoped).
#[derive(Debug, FromRow)]
pub(crate) struct ApiKeyRow {
    pub user_id: String,
    pub project_id: String,
}

/// An org-scoped API key row from the `api_keys` table.
///
/// EE-only: org keys are mintable only from the cloud UI and the onprem
/// bootstrap, so the OSS build carries no org-key auth at all.
#[cfg(not(edition_oss))]
#[derive(Debug, FromRow)]
pub(crate) struct OrgApiKeyRow {
    pub user_id: String,
    pub organization_id: String,
}

/// A vault connection row from the `vault_connections` table.
#[derive(Debug, FromRow)]
#[allow(dead_code)]
pub(crate) struct VaultConnectionRow {
    pub id: String,
    pub provider: String,
    pub name: Option<String>,
    pub status: String,
    pub connection_data: Option<serde_json::Value>,
}

// ── Queries ─────────────────────────────────────────────────────────────

/// Look up a user by their external auth ID (e.g. an IdP `sub` claim).
///
/// EE-only: only the editions whose browser sessions are IdP tokens (cloud
/// Cognito) have anything to resolve here.
#[cfg(not(edition_oss))]
pub(crate) async fn find_user_by_external_auth_id(
    pool: &PgPool,
    external_auth_id: &str,
) -> Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>(r#"SELECT id FROM users WHERE external_auth_id = $1 LIMIT 1"#)
        .bind(external_auth_id)
        .fetch_optional(pool)
        .await
        .context("querying user by external_auth_id")
}

/// Resolve a Better Auth session token to its user id, treating an expired
/// session as absent.
///
/// `NOW() AT TIME ZONE 'UTC'` rather than bare `NOW()`: `expires_at` is a
/// zone-less `timestamp(3)` holding a UTC instant, so comparing it against a
/// `timestamptz` would shift every expiry by the session's `TimeZone` offset.
#[cfg(not(edition_cloud))]
pub(crate) async fn find_auth_session_user_id(
    pool: &PgPool,
    token: &str,
) -> Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"SELECT user_id
           FROM auth_sessions
           WHERE token = $1 AND expires_at > (NOW() AT TIME ZONE 'UTC')
           LIMIT 1"#,
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    .context("querying auth_sessions by token")?;

    Ok(row.map(|(user_id,)| user_id))
}

/// The user's own oldest project in their oldest active org membership.
///
/// The `created_by_user_id` filter is load-bearing under shared tenancy:
/// without it every session resolves to the first user's project.
///
/// Not compiled for cloud, which is multi-project and instead requires an
/// explicit `X-Project-Id` validated by [`user_can_access_project`].
#[cfg(not(edition_cloud))]
pub(crate) async fn find_default_project_id_by_user(
    pool: &PgPool,
    user_id: &str,
) -> Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"SELECT p.id
           FROM organization_members om
           INNER JOIN projects p ON p.organization_id = om.organization_id
           WHERE om.user_id = $1 AND om.status <> 'suspended'
             AND p.created_by_user_id = $1
           ORDER BY om.created_at ASC, p.created_at ASC, p.id ASC
           LIMIT 1"#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .context("querying default project for user via organization_members")?;

    Ok(row.map(|(id,)| id))
}

/// Look up an API key (`oc_...`) and return its user_id and project_id.
pub(crate) async fn find_api_key(pool: &PgPool, key: &str) -> Result<Option<ApiKeyRow>> {
    sqlx::query_as::<_, ApiKeyRow>(
        r#"SELECT user_id, project_id FROM api_keys WHERE key = $1 LIMIT 1"#,
    )
    .bind(key)
    .fetch_optional(pool)
    .await
    .context("querying api_keys by key")
}

/// Look up an org-scoped API key (`oc_org_...`) and return its user_id and organization_id.
#[cfg(not(edition_oss))]
pub(crate) async fn find_org_api_key(pool: &PgPool, key: &str) -> Result<Option<OrgApiKeyRow>> {
    sqlx::query_as::<_, OrgApiKeyRow>(
        r#"SELECT user_id, organization_id
           FROM api_keys
           WHERE key = $1 AND scope = 'organization' AND organization_id IS NOT NULL
           LIMIT 1"#,
    )
    .bind(key)
    .fetch_optional(pool)
    .await
    .context("querying org api_keys by key")
}

/// Verify that a project belongs to the given organization.
#[cfg(not(edition_oss))]
pub(crate) async fn verify_project_in_org(
    pool: &PgPool,
    project_id: &str,
    organization_id: &str,
) -> Result<bool> {
    let row: Option<(String,)> =
        sqlx::query_as(r#"SELECT id FROM projects WHERE id = $1 AND organization_id = $2 LIMIT 1"#)
            .bind(project_id)
            .bind(organization_id)
            .fetch_optional(pool)
            .await
            .context("verifying project belongs to organization")?;
    Ok(row.is_some())
}

/// Whether the project belongs to an organization the user is a member of.
#[cfg(edition_cloud)]
pub(crate) async fn user_can_access_project(
    pool: &PgPool,
    user_id: &str,
    project_id: &str,
) -> Result<bool> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"SELECT p.id
           FROM organization_members om
           INNER JOIN projects p ON p.organization_id = om.organization_id
           WHERE om.user_id = $1 AND p.id = $2
             AND om.status <> 'suspended'
           LIMIT 1"#,
    )
    .bind(user_id)
    .bind(project_id)
    .fetch_optional(pool)
    .await
    .context("verifying user has access to project")?;
    Ok(row.is_some())
}

/// Whether a project API key's user may still use its project: an active member
/// of the project's organization, and either an org admin/owner or the holder of
/// a `ProjectAccess` binding (direct or via a group).
///
/// Re-checked on every project-key auth, in every edition — under shared tenancy
/// an unchecked key reaches every other user's project. Project creation grants
/// no access on its own; `created_by_user_id` is provenance only.
pub(crate) async fn user_can_manage_project(
    pool: &PgPool,
    user_id: &str,
    project_id: &str,
) -> Result<bool> {
    let row: Option<(String,)> = sqlx::query_as(
        // The INNER JOIN is the suspension/removal gate; the two EXISTS arms are
        // the direct and group-mediated bindings.
        r#"SELECT p.id
           FROM projects p
           INNER JOIN organization_members om
             ON om.organization_id = p.organization_id
            AND om.user_id = $1
            AND om.status <> 'suspended'
           WHERE p.id = $2
             AND (
               om.role IN ('owner', 'admin')
               OR EXISTS (
                 SELECT 1 FROM project_access pa
                 WHERE pa.project_id = p.id AND pa.user_id = $1
               )
               OR EXISTS (
                 SELECT 1 FROM project_access pa
                 JOIN group_members gm ON gm.group_id = pa.group_id
                 WHERE pa.project_id = p.id AND gm.user_id = $1
               )
             )
           LIMIT 1"#,
    )
    .bind(user_id)
    .bind(project_id)
    .fetch_optional(pool)
    .await
    .context("verifying project-key user still has access to project")?;
    Ok(row.is_some())
}

/// Whether a user is an admin or owner of an organization. Re-checked on every
/// org-scoped API-key auth so the key stops working after a demotion or
/// suspension.
#[cfg(not(edition_oss))]
pub(crate) async fn user_is_org_admin(
    pool: &PgPool,
    user_id: &str,
    organization_id: &str,
) -> Result<bool> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"SELECT user_id
           FROM organization_members
           WHERE user_id = $1 AND organization_id = $2
             AND role IN ('owner', 'admin')
             AND status <> 'suspended'
           LIMIT 1"#,
    )
    .bind(user_id)
    .bind(organization_id)
    .fetch_optional(pool)
    .await
    .context("verifying user is org admin")?;
    Ok(row.is_some())
}

/// Look up an agent by its access token.
pub(crate) async fn find_agent_by_token(
    pool: &PgPool,
    access_token: &str,
) -> Result<Option<AgentRow>> {
    sqlx::query_as::<_, AgentRow>(
        r#"SELECT a.id, a.name, a.identifier, a.project_id, p.organization_id, o.subscription_status
           FROM agents a
           JOIN projects p ON a.project_id = p.id
           JOIN organizations o ON p.organization_id = o.id
           WHERE a.access_token = $1
           LIMIT 1"#,
    )
    .bind(access_token)
    .fetch_optional(pool)
    .await
    .context("querying agent by access_token")
}

/// Look up the organization ID for a project.
pub(crate) async fn find_organization_id_by_project(
    pool: &PgPool,
    project_id: &str,
) -> Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as(r#"SELECT organization_id FROM projects WHERE id = $1 LIMIT 1"#)
            .bind(project_id)
            .fetch_optional(pool)
            .await
            .context("querying organization_id by project_id")?;
    Ok(row.map(|(oid,)| oid))
}

/// Find all secrets for a given project.
pub(crate) async fn find_secrets_by_project(
    pool: &PgPool,
    project_id: &str,
) -> Result<Vec<SecretRow>> {
    sqlx::query_as::<_, SecretRow>(
        r#"SELECT id, scope, type, value_source, encrypted_value, op_ref, host_pattern, path_pattern, injection_config, metadata FROM secrets WHERE project_id = $1"#,
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .context("querying secrets by project_id")
}

/// Find all organization-level secrets.
pub(crate) async fn find_secrets_by_org(
    pool: &PgPool,
    organization_id: &str,
) -> Result<Vec<SecretRow>> {
    sqlx::query_as::<_, SecretRow>(
        r#"SELECT id, scope, type, value_source, encrypted_value, op_ref, host_pattern, path_pattern, injection_config, metadata
           FROM secrets
           WHERE organization_id = $1 AND scope = 'organization'"#,
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await
    .context("querying secrets by organization_id")
}

/// Update a secret's encrypted value (used for token refresh).
pub(crate) async fn update_secret_value(
    pool: &PgPool,
    secret_id: &str,
    encrypted_value: &str,
) -> Result<()> {
    sqlx::query(r#"UPDATE secrets SET encrypted_value = $1, updated_at = NOW() WHERE id = $2"#)
        .bind(encrypted_value)
        .bind(secret_id)
        .execute(pool)
        .await
        .context("updating secret encrypted value")?;
    Ok(())
}

// ── New-model policy queries (policy_rules_v2) ─────────────────────────────
//
// Every edition loads the active published generation of a scope's rules, with
// identities and targets aggregated as JSON and ordered by `priority`
// (first-match). The org-scope, principal-set and availability loaders are
// EE-only and live in the EE overlay.

/// One aggregated identity (from `json_agg`, camelCase keys). Exactly one of the
/// three principal columns is set per row (the `one_principal` CHECK). OSS
/// decodes the non-agent kinds fail-closed.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyIdentityRow {
    pub agent_id: Option<String>,
    pub user_id: Option<String>,
    pub group_id: Option<String>,
}

/// One aggregated target (camelCase keys). `app_connection_id`/`secret_id` name
/// a specific credential to inject at connect, and the block/allow engine also
/// gates their hosts — a secret by its resolved host pattern, a connection by
/// its provider's catalog hosts.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyTargetRow {
    pub kind: String,
    pub app_provider: Option<String>,
    #[serde(default)]
    pub app_tools: Vec<String>,
    /// kind=app: "organization" | "project" injects every one of the agent's
    /// connections of `app_provider` at that level; NULL is the app-permission
    /// block/allow rule (no injection).
    pub app_connection_scope: Option<String>,
    pub app_connection_id: Option<String>,
    pub secret_id: Option<String>,
    /// kind=secret: "organization" | "project" injects every one of the agent's
    /// secrets at that level; NULL is a specific `secret_id` target.
    pub secret_scope: Option<String>,
    pub host_pattern: Option<String>,
    pub path_pattern: Option<String>,
    pub method: Option<String>,
}

/// A published `policy_rules_v2` rule, with its identities and targets decoded
/// at load and carried in `ConnectResponse`, so the per-request decision path
/// neither queries nor re-parses anything.
#[derive(Debug, Clone, PartialEq, FromRow, serde::Serialize, serde::Deserialize)]
pub(crate) struct PolicyRuleV2Row {
    pub id: String,
    /// Generation-stable identity the rate counter keys on, so counts survive a
    /// republish.
    pub logical_id: String,
    pub name: String,
    /// Rule origin (custom | app_permission | blocklist | default | equipment).
    /// `equipment` rules are injection-only: the block/allow assembler drops
    /// them and only the connect-time inject-selection reads them.
    pub source: String,
    pub priority: i32,
    pub is_default: bool,
    pub action: String,
    pub rate_limit: Option<i32>,
    pub rate_limit_window: Option<String>,
    pub require_approval: bool,
    pub conditions: Option<serde_json::Value>,
    pub identities: Json<Vec<PolicyIdentityRow>>,
    pub targets: Json<Vec<PolicyTargetRow>>,
}

/// The agent's principal context for a connection. Always empty in OSS, which
/// has agent-only identities; it lives here so both builds serialize the same
/// `ConnectResponse`.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PrincipalSet {
    /// Human users the agent's project grants via ProjectAccess — directly, or as
    /// members of a granted group.
    pub user_ids: Vec<String>,
    /// Directory groups to match: those granted to the project directly, plus
    /// every group the inherited users belong to (org-fenced).
    pub group_ids: Vec<String>,
}

/// The published rules for a connection's org + project scopes, loaded during
/// connection resolution. Empty when the engine is off, the org isn't
/// backfilled, or a load errored — the enforce seam then takes the legacy path.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PolicyV2Rules {
    pub org: Vec<PolicyRuleV2Row>,
    pub project: Vec<PolicyRuleV2Row>,
    /// The connection's resolved principal set. Resolved lazily — empty unless a
    /// loaded rule targets a user or group identity. Cloud-only.
    #[serde(default)]
    pub principals: PrincipalSet,
    /// The org+project custom secrets' host patterns, so a `secret` target can
    /// permit/deny its host without a query. Empty unless a loaded rule has a
    /// secret target.
    #[serde(default)]
    pub secret_hosts: SecretHosts,
    /// The org+project app connections' providers, so a `connection` target can
    /// resolve to its provider's catalog hosts without a query. Empty unless a
    /// loaded rule has a connection target. Cloud-only.
    #[serde(default)]
    pub connection_providers: ConnectionProviders,
}

/// The host patterns of the acting org+project custom secrets, resolved once at
/// connection resolution so a `secret` target can permit/deny its host without a
/// query. Each secret contributes every host its credential injects on, so the
/// enforcement surface matches the injection surface exactly.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SecretHosts {
    /// A specific secret's id → every host pattern its credential injects on.
    pub by_id: std::collections::HashMap<String, Vec<String>>,
    /// Host patterns for `secret_scope = "project"`.
    pub project_hosts: Vec<String>,
    /// Host patterns for `secret_scope = "organization"`.
    pub org_hosts: Vec<String>,
}

/// The providers of the acting org+project app connections, so a `connection`
/// target resolves to its provider's catalog hosts without a query. The map is
/// org+project-fenced at load, so a foreign connection id resolves to nothing
/// and its target never matches.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ConnectionProviders {
    /// A connection's id → its `provider` (e.g. "gmail").
    pub by_id: std::collections::HashMap<String, String>,
}

/// The credentials the published rules allow the requesting agent to have
/// injected, folded once at connect from the already-loaded `PolicyV2Rules`.
/// This is the only selection for the org/project tiers; it feeds the resolvers
/// whose output rides `ConnectResponse` and is not cached itself.
#[derive(Debug, Clone, Default)]
pub(crate) struct InjectSelection {
    /// Specific `Secret` ids named by the agent's matching `kind=secret` allow
    /// targets.
    pub secret_ids: std::collections::HashSet<String>,
    /// Specific `AppConnection` id → its `sessionPolicy` (the matching rule's
    /// conditions — the granular guard) for `kind=connection` allow targets.
    pub connections: std::collections::HashMap<String, Option<serde_json::Value>>,
    /// (provider, level) pairs from `kind=app` allow targets carrying a
    /// `connection_scope`: inject every one of the agent's connections of
    /// `provider` at that level. No per-connection sessionPolicy, but the
    /// connections it resolves to are still bounded by `boundaries`.
    pub app_scopes: Vec<(String, String)>,
    /// Connection id → the org's resource boundary for it. Kept separate from
    /// `connections` because a boundary is not a grant: it also applies to
    /// connections pulled in by a provider-level `app_scopes` grant, which are
    /// resolved long after the rules are folded. Always empty in OSS.
    pub boundaries: std::collections::HashMap<String, serde_json::Value>,
    /// Levels from `kind=secret` allow targets carrying a `secret_scope`: inject
    /// every one of the agent's secrets at that level, with no per-secret guard.
    pub secret_scopes: Vec<String>,
}

/// The apps a connection's project may reach. `restricted = false` — the
/// default, and always the case in OSS — means every app is available and the
/// per-request pre-check is a no-op.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct AvailableApps {
    pub restricted: bool,
    pub providers: Vec<String>,
}

pub(crate) const POLICY_V2_SELECT: &str = r#"
    SELECT r.id, r.logical_id, r.name, r.source, r.priority, r.is_default, r.action,
           r.rate_limit, r.rate_limit_window, r.require_approval, r.conditions,
           COALESCE((
             SELECT json_agg(json_build_object(
               'agentId', i.agent_id,
               'userId', i.user_id, 'groupId', i.group_id))
             FROM policy_rule_identities i WHERE i.rule_id = r.id
           ), '[]'::json) AS identities,
           COALESCE((
             SELECT json_agg(json_build_object(
               'kind', t.kind, 'appProvider', t.app_provider, 'appTools', t.app_tools,
               'appConnectionScope', t.app_connection_scope,
               'appConnectionId', t.app_connection_id, 'secretId', t.secret_id,
               'secretScope', t.secret_scope,
               'hostPattern', t.host_pattern, 'pathPattern', t.path_pattern,
               'method', t.method))
             FROM policy_rule_targets t WHERE t.rule_id = r.id
           ), '[]'::json) AS targets
    FROM policy_rules_v2 r
"#;

/// Active published project-scope rules (max published generation), first-match
/// ordered.
pub(crate) async fn find_published_policy_rules_v2_by_project(
    pool: &PgPool,
    project_id: &str,
) -> Result<Vec<PolicyRuleV2Row>> {
    sqlx::query_as::<_, PolicyRuleV2Row>(&format!(
        r#"{POLICY_V2_SELECT}
           WHERE r.project_id = $1 AND r.scope = 'project'
             AND r.status = 'published' AND r.enabled = true
             AND r.generation = (
               SELECT max(generation) FROM policy_rules_v2
               WHERE project_id = $1 AND scope = 'project' AND status = 'published')
           ORDER BY r.priority, r.id"#
    ))
    .bind(project_id)
    .fetch_all(pool)
    .await
    .context("querying policy_rules_v2 by project_id")
}

#[derive(sqlx::FromRow)]
struct SecretHostRow {
    id: String,
    host_pattern: String,
    scope: String,
    #[sqlx(rename = "type")]
    type_: String,
}

/// Resolve the host patterns of the acting org+project custom secrets.
///
/// Both arms are org+project-fenced, so a foreign `secret_id` or scope cannot
/// pull another org's host — it is simply absent from the set. Partner secrets
/// are out of scope. Run once at connect.
pub(crate) async fn find_secret_hosts(
    pool: &PgPool,
    organization_id: &str,
    project_id: &str,
) -> Result<SecretHosts> {
    let rows: Vec<SecretHostRow> = sqlx::query_as::<_, SecretHostRow>(
        r#"
        SELECT id, host_pattern, scope, type FROM secrets
        WHERE project_id = $2
           OR (organization_id = $1 AND scope = 'organization')
        "#,
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_all(pool)
    .await
    .context("resolving secret hosts")?;

    let mut hosts = SecretHosts::default();
    for row in rows {
        // A typed secret injects on several hosts, so expand to all of them and
        // keep the enforcement surface equal to the injection surface.
        let patterns = crate::secret_inject::secret_host_patterns(&row.type_, &row.host_pattern);
        match row.scope.as_str() {
            "project" => hosts.project_hosts.extend(patterns.iter().cloned()),
            "organization" => hosts.org_hosts.extend(patterns.iter().cloned()),
            _ => {}
        }
        hosts.by_id.insert(row.id, patterns);
    }
    Ok(hosts)
}

/// Resolve the providers of the acting org+project app connections.
///
/// Org+project-fenced like [`find_secret_hosts`], so a foreign connection id
/// never resolves and its target never matches. No status filter: the row's
/// existence is the reference, and deletion cascades the target row away.
pub(crate) async fn find_connection_providers(
    pool: &PgPool,
    organization_id: &str,
    project_id: &str,
) -> Result<ConnectionProviders> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT id, provider FROM app_connections
        WHERE project_id = $2
           OR (organization_id = $1 AND scope = 'organization')
        "#,
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_all(pool)
    .await
    .context("resolving connection providers")?;

    Ok(ConnectionProviders {
        by_id: rows.into_iter().collect(),
    })
}

// ── App config queries (BYOC credentials) ─────────────────────────────

/// An app config row from the `app_configs` table.
#[derive(Debug, FromRow)]
pub(crate) struct AppConfigRow {
    pub settings: Option<serde_json::Value>,
    pub credentials: Option<String>,
}

/// Find an enabled BYOC app config for a project + provider.
pub(crate) async fn find_app_config(
    pool: &PgPool,
    project_id: &str,
    provider: &str,
) -> Result<Option<AppConfigRow>> {
    sqlx::query_as::<_, AppConfigRow>(
        r#"SELECT settings, credentials FROM app_configs
           WHERE project_id = $1 AND provider = $2 AND enabled = true
           LIMIT 1"#,
    )
    .bind(project_id)
    .bind(provider)
    .fetch_optional(pool)
    .await
    .context("querying app_config by project_id + provider")
}

/// Find an enabled org-level BYOC app config for an organization + provider.
///
/// EE-only: org-level app configs are writable only through the EE org surface,
/// so OSS can never have one to look up.
#[cfg(not(edition_oss))]
pub(crate) async fn find_app_config_by_org(
    pool: &PgPool,
    organization_id: &str,
    provider: &str,
) -> Result<Option<AppConfigRow>> {
    sqlx::query_as::<_, AppConfigRow>(
        r#"SELECT settings, credentials FROM app_configs
           WHERE organization_id = $1 AND provider = $2
             AND scope = 'organization' AND enabled = true
           LIMIT 1"#,
    )
    .bind(organization_id)
    .bind(provider)
    .fetch_optional(pool)
    .await
    .context("querying app_config by organization_id + provider")
}

/// Find the enabled BYOC app config that minted a specific connection, via
/// `app_connections.app_config_id`.
///
/// A connection's OAuth refresh token is bound to the client that minted it, so
/// refresh must reuse that config even when the resolver's tier order would now
/// pick a different row. The `provider` guard stops a mislinked row handing one
/// provider's client secret to another's token endpoint. `None` when the link is
/// null, or the config is disabled, removed, or for another provider.
pub(crate) async fn find_app_config_by_connection(
    pool: &PgPool,
    connection_id: &str,
    provider: &str,
) -> Result<Option<AppConfigRow>> {
    sqlx::query_as::<_, AppConfigRow>(
        r#"SELECT ac.settings, ac.credentials FROM app_configs ac
           JOIN app_connections c ON c.app_config_id = ac.id
           WHERE c.id = $1 AND ac.provider = $2 AND ac.enabled = true
           LIMIT 1"#,
    )
    .bind(connection_id)
    .bind(provider)
    .fetch_optional(pool)
    .await
    .context("querying app_config by connection provenance link")
}

// ── App connection queries ─────────────────────────────────────────────

/// An app connection row from the `app_connections` table.
#[derive(Debug, Clone, PartialEq, FromRow, serde::Serialize, serde::Deserialize)]
pub(crate) struct AppConnectionRow {
    pub id: String,
    pub provider: String,
    /// "organization" | "project" — the connection's level, matched by app
    /// targets scoped to every connection at a level.
    pub scope: String,
    pub credentials: Option<String>,
    pub label: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub session_policy: Option<serde_json::Value>,
}

/// Find all connected app connections for a given project.
pub(crate) async fn find_app_connections_by_project(
    pool: &PgPool,
    project_id: &str,
) -> Result<Vec<AppConnectionRow>> {
    sqlx::query_as::<_, AppConnectionRow>(
        r#"SELECT id, provider, scope, credentials, label, metadata, NULL::jsonb AS session_policy FROM app_connections WHERE project_id = $1 AND status = 'connected'"#,
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .context("querying app_connections by project_id")
}

/// Find all organization-level app connections.
pub(crate) async fn find_app_connections_by_org(
    pool: &PgPool,
    organization_id: &str,
) -> Result<Vec<AppConnectionRow>> {
    sqlx::query_as::<_, AppConnectionRow>(
        r#"SELECT id, provider, scope, credentials, label, metadata, NULL::jsonb AS session_policy
           FROM app_connections
           WHERE organization_id = $1 AND scope = 'organization' AND status = 'connected'"#,
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await
    .context("querying app_connections by organization_id")
}

/// Update the encrypted credentials for an app connection (e.g., after token refresh).
pub(crate) async fn update_app_connection_credentials(
    pool: &PgPool,
    connection_id: &str,
    encrypted_credentials: &str,
) -> Result<()> {
    sqlx::query(r#"UPDATE app_connections SET credentials = $1 WHERE id = $2"#)
        .bind(encrypted_credentials)
        .bind(connection_id)
        .execute(pool)
        .await
        .context("updating app_connection credentials")?;
    Ok(())
}

// ── Vault connection queries ────────────────────────────────────────────

/// Find a vault connection for a project + provider pair.
pub(crate) async fn find_vault_connection(
    pool: &PgPool,
    project_id: &str,
    provider: &str,
) -> Result<Option<VaultConnectionRow>> {
    sqlx::query_as::<_, VaultConnectionRow>(
        r#"SELECT id, provider, name, status, connection_data FROM vault_connections WHERE project_id = $1 AND provider = $2 LIMIT 1"#,
    )
    .bind(project_id)
    .bind(provider)
    .fetch_optional(pool)
    .await
    .context("querying vault_connection by project_id + provider")
}

/// Upsert a vault connection (insert or update on project_id + provider conflict).
pub(crate) async fn upsert_vault_connection(
    pool: &PgPool,
    project_id: &str,
    provider: &str,
    status: &str,
    connection_data: Option<&serde_json::Value>,
) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO vault_connections (id, project_id, provider, status, connection_data, created_at, updated_at)
           VALUES (gen_random_uuid()::text, $1, $2, $3, $4, NOW(), NOW())
           ON CONFLICT (project_id, provider)
           DO UPDATE SET status = $3, connection_data = $4, updated_at = NOW()"#,
    )
    .bind(project_id)
    .bind(provider)
    .bind(status)
    .bind(connection_data)
    .execute(pool)
    .await
    .context("upserting vault_connection")?;
    Ok(())
}

/// Update only the connection_data JSON for an existing vault connection.
pub(crate) async fn update_vault_connection_data(
    pool: &PgPool,
    project_id: &str,
    provider: &str,
    connection_data: &serde_json::Value,
) -> Result<()> {
    sqlx::query(
        r#"UPDATE vault_connections SET connection_data = $3, updated_at = NOW() WHERE project_id = $1 AND provider = $2"#,
    )
    .bind(project_id)
    .bind(provider)
    .bind(connection_data)
    .execute(pool)
    .await
    .context("updating vault_connection connection_data")?;
    Ok(())
}

/// Delete a vault connection for a project + provider pair.
pub(crate) async fn delete_vault_connection(
    pool: &PgPool,
    project_id: &str,
    provider: &str,
) -> Result<()> {
    sqlx::query(r#"DELETE FROM vault_connections WHERE project_id = $1 AND provider = $2"#)
        .bind(project_id)
        .bind(provider)
        .execute(pool)
        .await
        .context("deleting vault_connection")?;
    Ok(())
}

// ── Proof tests ─────────────────────────────────────────────────────────

/// Real-PostgreSQL tests for the project-key usage gate.
///
/// Skipped locally when `POLICY_PROOF_DATABASE_URL` is unset, but a hard failure
/// in CI — a silently skipped suite reports the same green as a passing one.
#[cfg(test)]
mod access_proof_tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    const P: &str = "gwacc-";

    fn proof_database_url() -> Option<String> {
        match std::env::var("POLICY_PROOF_DATABASE_URL") {
            Ok(url) if !url.is_empty() => Some(url),
            _ => {
                if std::env::var("CI").map(|v| !v.is_empty()).unwrap_or(false) {
                    panic!(
                        "POLICY_PROOF_DATABASE_URL must be set in CI: the gateway \
                         proof tests must not silently skip"
                    );
                }
                None
            }
        }
    }

    async fn reset(pool: &PgPool) -> Result<()> {
        for stmt in [
            "DELETE FROM project_access WHERE project_id LIKE $1",
            "DELETE FROM projects WHERE id LIKE $1",
            "DELETE FROM organization_members WHERE user_id LIKE $1",
            "DELETE FROM users WHERE id LIKE $1",
            "DELETE FROM organizations WHERE id LIKE $1",
        ] {
            sqlx::query(stmt)
                .bind(format!("{P}%"))
                .execute(pool)
                .await?;
        }
        Ok(())
    }

    /// One org, two users with a project each, plus an org admin who owns none.
    /// Each project carries its creator's binding, as provisioning writes it.
    async fn seed(pool: &PgPool) -> Result<()> {
        reset(pool).await?;

        sqlx::query(
            "INSERT INTO organizations (id, name, slug, updated_at)
             VALUES ($1, 'proof', $1, NOW())",
        )
        .bind(format!("{P}org"))
        .execute(pool)
        .await?;

        for who in ["alice", "bob", "admin"] {
            sqlx::query(
                "INSERT INTO users (id, email, name, external_auth_id, updated_at)
                 VALUES ($1, $2, $1, $1, NOW())",
            )
            .bind(format!("{P}{who}"))
            .bind(format!("{P}{who}@proof.test"))
            .execute(pool)
            .await?;
        }

        for who in ["alice", "bob"] {
            sqlx::query(
                "INSERT INTO projects
                   (id, name, slug, organization_id, created_by_user_id, updated_at)
                 VALUES ($1, $1, $1, $2, $3, NOW())",
            )
            .bind(format!("{P}{who}-proj"))
            .bind(format!("{P}org"))
            .bind(format!("{P}{who}"))
            .execute(pool)
            .await?;

            sqlx::query(
                "INSERT INTO project_access (id, project_id, user_id, role, updated_at)
                 VALUES ($1, $2, $3, 'owner', NOW())",
            )
            .bind(format!("{P}{who}-binding"))
            .bind(format!("{P}{who}-proj"))
            .bind(format!("{P}{who}"))
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    async fn add_member(pool: &PgPool, who: &str, role: &str, status: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO organization_members
               (organization_id, user_id, user_email, role, status)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (organization_id, user_id)
             DO UPDATE SET role = EXCLUDED.role, status = EXCLUDED.status",
        )
        .bind(format!("{P}org"))
        .bind(format!("{P}{who}"))
        .bind(format!("{P}{who}@proof.test"))
        .bind(role)
        .bind(status)
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn can(pool: &PgPool, who: &str, project_owner: &str) -> bool {
        user_can_manage_project(
            pool,
            &format!("{P}{who}"),
            &format!("{P}{project_owner}-proj"),
        )
        .await
        .expect("access check")
    }

    #[tokio::test]
    async fn project_key_access_is_rechecked_against_membership_and_bindings() {
        let Some(url) = proof_database_url() else {
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect to proof database");

        seed(&pool).await.expect("seed");

        add_member(&pool, "alice", "member", "active")
            .await
            .unwrap();
        add_member(&pool, "bob", "member", "active").await.unwrap();
        add_member(&pool, "admin", "admin", "active").await.unwrap();

        assert!(can(&pool, "alice", "alice").await, "own project");
        // Alice and Bob share one org, so membership alone would admit her; the
        // binding check is what refuses.
        assert!(!can(&pool, "alice", "bob").await, "another user's project");
        assert!(
            can(&pool, "admin", "bob").await,
            "org admin reaches any project"
        );

        // Suspension revokes immediately, binding or not.
        add_member(&pool, "alice", "member", "suspended")
            .await
            .unwrap();
        assert!(!can(&pool, "alice", "alice").await, "suspended member");

        add_member(&pool, "admin", "admin", "suspended")
            .await
            .unwrap();
        assert!(!can(&pool, "admin", "bob").await, "suspended admin");

        // Removal from the org revokes too.
        sqlx::query("DELETE FROM organization_members WHERE user_id = $1")
            .bind(format!("{P}alice"))
            .execute(&pool)
            .await
            .unwrap();
        assert!(!can(&pool, "alice", "alice").await, "removed member");

        reset(&pool).await.expect("cleanup");
    }
}
