//! Budget layer — stub for the OSS build. All functions are no-ops; the cloud
//! build swaps this module for `ee/budget.rs` via `#[path]` in `main.rs`.
//!
//! The shared surface exists in both builds so the threading through
//! `connect.rs`/`gateway/mitm.rs` stays identical, and is inert in OSS.

use serde::{Deserialize, Serialize};

// Keep the types below identical to `ee/budget.rs`. Only one of the two modules
// compiles per build, so a field added to one and not the other will not fail
// compilation. Treat them as one type.

/// How a budget's spend window resets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BudgetPeriod {
    /// Resets on the 1st of each month (UTC).
    Monthly,
    /// Lifetime cap; never resets.
    Total,
}

/// A resolved budget that governs the effective credential for a request's host.
/// Resolved once at connect time and threaded `ConnectResponse → ResolvedRules`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct BudgetBinding {
    pub secret_id: String,
    pub organization_id: String,
    /// Secret type, selects the metering strategy (e.g. "anthropic").
    pub secret_type: String,
    /// Spend ceiling in nano-dollars (1e-9 USD).
    pub limit_nanos: i64,
    pub period: BudgetPeriod,
}

/// Resolve budget bindings for the effective partner secrets among a request's
/// host-filtered secrets. Always empty in OSS — no budgets are enforced.
pub(crate) async fn resolve_bindings(
    _pool: &sqlx::PgPool,
    _org_id: &str,
    _secrets: &[crate::db::SecretRow],
) -> Vec<BudgetBinding> {
    Vec::new()
}
