//! Policy engine — the OSS project-level first-match core. EE editions swap this
//! module for `ee/policy_engine.rs` via `#[path]` in `main.rs`; the `pub(crate)`
//! surface is identical in both builds, so shared call sites never change.
//!
//! Scope here is project rules only. Org scope, directory identities, granular
//! session policies and availability are OneCLI Cloud capabilities with no code
//! here.

mod assemble;
mod catalog;
mod enforce;
mod evaluate;
mod inject_select;
mod types;

// The corpus parity test lives in the private tree and never ships; the OSS
// repo carries an empty stub at the same path so `cargo fmt`/`cargo test`
// resolve it.
#[cfg(test)]
#[path = "ee/policy_engine/oss_parity_test.rs"]
mod oss_parity_test;

pub(crate) use enforce::{evaluate, load_available_apps, load_connect_v2, needs_body_buffer};
pub(crate) use inject_select::derive_inject_selection;
