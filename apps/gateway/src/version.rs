//! Resolve the running app/build version.
//!
//! Read from the `APP_VERSION` env var stamped on the deployed image
//! (`<semver>+<short-sha>`), falling back to the compile-time crate version.

/// The app version reported by `/healthz` and telemetry.
pub fn app_version() -> String {
    std::env::var("APP_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
}
