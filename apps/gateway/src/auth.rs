//! Gateway authentication for browser requests.
//!
//! Supports two modes controlled by the `AUTH_MODE` env var:
//! - `local`: no session mechanism at all (single-user dev, no login) — the
//!   only accepted credential is an `Authorization: Bearer oc_...` API key,
//!   checked by `validate_api_key` before mode-specific logic even runs.
//! - `oauth` (default): validates a NextAuth session cookie JWT (HS256).

use std::sync::OnceLock;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use hyper::HeaderMap;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sqlx::PgPool;
use tracing::warn;

use crate::db;
use crate::gateway::GatewayState;

// ── AuthError ────────────────────────────────────────────────────────────

/// Authentication error — always returns 401 Unauthorized.
#[derive(Debug)]
pub(crate) struct AuthError(String);

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "auth error: {}", self.0)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::UNAUTHORIZED, self.0).into_response()
    }
}

// ── JWT claims ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SessionClaims {
    sub: String,
}

// ── Cached env reads ─────────────────────────────────────────────────────

fn auth_mode() -> &'static str {
    static AUTH_MODE: OnceLock<String> = OnceLock::new();
    AUTH_MODE.get_or_init(|| std::env::var("AUTH_MODE").unwrap_or_else(|_| "oauth".to_string()))
}

fn nextauth_secret() -> Option<&'static str> {
    static SECRET: OnceLock<Option<String>> = OnceLock::new();
    SECRET
        .get_or_init(|| std::env::var("NEXTAUTH_SECRET").ok())
        .as_deref()
}

// ── Extractor ────────────────────────────────────────────────────────────

/// Authenticated user extracted from browser session cookies.
///
/// Add as an Axum handler parameter to require authentication:
/// ```ignore
/// async fn list_secrets(auth: AuthUser) -> impl IntoResponse { ... }
/// ```
pub(crate) struct AuthUser {
    pub user_id: String,
    pub project_id: String,
    pub auth_method: String,
}

impl FromRequestParts<GatewayState> for AuthUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &GatewayState,
    ) -> Result<Self, Self::Rejection> {
        // Try API key auth first (Authorization: Bearer oc_...)
        if let Some(api_key_user) =
            validate_api_key(&state.policy_engine.pool, &parts.headers).await
        {
            return Ok(api_key_user);
        }

        // Fall back to session auth (cookies / JWT)
        let user_id = validate_request(&state.policy_engine.pool, &parts.headers).await?;

        // Resolve default project for this user (org → first project).
        let project_id = db::find_default_project_id_by_user(&state.policy_engine.pool, &user_id)
            .await
            .map_err(|e| {
                warn!(error = %e, "auth: failed to resolve project");
                AuthError("internal error".to_string())
            })?
            .ok_or_else(|| {
                warn!(user_id = %user_id, "auth: no project found for user");
                AuthError("no project found".to_string())
            })?;

        Ok(Self {
            user_id,
            project_id,
            auth_method: "session".to_string(),
        })
    }
}

// ── API key auth ─────────────────────────────────────────────────────────

/// Try to authenticate via `Authorization: Bearer oc_...` API key.
/// Returns `None` if no API key is present (falls through to session auth).
async fn validate_api_key(pool: &PgPool, headers: &HeaderMap) -> Option<AuthUser> {
    let auth_header = headers.get(hyper::header::AUTHORIZATION)?.to_str().ok()?;
    let token = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))?;

    if !token.starts_with("oc_") {
        return None;
    }

    let api_key = db::find_api_key(pool, token)
        .await
        .map_err(|e| warn!(error = %e, "api key auth: db error"))
        .ok()??;

    let prefix = token.get(..12).unwrap_or(token);
    Some(AuthUser {
        user_id: api_key.user_id,
        project_id: api_key.project_id,
        auth_method: format!("api_key:{prefix}"),
    })
}

// ── Session auth ─────────────────────────────────────────────────────────

/// Validate an incoming browser request and return the internal user ID.
/// The caller resolves the project ID from the user's membership.
async fn validate_request(pool: &PgPool, headers: &HeaderMap) -> Result<String, AuthError> {
    match auth_mode() {
        // Local mode has no cookie/session mechanism to fall back to (no
        // login flow exists). A request reaching here already failed the API
        // key check above, so it is unauthenticated — reject it rather than
        // auto-trusting it as local-admin. This is the only credential path
        // in local mode, so it must hold even when the gateway is bound to
        // loopback: anything else on the same host could otherwise reach it.
        "local" => Err(AuthError(
            "missing API key (Authorization: Bearer oc_...)".to_string(),
        )),
        _ => validate_oauth(pool, headers).await,
    }
}

// ── OAuth mode ───────────────────────────────────────────────────────────

async fn validate_oauth(pool: &PgPool, headers: &HeaderMap) -> Result<String, AuthError> {
    // 1. Extract session token from cookies
    let cookie_header = headers
        .get(hyper::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            warn!("oauth auth: no cookie header");
            AuthError("missing cookie".to_string())
        })?;

    let token = session_token_from_cookies(cookie_header).ok_or_else(|| {
        warn!("oauth auth: session token cookie not found");
        AuthError("missing session token".to_string())
    })?;

    // 2. Read NEXTAUTH_SECRET
    let secret = nextauth_secret().ok_or_else(|| {
        warn!("oauth auth: NEXTAUTH_SECRET not set");
        AuthError("server misconfigured".to_string())
    })?;

    // 3. Decode JWT (HS256)
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;

    let token_data = decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|e| {
        warn!(error = %e, "oauth auth: JWT decode failed");
        AuthError("invalid session token".to_string())
    })?;

    let sub = &token_data.claims.sub;

    // 4. Look up user by external auth ID
    let user = db::find_user_by_external_auth_id(pool, sub)
        .await
        .map_err(|e| {
            warn!(error = %e, "oauth auth: db error");
            AuthError("internal error".to_string())
        })?
        .ok_or_else(|| {
            warn!(sub = %sub, "oauth auth: user not found");
            AuthError("user not found".to_string())
        })?;

    Ok(user.id)
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// The NextAuth session cookie, under either spelling Auth.js may have used.
///
/// Auth.js prefixes the cookie with `__Secure-` whenever it considers the
/// deployment secure, which it decides from the scheme of the resolved
/// `AUTH_URL` / `NEXTAUTH_URL`. Every instance reached over https therefore
/// sends `__Secure-authjs.session-token`, and a self-hosted one cannot opt out:
/// the OAuth spec (and Google's redirect-URI validation) requires an https
/// callback for anything but localhost, so the single variable that makes login
/// work also renames this cookie. Matching only the bare name meant session auth
/// could never succeed on a TLS deployment.
///
/// Bare name first: it is what an http/localhost install sends, and checking it
/// first keeps that path a single comparison.
fn session_token_from_cookies(cookie_header: &str) -> Option<&str> {
    parse_cookie(cookie_header, "authjs.session-token")
        .or_else(|| parse_cookie(cookie_header, "__Secure-authjs.session-token"))
}

/// Parse a specific cookie value from a Cookie header string.
fn parse_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header.split(';').find_map(|pair| {
        let pair = pair.trim();
        let (key, value) = pair.split_once('=')?;
        if key.trim() == name {
            Some(value.trim())
        } else {
            None
        }
    })
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cookie_finds_value() {
        let header = "other=abc; authjs.session-token=eyJhbGciOiJIUzI1NiJ9.test; path=/";
        assert_eq!(
            parse_cookie(header, "authjs.session-token"),
            Some("eyJhbGciOiJIUzI1NiJ9.test")
        );
    }

    #[test]
    fn parse_cookie_missing() {
        let header = "other=abc; foo=bar";
        assert_eq!(parse_cookie(header, "authjs.session-token"), None);
    }

    #[test]
    fn parse_cookie_empty() {
        assert_eq!(parse_cookie("", "authjs.session-token"), None);
    }

    #[test]
    fn session_token_accepts_bare_name() {
        let header = "other=abc; authjs.session-token=eyJhbGciOiJIUzI1NiJ9.test";
        assert_eq!(
            session_token_from_cookies(header),
            Some("eyJhbGciOiJIUzI1NiJ9.test")
        );
    }

    /// What a browser sends to an https deployment: Auth.js switches the session
    /// cookie to the `__Secure-` prefix and the CSRF cookie to `__Host-`.
    #[test]
    fn session_token_accepts_secure_prefixed_name() {
        let header = "__Host-authjs.csrf-token=abc; \
                      __Secure-authjs.session-token=eyJhbGciOiJIUzI1NiJ9.test";
        assert_eq!(
            session_token_from_cookies(header),
            Some("eyJhbGciOiJIUzI1NiJ9.test")
        );
    }

    /// The bare name wins when both are somehow present, so an http install's
    /// behaviour is unchanged.
    #[test]
    fn session_token_prefers_bare_name() {
        let header = "__Secure-authjs.session-token=prefixed; authjs.session-token=bare";
        assert_eq!(session_token_from_cookies(header), Some("bare"));
    }

    #[test]
    fn session_token_missing() {
        assert_eq!(session_token_from_cookies("other=abc; foo=bar"), None);
    }

    /// Regression test for the loopback auth bypass (local gateway API did
    /// not enforce ONECLI_API_KEY when bound to TCP loopback): a bare
    /// request with no `Authorization` header must be rejected in `local`
    /// mode instead of silently authenticating as local-admin.
    #[tokio::test]
    async fn validate_request_local_mode_rejects_bare_request() {
        std::env::set_var("AUTH_MODE", "local");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/nonexistent")
            .expect("lazy pool never fails to construct");
        let headers = HeaderMap::new();

        let result = validate_request(&pool, &headers).await;

        assert!(result.is_err());
    }
}
