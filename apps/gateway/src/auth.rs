//! Gateway authentication for browser requests.
//!
//! Supports two modes controlled by the `AUTH_MODE` env var:
//! - `local`: no session mechanism at all (single-user dev, no login) — the
//!   only accepted credential is an `Authorization: Bearer oc_...` API key,
//!   checked by `validate_api_key` before mode-specific logic even runs.
//! - `oauth` (default): resolves a Better Auth session cookie against the
//!   `auth_sessions` row it names. The gateway shares the web app's database,
//!   so it reads the session table Better Auth writes rather than re-deriving
//!   anything from the cookie — see `validate_oauth`.

use std::sync::OnceLock;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use hyper::HeaderMap;
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

// ── Cached env reads ─────────────────────────────────────────────────────

fn auth_mode() -> &'static str {
    static AUTH_MODE: OnceLock<String> = OnceLock::new();
    AUTH_MODE.get_or_init(|| std::env::var("AUTH_MODE").unwrap_or_else(|_| "oauth".to_string()))
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

/// Resolve a Better Auth session cookie to the user it belongs to.
///
/// The cookie carries no claims to decode: Better Auth stores the session
/// server-side and the cookie is only a pointer to that row. So the row IS the
/// decision — a lookup that finds a live session is proof the session exists and
/// has not expired or been revoked, which no self-contained token could tell us.
/// The token is 32 CSPRNG characters, so it cannot be guessed into existence.
///
/// The HMAC signature the cookie also carries is deliberately NOT verified —
/// see [`session_token_value`].
async fn validate_oauth(pool: &PgPool, headers: &HeaderMap) -> Result<String, AuthError> {
    let cookie_header = headers
        .get(hyper::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            warn!("oauth auth: no cookie header");
            AuthError("missing cookie".to_string())
        })?;

    let cookie_value = session_token_from_cookies(cookie_header).ok_or_else(|| {
        warn!("oauth auth: session token cookie not found");
        AuthError("missing session token".to_string())
    })?;

    // `auth_sessions.user_id` is already `users.id` — Better Auth's user model is
    // mapped onto the existing table, so there is no external-auth-id hop here.
    let user_id = db::find_auth_session_user_id(pool, session_token_value(cookie_value))
        .await
        .map_err(|e| {
            warn!(error = %e, "oauth auth: db error");
            AuthError("internal error".to_string())
        })?
        .ok_or_else(|| {
            // Unknown, revoked and expired are one case on purpose: the holder of
            // a bad cookie learns nothing about which it was.
            warn!("oauth auth: no live session for token");
            AuthError("invalid session token".to_string())
        })?;

    Ok(user_id)
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// The Better Auth session cookie, under either spelling it may have been set with.
///
/// Better Auth prefixes the cookie with `__Secure-` whenever it considers the
/// deployment secure, which it decides from the scheme of the resolved
/// `baseURL` (our `APP_URL`). Every instance reached over https therefore sends
/// `__Secure-better-auth.session_token`, and a self-hosted one cannot opt out:
/// the OAuth spec (and Google's redirect-URI validation) requires an https
/// callback for anything but localhost, so the single variable that makes login
/// work also renames this cookie. Matching only the bare name meant session auth
/// could never succeed on a TLS deployment.
///
/// Bare name first: it is what an http/localhost install sends, and checking it
/// first keeps that path a single comparison.
fn session_token_from_cookies(cookie_header: &str) -> Option<&str> {
    parse_cookie(cookie_header, "better-auth.session_token")
        .or_else(|| parse_cookie(cookie_header, "__Secure-better-auth.session_token"))
}

/// The stored token half of a Better Auth session cookie.
///
/// The value is NOT a JWT. Better Auth writes it with `setSignedCookie`, which
/// emits `encodeURIComponent("<token>.<base64 HMAC-SHA256>")` — only `<token>`
/// is what `auth_sessions.token` holds. Split on the LAST `.` so a token that
/// ever gains one of its own still resolves; percent-encoding cannot confuse
/// that, since it never emits a `.` and never escapes one. The token's own
/// alphabet is `[a-zA-Z0-9]`, so it survives the encoding unchanged and needs no
/// decoding before the lookup.
///
/// A value with no `.` is passed through whole rather than rejected: it simply
/// will not match a stored token, and letting the database be the only authority
/// keeps one place able to say yes.
///
/// The signature is not verified. Doing so would buy nothing here — it proves
/// the cookie was minted by something holding `AUTH_SECRET`, whereas the lookup
/// already proves the stronger thing, that the session is real and live; and an
/// attacker who cannot produce a signature cannot produce a valid token either.
/// It would, however, add a second thing that must match the web app exactly
/// (secret byte-for-byte, standard-base64 padding, percent-decoding first) whose
/// failure mode is rejecting every valid session.
fn session_token_value(cookie_value: &str) -> &str {
    match cookie_value.rsplit_once('.') {
        Some((token, _signature)) => token,
        None => cookie_value,
    }
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

    /// A realistic cookie value: the 32-char token, then the percent-encoded
    /// base64 signature (`/` → `%2F`, `+` → `%2B`, the `=` pad → `%3D`).
    const SIGNED: &str =
        "Xk3pQz7RtV1aB2cD4eF5gH6iJ8kL9mN0.9Xq%2Fz1c%2BAbC3dEfGhIjKlMnOpQrStUvWxYz0123%3D";

    #[test]
    fn parse_cookie_finds_value() {
        let header = "other=abc; better-auth.session_token=tok.sig; path=/";
        assert_eq!(
            parse_cookie(header, "better-auth.session_token"),
            Some("tok.sig")
        );
    }

    #[test]
    fn parse_cookie_missing() {
        let header = "other=abc; foo=bar";
        assert_eq!(parse_cookie(header, "better-auth.session_token"), None);
    }

    #[test]
    fn parse_cookie_empty() {
        assert_eq!(parse_cookie("", "better-auth.session_token"), None);
    }

    #[test]
    fn session_token_accepts_bare_name() {
        let header = format!("other=abc; better-auth.session_token={SIGNED}");
        assert_eq!(session_token_from_cookies(&header), Some(SIGNED));
    }

    /// What a browser sends to an https deployment: Better Auth switches the
    /// session cookie to the `__Secure-` prefix.
    #[test]
    fn session_token_accepts_secure_prefixed_name() {
        let header = format!("other=abc; __Secure-better-auth.session_token={SIGNED}");
        assert_eq!(session_token_from_cookies(&header), Some(SIGNED));
    }

    /// The bare name wins when both are somehow present, so an http install's
    /// behaviour is unchanged.
    #[test]
    fn session_token_prefers_bare_name() {
        let header = "__Secure-better-auth.session_token=prefixed.sig; \
                      better-auth.session_token=bare.sig";
        assert_eq!(session_token_from_cookies(header), Some("bare.sig"));
    }

    #[test]
    fn session_token_missing() {
        assert_eq!(session_token_from_cookies("other=abc; foo=bar"), None);
    }

    /// The signature — percent-encoded base64, which can hold `%2F`/`%2B`/`%3D`
    /// but never a `.` — is dropped, leaving exactly what `auth_sessions.token`
    /// stores.
    #[test]
    fn session_token_value_strips_signature() {
        assert_eq!(
            session_token_value(SIGNED),
            "Xk3pQz7RtV1aB2cD4eF5gH6iJ8kL9mN0"
        );
    }

    /// Splitting on the LAST `.`, not the first: a token carrying dots of its own
    /// must still come back whole.
    #[test]
    fn session_token_value_splits_on_last_dot() {
        assert_eq!(session_token_value("a.b.c.signature"), "a.b.c");
    }

    /// An unsigned-looking value is passed through, not truncated to nothing —
    /// the lookup rejects it.
    #[test]
    fn session_token_value_without_signature_passes_through() {
        assert_eq!(
            session_token_value("Xk3pQz7RtV1aB2cD4eF5gH6iJ8kL9mN0"),
            "Xk3pQz7RtV1aB2cD4eF5gH6iJ8kL9mN0"
        );
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
