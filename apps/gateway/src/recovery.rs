//! Emergency recovery key minting.
//!
//! Break-glass access for an operator whose identity provider is broken. Kept
//! in the gateway binary because that binary is self-contained: it needs only
//! `DATABASE_URL`, so it still runs when the web container will not start,
//! which is the situation recovery exists for.
//!
//! Reachable only by someone who can start a container against this database.
//! That host access is the gate — the printed link is a bearer credential and
//! is short-lived and single-use precisely because it is one.

use anyhow::{Context, Result};
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

use crate::db;

/// Long enough that guessing is hopeless against a token that also expires in
/// minutes and dies on first use.
const TOKEN_BYTES: usize = 32;

/// Hex SHA-256, matching what the web app computes when redeeming.
pub(crate) fn hash_token(token: &str) -> String {
    hex::encode(digest::digest(&digest::SHA256, token.as_bytes()))
}

fn generate_token() -> Result<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("system RNG unavailable"))?;
    Ok(hex::encode(bytes))
}

/// Mint a key for `email` and print the link that redeems it.
///
/// Printed to stdout rather than the log: the log is shipped, and this is a
/// credential.
pub(crate) async fn create_recovery_key(
    database_url: &str,
    email: &str,
    ttl_minutes: i32,
) -> Result<()> {
    if ttl_minutes < 1 {
        anyhow::bail!("ttl must be at least 1 minute");
    }

    let pool = db::create_pool(database_url).await?;
    let token = generate_token()?;

    let created = db::insert_recovery_token(&pool, email, &hash_token(&token), ttl_minutes)
        .await
        .context("storing the recovery key")?;
    pool.close().await;

    if !created {
        anyhow::bail!("no user with email {email}");
    }

    // Trailing slash stripped: APP_URL is operator-supplied and a doubled slash
    // would not match the route.
    let base = std::env::var("APP_URL")
        .unwrap_or_else(|_| "http://localhost:10254".to_string())
        .trim_end_matches('/')
        .to_string();

    println!("Recovery link for {email}, valid {ttl_minutes} minute(s), single use:");
    println!();
    println!("  {base}/auth/recovery?key={token}");
    println!();
    println!("Anyone holding this link can sign in as {email}. It is not recoverable");
    println!("once this output is lost — mint another instead.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known answer, asserted identically in `redeem-recovery-key.pg.test.ts`.
    /// If the two drift, every minted key silently fails to redeem.
    #[test]
    fn hash_matches_the_web_app() {
        assert_eq!(
            hash_token("onecli-recovery-known-answer"),
            "f1bb0f5f4e8fa2cadabd895af06faec86b6ef2e60d7d680a67c05c72c46def41"
        );
    }

    #[test]
    fn tokens_are_unpredictable_and_full_length() {
        let a = generate_token().expect("token");
        let b = generate_token().expect("token");
        assert_eq!(a.len(), TOKEN_BYTES * 2, "hex of {TOKEN_BYTES} bytes");
        assert_ne!(a, b);
    }
}
