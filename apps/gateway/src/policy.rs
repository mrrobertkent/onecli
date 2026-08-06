//! Policy rule evaluation for the gateway.
//!
//! Policy rules control access to upstream endpoints:
//! - **Block**: returns 403 Forbidden
//! - **Rate limit**: allows up to N requests per time window, then 429
//! - **Allow**: explicitly permits a request (used in deny-by-default mode)

use tracing::warn;

use crate::cache::CacheStore;
use crate::inject::path_matches;

// ── Data types ──────────────────────────────────────────────────────────

/// What action to take when a request matches a policy rule.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum PolicyAction {
    Block,
    RateLimit {
        rule_id: String,
        max_requests: u64,
        window_secs: u64,
    },
    ManualApproval {
        rule_id: String,
    },
    Allow,
}

/// A resolved policy rule ready for evaluation.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PolicyRule {
    pub name: String,
    pub path_pattern: String,
    pub method: Option<String>,
    pub action: PolicyAction,
    #[serde(default)]
    pub conditions_raw: Option<serde_json::Value>,
}

/// The rule that decided a request, recorded into telemetry.
///
/// `logical_id` stays stable across publishes (row ids do not); `name` is a
/// display snapshot; `scope` is "organization" or "project", which the read
/// side uses to apply per-viewer visibility to org rule names.
#[derive(Debug, Clone)]
pub(crate) struct MatchedRule {
    pub(crate) logical_id: String,
    #[allow(dead_code)] // read by cloud telemetry (extra_data), unused in OSS
    pub(crate) name: String,
    #[allow(dead_code)] // read by cloud telemetry (extra_data), unused in OSS
    pub(crate) scope: String,
}

/// Result of policy evaluation for a single request.
#[derive(Debug)]
pub(crate) enum PolicyDecision {
    /// Request is allowed.
    Allow,
    /// Request is blocked by a block rule.
    Blocked { rule_name: String },
    /// Request exceeds a rate limit.
    RateLimited {
        rule_name: String,
        limit: u64,
        window: &'static str,
        retry_after_secs: u64,
    },
    /// Request requires manual approval before proceeding.
    ManualApproval { rule_id: String },
    /// Request blocked because no allow rule matched in deny-by-default mode.
    BlockedByDefaultPolicy,
}

// ── Evaluation ──────────────────────────────────────────────────────────

/// Increment the rate counter for a matched rate-limit rule and return a
/// `RateLimited` decision once the request is over the limit (`None` while it
/// is under). Shared by every caller so the key structure and window math stay
/// identical; `rule_id` is the caller's rule identity, so passing a stable
/// logical id keeps a rule's counter across republishes.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn check_rate_limit(
    org_id: &str,
    project_id: &str,
    rule_id: &str,
    rule_name: &str,
    max_requests: u64,
    window_secs: u64,
    agent_token: &str,
    cache: &dyn CacheStore,
) -> Option<PolicyDecision> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let window_id = now / window_secs.max(1);
    let key = format!("rate:{org_id}:{project_id}:{rule_id}:{agent_token}:{window_id}");

    match cache.incr(&key, window_secs).await {
        Some(count) if count > max_requests => {
            let window_end = (window_id + 1) * window_secs;
            Some(PolicyDecision::RateLimited {
                rule_name: rule_name.to_string(),
                limit: max_requests,
                window: rate_window_name(window_secs),
                retry_after_secs: window_end.saturating_sub(now),
            })
        }
        Some(_) => None,
        None => {
            warn!(rule = %rule_name, "policy: rate limit cache unavailable, allowing through");
            None
        }
    }
}

fn rate_window_name(window_secs: u64) -> &'static str {
    match window_secs {
        60 => "minute",
        3600 => "hour",
        86400 => "day",
        _ => "window",
    }
}

/// Check if a rule matches the request method, path, and conditions.
///
/// Shared with the policy engine so the live decision uses this matcher rather
/// than a copy of it.
pub(crate) fn matches_request(
    rule: &PolicyRule,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> bool {
    let direct = path_matches(path, &rule.path_pattern)
        && rule
            .method
            .as_ref()
            .is_none_or(|m| m.eq_ignore_ascii_case(method))
        && crate::condition_match::matches(rule, body);
    if direct {
        return true;
    }
    // Git push is two-phase: a GET info/refs?service=git-receive-pack discovery
    // followed by POST git-receive-pack. A rule blocking the POST should also
    // block the discovery.
    if rule.path_pattern.ends_with("/git-receive-pack")
        && method.eq_ignore_ascii_case("GET")
        && is_git_push_discovery(path)
    {
        return crate::condition_match::matches(rule, body);
    }
    false
}

/// Returns true if the request path is a git push discovery request
/// (`/info/refs?service=git-receive-pack`).
fn is_git_push_discovery(path: &str) -> bool {
    let (base, query) = path.split_once('?').unwrap_or((path, ""));
    base.ends_with("/info/refs") && query.split('&').any(|p| p == "service=git-receive-pack")
}

/// Returns true if the host belongs to a known LLM provider.
/// LLM traffic bypasses deny-by-default policy and is always logged.
pub(crate) fn is_llm_host(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or(host);
    h.contains("anthropic.com")
        || h.contains("openai.com")
        || h.contains("chatgpt.com")
        || h.contains("deepseek.com")
        || h.contains("groq.com")
        || h.contains("openrouter.ai")
        || h.contains("moonshot.cn")
        || h.contains("generativelanguage.googleapis.com")
}

/// Check if a request should be blocked by any policy rule (sync, block-only).
/// A test-only helper; the live decision path is `policy_engine::evaluate`.
#[allow(dead_code)]
pub(crate) fn is_blocked(
    request_method: &str,
    request_path: &str,
    request_body: Option<&[u8]>,
    rules: &[PolicyRule],
) -> bool {
    rules.iter().any(|rule| {
        matches!(rule.action, PolicyAction::Block)
            && matches_request(rule, request_method, request_path, request_body)
    })
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn block_rule(path: &str, method: Option<&str>) -> PolicyRule {
        PolicyRule {
            name: "Test block rule".to_string(),
            path_pattern: path.to_string(),
            method: method.map(|m| m.to_string()),
            action: PolicyAction::Block,
            conditions_raw: None,
        }
    }

    // ── Block tests ──────────────────────────────────────────────────────

    #[test]
    fn blocks_exact_path_and_method() {
        let rules = vec![block_rule("/gmail/v1/users/me/messages/send", Some("POST"))];
        assert!(is_blocked(
            "POST",
            "/gmail/v1/users/me/messages/send",
            None,
            &rules
        ));
    }

    #[test]
    fn allows_different_method() {
        let rules = vec![block_rule("/gmail/v1/users/me/messages/send", Some("POST"))];
        assert!(!is_blocked(
            "GET",
            "/gmail/v1/users/me/messages/send",
            None,
            &rules
        ));
    }

    #[test]
    fn allows_different_path() {
        let rules = vec![block_rule("/gmail/v1/users/me/messages/send", Some("POST"))];
        assert!(!is_blocked(
            "POST",
            "/gmail/v1/users/me/messages",
            None,
            &rules
        ));
    }

    #[test]
    fn blocks_all_methods_when_none() {
        let rules = vec![block_rule("/admin/*", None)];
        assert!(is_blocked("GET", "/admin/users", None, &rules));
        assert!(is_blocked("POST", "/admin/users", None, &rules));
        assert!(is_blocked("DELETE", "/admin/settings", None, &rules));
    }

    #[test]
    fn blocks_wildcard_path() {
        let rules = vec![block_rule("/gmail/*", Some("POST"))];
        assert!(is_blocked(
            "POST",
            "/gmail/v1/users/me/messages/send",
            None,
            &rules
        ));
        assert!(!is_blocked("POST", "/calendar/v1/events", None, &rules));
    }

    #[test]
    fn blocks_all_paths() {
        let rules = vec![block_rule("*", Some("DELETE"))];
        assert!(is_blocked("DELETE", "/anything", None, &rules));
        assert!(!is_blocked("GET", "/anything", None, &rules));
    }

    #[test]
    fn method_matching_is_case_insensitive() {
        let rules = vec![block_rule("*", Some("POST"))];
        assert!(is_blocked("post", "/path", None, &rules));
        assert!(is_blocked("Post", "/path", None, &rules));
    }

    #[test]
    fn no_rules_allows_everything() {
        assert!(!is_blocked("POST", "/anything", None, &[]));
    }

    #[test]
    fn blocks_with_default_wildcard_path() {
        let rules = vec![block_rule("*", Some("POST"))];
        assert!(is_blocked("POST", "/any/path/here", None, &rules));
        assert!(is_blocked("POST", "/", None, &rules));
    }

    #[test]
    fn multiple_rules_any_match_blocks() {
        let rules = vec![
            block_rule("/safe/*", Some("GET")),
            block_rule("/danger/*", Some("POST")),
        ];
        assert!(!is_blocked("POST", "/safe/path", None, &rules));
        assert!(is_blocked("POST", "/danger/path", None, &rules));
    }

    // ── Git push discovery tests ────────────────────────────────────

    #[test]
    fn git_push_block_also_blocks_discovery() {
        let rules = vec![block_rule("/*/*/git-receive-pack", Some("POST"))];
        assert!(is_blocked(
            "GET",
            "/owner/repo.git/info/refs?service=git-receive-pack",
            None,
            &rules
        ));
    }

    #[test]
    fn git_push_block_does_not_block_clone_discovery() {
        let rules = vec![block_rule("/*/*/git-receive-pack", Some("POST"))];
        assert!(!is_blocked(
            "GET",
            "/owner/repo.git/info/refs?service=git-upload-pack",
            None,
            &rules
        ));
    }

    #[test]
    fn git_push_block_still_blocks_receive_pack_post() {
        let rules = vec![block_rule("/*/*/git-receive-pack", Some("POST"))];
        assert!(is_blocked(
            "POST",
            "/owner/repo.git/git-receive-pack",
            None,
            &rules
        ));
    }

    // ── LLM host detection tests ────────────────────────────────────

    #[test]
    fn is_llm_host_matches_known_providers() {
        assert!(is_llm_host("api.anthropic.com"));
        assert!(is_llm_host("api.openai.com"));
        assert!(is_llm_host("chatgpt.com"));
        assert!(is_llm_host("api.deepseek.com"));
        assert!(is_llm_host("api.groq.com"));
        assert!(is_llm_host("openrouter.ai"));
        assert!(is_llm_host("api.moonshot.cn"));
        assert!(is_llm_host("generativelanguage.googleapis.com"));
    }

    #[test]
    fn is_llm_host_strips_port() {
        assert!(is_llm_host("api.anthropic.com:443"));
    }

    #[test]
    fn is_llm_host_rejects_non_llm() {
        assert!(!is_llm_host("api.github.com"));
        assert!(!is_llm_host("gmail.googleapis.com"));
        assert!(!is_llm_host("example.com"));
    }
}
