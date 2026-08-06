//! The OSS first-match evaluator, one level (project): the first matching rule
//! decides, else the project Default Rule is the terminal (its Block gated by
//! the `enforce_deny` carve), else allow.
//!
//! Matching routes through the gateway's own `connect::host_matches` +
//! `policy::matches_request`, so path globs, methods and the git-receive-pack
//! bridge behave identically here.

use crate::policy::{matches_request, PolicyAction, PolicyRule};

use super::types::{Identity, Outcome, Request, Rule, Target};

/// Empty identities = "any agent"; an `Agent` identity matches by id; `Other`
/// (a stored directory identity) never matches.
fn identity_matches(rule: &Rule, request: &Request) -> bool {
    rule.identities.is_empty()
        || rule.identities.iter().any(|i| match i {
            Identity::Agent(id) => *id == request.agent_id,
            Identity::Other => false,
        })
}

/// A throwaway `policy::PolicyRule` so the network match runs the gateway's
/// exact `matches_request` (the action is irrelevant to matching).
fn pseudo_rule(
    path_pattern: Option<&str>,
    method: Option<String>,
    conditions: &Option<serde_json::Value>,
) -> PolicyRule {
    PolicyRule {
        name: String::new(),
        path_pattern: path_pattern.unwrap_or("*").to_string(),
        method,
        action: PolicyAction::Allow,
        conditions_raw: conditions.clone(),
    }
}

fn target_matches(target: &Target, rule: &Rule, request: &Request, body: Option<&[u8]>) -> bool {
    match target {
        Target::Network {
            host_pattern,
            path_pattern,
            method,
        } => {
            crate::connect::host_matches(&request.host, host_pattern)
                && matches_request(
                    &pseudo_rule(path_pattern.as_deref(), method.clone(), &rule.conditions),
                    &request.method,
                    &request.path,
                    body,
                )
        }
        Target::App { provider, tools } => super::catalog::app_target_matches(
            provider,
            tools,
            &request.host,
            &request.method,
            &request.path,
            body,
            &rule.conditions,
        ),
        // Matches only when this is the request's winning injected connection
        // and the provider/tools fan-out hits; no winner never matches.
        Target::Connection {
            id,
            provider,
            tools,
        } => {
            request.winning_connection_id.as_deref() == Some(id.as_str())
                && super::catalog::app_target_matches(
                    provider,
                    tools,
                    &request.host,
                    &request.method,
                    &request.path,
                    body,
                    &rule.conditions,
                )
        }
        // Gates its resolved host(s), host-only. Empty patterns (unresolved or
        // deleted secret) never match.
        Target::Secret { host_patterns } => host_patterns
            .iter()
            .any(|h| crate::connect::host_matches(&request.host, h)),
        Target::Unresolved => false,
    }
}

/// A non-default rule matches only when it names at least one target and one of
/// them matches. Empty targets match nothing — "match everything" is the Default
/// Rule's job — which also neutralizes a rule orphaned to zero targets.
fn rule_matches(rule: &Rule, request: &Request, body: Option<&[u8]>) -> bool {
    identity_matches(rule, request)
        && !rule.targets.is_empty()
        && rule
            .targets
            .iter()
            .any(|t| target_matches(t, rule, request, body))
}

/// First matching non-default rule in `(priority, id)` order. The id tie-break
/// makes equal priorities deterministic and agrees with the query's
/// `ORDER BY r.priority, r.id`: ids are lowercase-hex UUIDs, so Rust byte order
/// equals the Postgres collation.
fn first_match<'a>(rules: &'a [Rule], request: &Request, body: Option<&[u8]>) -> Option<&'a Rule> {
    let mut ordered: Vec<&'a Rule> = rules.iter().filter(|r| !r.is_default).collect();
    ordered.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
    ordered
        .into_iter()
        .find(|rule| rule_matches(rule, request, body))
}

/// Decide the request: the first matching rule wins (an explicit allow opens
/// its own Default-Block, allowlist-style); otherwise the project Default Rule
/// is the terminal, its Block enforced only under the `enforce_deny` carve;
/// otherwise allow.
pub(super) fn evaluate_outcome<'a>(
    rules: &'a [Rule],
    request: &Request,
    body: Option<&[u8]>,
) -> Outcome<'a> {
    if let Some(rule) = first_match(rules, request, body) {
        return Outcome::Rule(rule);
    }
    let default = rules.iter().find(|r| r.is_default);
    if let Some(d) = default {
        if d.action == super::types::Action::Block && request.enforce_deny() {
            return Outcome::DenyDefault(d);
        }
    }
    Outcome::Allow
}

#[cfg(test)]
mod tests {
    use super::super::types::{Action, RateWindow};
    use super::*;

    fn rule(id: &str, priority: usize, action: Action) -> Rule {
        Rule {
            id: id.to_string(),
            logical_id: format!("l-{id}"),
            name: id.to_string(),
            priority,
            is_default: false,
            identities: Vec::new(),
            targets: vec![Target::Network {
                host_pattern: "api.example.com".to_string(),
                path_pattern: None,
                method: None,
            }],
            action,
            require_approval: false,
            rate_limit: None,
            rate_limit_window: None,
            conditions: None,
        }
    }

    fn default_rule(action: Action) -> Rule {
        let mut r = rule("default", 99, action);
        r.is_default = true;
        r.targets = Vec::new();
        r
    }

    fn request() -> Request {
        Request {
            host: "api.example.com".to_string(),
            path: "/x".to_string(),
            method: "GET".to_string(),
            agent_id: "agent-1".to_string(),
            has_injections: false,
            is_llm_host: false,
            winning_connection_id: None,
        }
    }

    fn injected_request() -> Request {
        Request {
            has_injections: true,
            ..request()
        }
    }

    /// A `Connection` target matches iff the request's winning injected
    /// connection is its id and the provider catalog fan-out hits.
    #[test]
    fn connection_target_binds_to_the_winning_connection() {
        let conn_block = |id: &str| {
            let mut r = rule("c-rule", 1, Action::Block);
            r.targets = vec![Target::Connection {
                id: id.to_string(),
                provider: "gmail".to_string(),
                tools: Vec::new(),
            }];
            r
        };
        let req_via = |winner: Option<&str>| Request {
            host: "gmail.googleapis.com".to_string(),
            path: "/gmail/v1/users/me/messages".to_string(),
            method: "GET".to_string(),
            agent_id: "agent-1".to_string(),
            has_injections: true,
            is_llm_host: false,
            winning_connection_id: winner.map(str::to_string),
        };
        let rules = vec![conn_block("c1")];

        // Matching winner on the provider's catalog host → the block binds.
        assert!(matches!(
            evaluate_outcome(&rules, &req_via(Some("c1")), None),
            Outcome::Rule(r) if r.action == Action::Block
        ));
        // A same-provider sibling account → no match.
        assert!(matches!(
            evaluate_outcome(&rules, &req_via(Some("c2")), None),
            Outcome::Allow
        ));
        // No winner (secret-served / uncredentialed) → no match.
        assert!(matches!(
            evaluate_outcome(&rules, &req_via(None), None),
            Outcome::Allow
        ));
        // Winner equality alone is not enough: a host outside the provider's
        // catalog fails the fan-out gate.
        let mut off_host = req_via(Some("c1"));
        off_host.host = "api.github.com".to_string();
        assert!(matches!(
            evaluate_outcome(&rules, &off_host, None),
            Outcome::Allow
        ));
    }

    #[test]
    fn first_match_wins_by_priority() {
        let rules = vec![rule("b", 1, Action::Block), rule("a", 0, Action::Allow)];
        match evaluate_outcome(&rules, &request(), None) {
            Outcome::Rule(r) => assert_eq!(r.id, "a"),
            _ => panic!("expected a rule match"),
        }
    }

    #[test]
    fn equal_priority_ties_break_by_id_regardless_of_input_order() {
        for rules in [
            vec![rule("a", 5, Action::Allow), rule("b", 5, Action::Block)],
            vec![rule("b", 5, Action::Block), rule("a", 5, Action::Allow)],
        ] {
            match evaluate_outcome(&rules, &request(), None) {
                Outcome::Rule(r) => assert_eq!(r.id, "a", "lower id wins the tie"),
                _ => panic!("expected a rule match"),
            }
        }
    }

    #[test]
    fn agent_identity_scopes_and_other_never_matches() {
        let mut agent_scoped = rule("scoped", 0, Action::Block);
        agent_scoped.identities = vec![Identity::Agent("agent-1".to_string())];
        let mut other = rule("directory", 1, Action::Block);
        other.identities = vec![Identity::Other];
        let allow = rule("any", 2, Action::Allow);

        let rules = vec![agent_scoped, other, allow];
        match evaluate_outcome(&rules, &request(), None) {
            Outcome::Rule(r) => assert_eq!(r.id, "scoped"),
            _ => panic!("expected the agent-scoped match"),
        }
        let mut foreign = request();
        foreign.agent_id = "agent-2".to_string();
        match evaluate_outcome(&rules, &foreign, None) {
            // The directory identity must not match — the any-agent allow wins.
            Outcome::Rule(r) => assert_eq!(r.id, "any"),
            _ => panic!("expected the any-agent match"),
        }
    }

    #[test]
    fn empty_target_rule_is_inert() {
        let mut orphan = rule("orphan", 0, Action::Block);
        orphan.targets = Vec::new();
        let control = rule("control", 1, Action::Allow);
        match evaluate_outcome(&[orphan, control], &request(), None) {
            Outcome::Rule(r) => assert_eq!(r.id, "control"),
            _ => panic!("expected the control match"),
        }
    }

    #[test]
    fn default_block_enforces_only_under_the_carve() {
        let rules = vec![default_rule(Action::Block)];
        // Uncredentialed → the carve spares it.
        assert!(matches!(
            evaluate_outcome(&rules, &request(), None),
            Outcome::Allow
        ));
        // Credentialed non-LLM → blocked, attributed to the Default Rule.
        match evaluate_outcome(&rules, &injected_request(), None) {
            Outcome::DenyDefault(d) => assert!(d.is_default),
            _ => panic!("expected the deny-default"),
        }
        // LLM host → spared.
        let mut llm = injected_request();
        llm.is_llm_host = true;
        assert!(matches!(
            evaluate_outcome(&rules, &llm, None),
            Outcome::Allow
        ));
    }

    #[test]
    fn explicit_allow_opens_the_default_block() {
        let rules = vec![rule("open", 0, Action::Allow), default_rule(Action::Block)];
        match evaluate_outcome(&rules, &injected_request(), None) {
            Outcome::Rule(r) => assert_eq!(r.id, "open"),
            _ => panic!("expected the allow rule to win over the default block"),
        }
    }

    #[test]
    fn default_allow_is_neutral() {
        let rules = vec![default_rule(Action::Allow)];
        assert!(matches!(
            evaluate_outcome(&rules, &injected_request(), None),
            Outcome::Allow
        ));
    }

    #[test]
    fn conditioned_rule_matches_with_no_body_in_oss() {
        // OSS's condition arm is the no-op, so a conditioned block matches
        // vacuously. If OSS ever ships real condition matching, this test flips.
        let mut conditioned = rule("cond", 0, Action::Block);
        conditioned.conditions = serde_json::from_str(
            r#"[{"target":"body","operator":"contains","value":"never-present"}]"#,
        )
        .ok();
        match evaluate_outcome(&[conditioned], &request(), None) {
            Outcome::Rule(r) => assert_eq!(r.id, "cond"),
            _ => panic!("expected the conditioned rule to match vacuously"),
        }
    }

    #[test]
    fn rate_window_secs_mapping() {
        assert_eq!(RateWindow::Minute.secs(), 60);
        assert_eq!(RateWindow::Hour.secs(), 3600);
        assert_eq!(RateWindow::Day.secs(), 86400);
    }
}
