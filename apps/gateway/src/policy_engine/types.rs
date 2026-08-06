//! Shapes for the OSS project-level policy core: the decoded rule, the request
//! context, and the evaluation outcome.

/// The rule verdict. Approval and rate limits are modifiers on `Allow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    Allow,
    Block,
}

/// A rate-limit window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RateWindow {
    Minute,
    Hour,
    Day,
}

impl RateWindow {
    pub(super) fn secs(self) -> u64 {
        match self {
            RateWindow::Minute => 60,
            RateWindow::Hour => 3600,
            RateWindow::Day => 86400,
        }
    }
}

/// A rule identity. OSS rules target a specific agent or all agents (empty
/// identity list = "any"). `Other` covers stored non-agent identity rows and
/// never matches, so such a row narrows to nothing rather than widening to
/// "any".
#[derive(Debug, Clone)]
pub(super) enum Identity {
    Agent(String),
    Other,
}

/// A rule target. `App` expands its provider/tool set through the catalog to an
/// endpoint fan-out (empty tools = the whole app, host-only); `Secret` gates its
/// resolved host pattern(s); `Unresolved` is the fail-closed arm for anything
/// that cannot be resolved (unknown kind, provider-less app row, an id absent
/// from the fenced connect-time maps) and never matches.
#[derive(Debug, Clone)]
pub(super) enum Target {
    Network {
        host_pattern: String,
        path_pattern: Option<String>,
        method: Option<String>,
    },
    App {
        provider: String,
        tools: Vec<String>,
    },
    /// Matches only when this is the request's winning injected connection and
    /// the provider/tools fan-out hits; no winner never matches, for allow as
    /// well as block.
    Connection {
        id: String,
        provider: String,
        tools: Vec<String>,
    },
    Secret {
        host_patterns: Vec<String>,
    },
    Unresolved,
}

/// A decoded project rule the evaluator walks.
#[derive(Debug, Clone)]
pub(super) struct Rule {
    pub id: String,
    /// Generation-stable identity — the shared rate counter keys on it, so the
    /// count survives republishes.
    pub logical_id: String,
    pub name: String,
    pub priority: usize,
    pub is_default: bool,
    pub identities: Vec<Identity>,
    pub targets: Vec<Target>,
    pub action: Action,
    pub require_approval: bool,
    pub rate_limit: Option<u64>,
    pub rate_limit_window: Option<RateWindow>,
    /// Routed through the edition-swapped `condition_match`, whose OSS arm is a
    /// no-op — conditions are never evaluated here.
    pub conditions: Option<serde_json::Value>,
}

/// The request context one decision runs against. `host` is port-stripped by
/// the caller.
#[derive(Debug, Clone)]
pub(super) struct Request {
    pub host: String,
    pub path: String,
    pub method: String,
    pub agent_id: String,
    /// A credential was injected for this host — the deny-default precondition.
    pub has_injections: bool,
    /// Host is a known LLM provider — bypasses deny-default.
    pub is_llm_host: bool,
    /// The app connection that won injection for this request; `None` when no
    /// connection serves it. `Target::Connection` matches only against this id.
    pub winning_connection_id: Option<String>,
}

impl Request {
    /// The deny-default carve: only credentialed, non-LLM traffic can be
    /// blocked by the Default Rule.
    pub(super) fn enforce_deny(&self) -> bool {
        self.has_injections && !self.is_llm_host
    }
}

/// The winning outcome of an evaluation: an explicit matching rule, the project
/// Default Rule's enforced Block (carrying that rule so telemetry can attribute
/// it), or a plain allow.
pub(super) enum Outcome<'a> {
    Rule(&'a Rule),
    DenyDefault(&'a Rule),
    Allow,
}
