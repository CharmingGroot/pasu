//! pasu-rules — the concrete `RuleEngine`.
//!
//! A small, Falco-inspired ruleset: an ordered list of rules, each a `match` +
//! `action` (allow / deny / ask). The first matching rule wins; if none match,
//! the ruleset's `default` action applies — **fail-closed (deny) by default**.
//! Rules load from YAML.
//!
//! The Falco dependency (its rich condition language, macros, lists) is a future
//! extension; this MVP keeps a minimal matcher. Isolating the engine here keeps
//! the trait's callers (pasu-rig, pasu-egress) decoupled from the rule format —
//! swap this for OPA / a DSL later without touching them. Design: docs/rules.md

use pasu_core::{Event, EventKind, RuleEngine, Verdict};
use serde::Deserialize;

/// What to do when a rule matches (or as the ruleset default).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    Ask,
}

/// A rule's match criteria. A rule matches an event when its set field matches:
/// `tool` against a tool call's name, `host` against an egress host (exact, or a
/// leading-dot suffix like `.openai.com` for domain matching).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Match {
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
}

/// A single rule: name + match + action (+ optional human-readable reason).
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(rename = "match")]
    pub matcher: Match,
    pub action: Action,
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_action() -> Action {
    Action::Deny
}

/// An ordered ruleset plus the default action for unmatched events.
#[derive(Debug, Clone, Deserialize)]
pub struct Ruleset {
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Action when no rule matches. Defaults to `deny` (fail-closed).
    #[serde(default = "default_action")]
    pub default: Action,
}

impl Match {
    fn matches(&self, event: &Event) -> bool {
        match &event.kind {
            EventKind::ToolCall { name, .. } => self.tool.as_deref() == Some(name.as_str()),
            EventKind::Egress { host, .. } => match self.host.as_deref() {
                // ".suffix" matches the domain and its subdomains.
                Some(h) if h.starts_with('.') => host == &h[1..] || host.ends_with(h),
                Some(h) => host == h,
                None => false,
            },
        }
    }
}

impl Action {
    fn to_verdict(self, reason: Option<&str>, rule_name: &str) -> Verdict {
        let why = reason
            .map(str::to_string)
            .unwrap_or_else(|| format!("rule: {rule_name}"));
        match self {
            Action::Allow => Verdict::Allow,
            Action::Deny => Verdict::Deny(why),
            Action::Ask => Verdict::Ask(why),
        }
    }
}

/// `RuleEngine` backed by an ordered ruleset (first match wins, else default).
pub struct RulesetEngine {
    ruleset: Ruleset,
}

impl RulesetEngine {
    pub fn new(ruleset: Ruleset) -> Self {
        Self { ruleset }
    }

    /// Load a ruleset from YAML.
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        Ok(Self::new(serde_yaml::from_str(yaml)?))
    }
}

impl RuleEngine for RulesetEngine {
    fn evaluate(&self, event: &Event) -> Verdict {
        for rule in &self.ruleset.rules {
            if rule.matcher.matches(event) {
                return rule.action.to_verdict(rule.reason.as_deref(), &rule.name);
            }
        }
        self.ruleset.default.to_verdict(None, "default")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
rules:
  - name: allow-llm
    match: { host: "api.openai.com" }
    action: allow
  - name: block-rm
    match: { tool: "rm_rf" }
    action: deny
    reason: "destructive tool"
  - name: confirm-transfer
    match: { tool: "transfer_funds" }
    action: ask
default: deny
"#;

    fn engine() -> RulesetEngine {
        RulesetEngine::from_yaml(YAML).expect("valid yaml")
    }

    fn tool(name: &str) -> Event {
        Event {
            kind: EventKind::ToolCall {
                name: name.to_string(),
                input: "{}".into(),
            },
        }
    }

    fn egress(host: &str) -> Event {
        Event {
            kind: EventKind::Egress {
                host: host.to_string(),
                port: 443,
            },
        }
    }

    #[test]
    fn allows_matching_host() {
        assert!(matches!(
            engine().evaluate(&egress("api.openai.com")),
            Verdict::Allow
        ));
    }

    #[test]
    fn denies_matching_tool_with_reason() {
        match engine().evaluate(&tool("rm_rf")) {
            Verdict::Deny(why) => assert_eq!(why, "destructive tool"),
            v => panic!("expected Deny, got {v:?}"),
        }
    }

    #[test]
    fn asks_for_transfer() {
        assert!(matches!(
            engine().evaluate(&tool("transfer_funds")),
            Verdict::Ask(_)
        ));
    }

    #[test]
    fn unmatched_events_hit_default_deny() {
        assert!(matches!(
            engine().evaluate(&egress("evil.example")),
            Verdict::Deny(_)
        ));
        assert!(matches!(
            engine().evaluate(&tool("some_other_tool")),
            Verdict::Deny(_)
        ));
    }

    #[test]
    fn suffix_host_matches_domain_and_subdomains() {
        let e = RulesetEngine::from_yaml(
            "rules:\n  - name: s\n    match: { host: \".openai.com\" }\n    action: allow\ndefault: deny",
        )
        .unwrap();
        assert!(matches!(e.evaluate(&egress("openai.com")), Verdict::Allow));
        assert!(matches!(
            e.evaluate(&egress("api.openai.com")),
            Verdict::Allow
        ));
        assert!(matches!(
            e.evaluate(&egress("evil.example")),
            Verdict::Deny(_)
        ));
    }

    #[test]
    fn empty_ruleset_defaults_to_deny() {
        let e = RulesetEngine::from_yaml("rules: []").unwrap();
        assert!(matches!(e.evaluate(&tool("anything")), Verdict::Deny(_)));
    }
}
