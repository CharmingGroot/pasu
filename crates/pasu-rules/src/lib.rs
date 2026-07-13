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

use std::net::Ipv4Addr;

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

/// The kernel-enforceable part of a ruleset: the egress allowlist derived from
/// its `allow` rules. This is how "one policy file" reaches the eBPF layer —
/// the same YAML the rig hook evaluates is *lowered* to the kernel's
/// default-deny allowlist.
#[derive(Debug, Default, PartialEq)]
pub struct EgressAllowlist {
    /// Host entries that parse as IPv4 — injected as static allow entries.
    pub ips: Vec<Ipv4Addr>,
    /// Exact hostnames — resolved (and periodically re-resolved) to IPv4s.
    pub domains: Vec<String>,
    /// Allow rules the kernel layer cannot express, with the reason. These stay
    /// enforced at the hook layer only — surface them to the operator.
    pub skipped: Vec<SkippedRule>,
}

/// An allow rule that could not be lowered to the kernel layer.
#[derive(Debug, PartialEq)]
pub struct SkippedRule {
    pub rule: String,
    pub reason: String,
}

/// A ruleset whose `default` is `allow` cannot be lowered: the kernel layer is
/// default-deny, and silently enforcing deny would invert the operator's policy.
#[derive(Debug, PartialEq)]
pub struct DefaultAllowError;

impl std::fmt::Display for DefaultAllowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "policy default is `allow`, but the kernel egress layer is default-deny; \
             set `default: deny` (fail-closed) to run it"
        )
    }
}

impl std::error::Error for DefaultAllowError {}

const SUFFIX_SKIP_REASON: &str = "suffix host patterns cannot be enumerated in the kernel \
     (needs DNS-response sniffing); enforced at the hook layer only";

impl Ruleset {
    /// Load a ruleset from YAML (the same document `RulesetEngine::from_yaml` reads).
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    /// Lower this ruleset to the kernel egress allowlist.
    ///
    /// Only `allow` rules with a `host` matcher participate: an IPv4 literal
    /// becomes a static allow, an exact hostname becomes a DNS-resolved allow,
    /// and a `.suffix` pattern is reported as skipped (the kernel cannot
    /// enumerate it). `deny`/`ask` rules need no lowering — the kernel is
    /// default-deny, so anything not allowed is already dropped.
    pub fn egress_allowlist(&self) -> Result<EgressAllowlist, DefaultAllowError> {
        if matches!(self.default, Action::Allow) {
            return Err(DefaultAllowError);
        }
        let mut out = EgressAllowlist::default();
        for rule in &self.rules {
            if !matches!(rule.action, Action::Allow) {
                continue;
            }
            let Some(host) = rule.matcher.host.as_deref() else {
                continue; // tool-only rule: nothing to lower
            };
            if host.starts_with('.') {
                out.skipped.push(SkippedRule {
                    rule: rule.name.clone(),
                    reason: SUFFIX_SKIP_REASON.to_string(),
                });
            } else if let Ok(ip) = host.parse::<Ipv4Addr>() {
                out.ips.push(ip);
            } else {
                out.domains.push(host.to_string());
            }
        }
        Ok(out)
    }
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

    // --- egress_allowlist: lowering the same YAML to the kernel layer ---

    #[test]
    fn lowers_ip_exact_host_and_suffix_allow_rules() {
        let rs = Ruleset::from_yaml(
            r#"
rules:
  - name: allow-dns
    match: { host: "1.1.1.1" }
    action: allow
  - name: allow-llm
    match: { host: "api.openai.com" }
    action: allow
  - name: allow-suffix
    match: { host: ".anthropic.com" }
    action: allow
default: deny
"#,
        )
        .unwrap();
        let out = rs.egress_allowlist().unwrap();
        assert_eq!(out.ips, vec![Ipv4Addr::new(1, 1, 1, 1)]);
        assert_eq!(out.domains, vec!["api.openai.com".to_string()]);
        assert_eq!(out.skipped.len(), 1);
        assert_eq!(out.skipped[0].rule, "allow-suffix");
    }

    #[test]
    fn deny_ask_and_tool_only_rules_do_not_lower() {
        // TN pair: nothing here may widen the kernel allowlist.
        let rs = Ruleset::from_yaml(
            r#"
rules:
  - name: deny-exfil
    match: { host: "evil.example" }
    action: deny
  - name: ask-host
    match: { host: "review.example" }
    action: ask
  - name: allow-tool
    match: { tool: "read_file" }
    action: allow
default: deny
"#,
        )
        .unwrap();
        let out = rs.egress_allowlist().unwrap();
        assert_eq!(out, EgressAllowlist::default());
    }

    #[test]
    fn tool_scoped_host_allow_still_lowers() {
        // A rule with both matchers allows the host for ANY egress event (the
        // matcher is per-event-kind), so the kernel entry is not a widening.
        let rs = Ruleset::from_yaml(
            "rules:\n  - name: combo\n    match: { tool: fetch, host: \"api.example\" }\n    action: allow\ndefault: deny",
        )
        .unwrap();
        let out = rs.egress_allowlist().unwrap();
        assert_eq!(out.domains, vec!["api.example".to_string()]);
    }

    #[test]
    fn default_allow_refuses_to_lower() {
        // fail-closed: the kernel layer cannot express a default-allow policy.
        let rs = Ruleset::from_yaml("rules: []\ndefault: allow").unwrap();
        assert_eq!(rs.egress_allowlist(), Err(DefaultAllowError));
    }
}
