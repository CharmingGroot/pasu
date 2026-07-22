//! pasu-rules — the concrete `RuleEngine`.
//!
//! A small, Falco-inspired ruleset: an ordered list of rules, each a `match` +
//! `action` (allow / deny / ask). The first matching rule wins; if none match,
//! the ruleset's `default` action applies — **fail-closed (deny) by default**.
//! Rules load from YAML.
//!
//! The Falco dependency (its rich condition language, macros, lists) is a future
//! extension; this MVP keeps a minimal matcher. Isolating the engine here keeps
//! the trait's callers (pasu-proxy, pasu-egress) decoupled from the rule format —
//! swap this for OPA / a DSL later without touching them. Design: docs/rules.md

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

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
/// the same YAML the proxy evaluates is *lowered* to the kernel's
/// default-deny allowlist.
#[derive(Debug, Default, PartialEq)]
pub struct EgressAllowlist {
    /// Host entries that parse as IPv4 — injected as static allow entries.
    pub ips: Vec<Ipv4Addr>,
    /// Host entries that parse as IPv6 — injected as static allow entries.
    pub ips6: Vec<Ipv6Addr>,
    /// Exact hostnames — resolved (and periodically re-resolved) to IPs.
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
            } else if let Ok(ip6) = host.parse::<Ipv6Addr>() {
                out.ips6.push(ip6);
            } else {
                out.domains.push(host.to_string());
            }
        }
        Ok(out)
    }

    /// Layer a `user` overlay on top of this (project baseline) ruleset.
    ///
    /// The overlay's rules take precedence: the engine is first-match, so the
    /// user's rules are evaluated *before* the baseline's and override them for
    /// the same target. The merged default action is the stricter of the two —
    /// `deny` wins (fail-closed). This is how `default/` (project, overwritten
    /// on upgrade) and `user/` (customization, preserved) compose without either
    /// clobbering the other; the caller supplies both paths.
    #[must_use]
    pub fn layered(mut self, user: Ruleset) -> Ruleset {
        let mut rules = user.rules;
        rules.append(&mut self.rules);
        let default = strictest(self.default, user.default);
        Ruleset { rules, default }
    }

    /// Load and concatenate every `*.yaml` / `*.yml` file in `dir`, sorted by
    /// file name — the `10-…`, `20-…` convention gives explicit ordering, like
    /// Falco's `rules.d` or `sudoers.d`. A missing directory yields an empty,
    /// fail-closed (`default: deny`) ruleset. Rules keep file order; the default
    /// is `deny` unless every file present declares `allow`.
    pub fn from_dir(dir: &Path) -> std::io::Result<Ruleset> {
        let mut files: Vec<PathBuf> = match std::fs::read_dir(dir) {
            Ok(rd) => rd
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    matches!(
                        p.extension().and_then(|e| e.to_str()),
                        Some("yaml") | Some("yml")
                    )
                })
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        files.sort();

        let mut rules = Vec::new();
        let mut any_file = false;
        let mut any_deny_default = false;
        for path in files {
            any_file = true;
            let yaml = std::fs::read_to_string(&path)?;
            let rs = Ruleset::from_yaml(&yaml).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            })?;
            rules.extend(rs.rules);
            if matches!(rs.default, Action::Deny) {
                any_deny_default = true;
            }
        }
        // Fail-closed: deny unless at least one file was present and none of the
        // files declared a `deny` default.
        let default = if any_file && !any_deny_default {
            Action::Allow
        } else {
            Action::Deny
        };
        Ok(Ruleset { rules, default })
    }
}

/// The stricter of two default actions (deny > ask > allow) — fail-closed merge.
fn strictest(a: Action, b: Action) -> Action {
    match (a, b) {
        (Action::Deny, _) | (_, Action::Deny) => Action::Deny,
        (Action::Ask, _) | (_, Action::Ask) => Action::Ask,
        _ => Action::Allow,
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

    // --- layered / from_dir (default/ + user/ composition) ---

    #[test]
    fn user_overlay_rules_take_precedence_over_baseline() {
        // Baseline allows a tool; the user overlay denies it. First-match means
        // the user rule (evaluated first) wins.
        let base = Ruleset::from_yaml(
            "rules:\n  - name: allow-bash\n    match: { tool: Bash }\n    action: allow\ndefault: deny\n",
        )
        .unwrap();
        let user = Ruleset::from_yaml(
            "rules:\n  - name: deny-bash\n    match: { tool: Bash }\n    action: deny\ndefault: deny\n",
        )
        .unwrap();
        let engine = RulesetEngine::new(base.layered(user));
        let ev = Event {
            kind: EventKind::ToolCall {
                name: "Bash".into(),
                input: "{}".into(),
            },
        };
        assert!(matches!(engine.evaluate(&ev), Verdict::Deny(_)));
    }

    #[test]
    fn layered_default_is_deny_when_either_layer_denies() {
        let allow_all = Ruleset {
            rules: vec![],
            default: Action::Allow,
        };
        let deny = Ruleset {
            rules: vec![],
            default: Action::Deny,
        };
        assert!(matches!(
            allow_all.clone().layered(deny).default,
            Action::Deny
        ));
        assert!(matches!(
            allow_all.clone().layered(allow_all).default,
            Action::Allow
        ));
    }

    #[test]
    fn from_dir_concatenates_sorted_and_missing_is_fail_closed() {
        let dir = std::env::temp_dir().join("pasu-rules-fromdir-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Filenames drive order: 20 loaded after 10, so 10's rule matches first.
        std::fs::write(
            dir.join("20-b.yaml"),
            "rules:\n  - name: b\n    match: { tool: T }\n    action: deny\ndefault: deny\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("10-a.yaml"),
            "rules:\n  - name: a\n    match: { tool: T }\n    action: allow\ndefault: allow\n",
        )
        .unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored, not yaml").unwrap();

        let rs = Ruleset::from_dir(&dir).unwrap();
        assert_eq!(rs.rules.len(), 2);
        assert_eq!(rs.rules[0].name, "a"); // 10-a.yaml first
        assert!(matches!(rs.default, Action::Deny)); // 20-b declares deny → deny wins

        // Missing directory → empty, fail-closed.
        let missing = Ruleset::from_dir(&dir.join("does-not-exist")).unwrap();
        assert!(missing.rules.is_empty());
        assert!(matches!(missing.default, Action::Deny));
    }

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
    fn lowers_ipv6_literal_to_ips6() {
        let rs = Ruleset::from_yaml(
            "rules:\n  - name: allow-v6\n    match: { host: \"2606:4700:4700::1111\" }\n    action: allow\n  - name: allow-v4\n    match: { host: \"1.1.1.1\" }\n    action: allow\ndefault: deny\n",
        )
        .unwrap();
        let out = rs.egress_allowlist().unwrap();
        assert_eq!(out.ips, vec![Ipv4Addr::new(1, 1, 1, 1)]);
        assert_eq!(
            out.ips6,
            vec!["2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()]
        );
        assert!(out.domains.is_empty());
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
