//! Control-plane admin API for the running guard.
//!
//! A tiny newline-delimited protocol over a unix socket so operators (and the
//! UI) can inspect the live guard and edit the allowlist without a restart:
//!
//! ```text
//! status          -> {"cgroup_path":"…","allow_ips":["1.1.1.1"],…}
//! allow 1.2.3.4   -> {"ok":true}
//! deny  1.2.3.4   -> {"ok":true}
//! ```
//!
//! The socket only mediates requests; the eBPF `ALLOW` map is owned by the guard
//! loop, which applies commands one at a time (no shared mutable eBPF state).

use std::net::Ipv4Addr;

use tokio::sync::oneshot;

/// A parsed admin request.
#[derive(Debug, PartialEq)]
pub enum Request {
    Status,
    Allow(Ipv4Addr),
    Deny(Ipv4Addr),
}

/// Parse one request line. Case-insensitive verb; a single IPv4 argument for
/// `allow`/`deny`.
pub fn parse_request(line: &str) -> Result<Request, String> {
    let mut parts = line.split_whitespace();
    let verb = parts.next().unwrap_or_default().to_ascii_lowercase();
    match verb.as_str() {
        "status" => Ok(Request::Status),
        "allow" | "deny" => {
            let arg = parts
                .next()
                .ok_or_else(|| format!("{verb}: missing <ipv4>"))?;
            let ip: Ipv4Addr = arg
                .parse()
                .map_err(|_| format!("{verb}: invalid ipv4 `{arg}`"))?;
            Ok(if verb == "allow" {
                Request::Allow(ip)
            } else {
                Request::Deny(ip)
            })
        }
        "" => Err("empty request".to_string()),
        other => Err(format!("unknown command `{other}`")),
    }
}

/// Live guard status (serialized to JSON as the `status` reply).
#[derive(Debug, serde::Serialize, PartialEq)]
pub struct Status {
    pub cgroup_path: String,
    pub attached: bool,
    pub refresh_secs: u64,
    /// Static + resolved IPv4s currently in the kernel ALLOW map.
    pub allow_ips: Vec<String>,
    /// Domains being resolved into the allowlist (from policy/config).
    pub allow_domains: Vec<String>,
}

/// A command handed to the guard loop, with a channel for its reply.
pub enum Command {
    Status(oneshot::Sender<Status>),
    Allow(Ipv4Addr, oneshot::Sender<Result<(), String>>),
    Deny(Ipv4Addr, oneshot::Sender<Result<(), String>>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status() {
        assert_eq!(parse_request("status").unwrap(), Request::Status);
        assert_eq!(parse_request("  STATUS  ").unwrap(), Request::Status);
    }

    #[test]
    fn parses_allow_deny() {
        assert_eq!(
            parse_request("allow 1.2.3.4").unwrap(),
            Request::Allow(Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(
            parse_request("DENY 10.0.0.1").unwrap(),
            Request::Deny(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_request("allow").is_err()); // missing arg
        assert!(parse_request("allow not-an-ip").is_err());
        assert!(parse_request("allow ::1").is_err()); // ipv4 only
        assert!(parse_request("bogus").is_err());
        assert!(parse_request("").is_err());
    }

    #[test]
    fn status_serializes_to_json() {
        let s = Status {
            cgroup_path: "/sys/fs/cgroup/pasu-agent".into(),
            attached: true,
            refresh_secs: 30,
            allow_ips: vec!["1.1.1.1".into()],
            allow_domains: vec!["api.openai.com".into()],
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"attached\":true"));
        assert!(json.contains("\"1.1.1.1\""));
        assert!(json.contains("api.openai.com"));
    }
}
