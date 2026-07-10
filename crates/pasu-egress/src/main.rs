use std::net::Ipv4Addr;

use anyhow::Context as _;
use clap::Parser;
use pasu_egress::guard::{self, GuardConfig};

#[derive(Debug, Parser)]
struct Opt {
    /// Load settings from a TOML config file (daemon mode; see
    /// packaging/pasu-egress.toml). When set, the flags below are ignored.
    #[clap(long)]
    config: Option<std::path::PathBuf>,
    /// cgroup v2 path to attach to. Required unless `--config` is given, and must
    /// be a DEDICATED cgroup: default-deny on the root cgroup would cut the host's
    /// own egress (SSH included).
    #[clap(short, long)]
    cgroup_path: Option<std::path::PathBuf>,
    /// Destination IPv4 allowed to egress (repeatable). Everything else is dropped.
    #[clap(short, long = "allow")]
    allow: Vec<Ipv4Addr>,
    /// Domain whose resolved IPv4 addresses are allowed (repeatable). Best-effort,
    /// control-plane resolution (precise DNS-response sniffing is future work, M2b).
    #[clap(short = 'd', long = "allow-domain")]
    allow_domain: Vec<String>,
    /// Domain re-resolution interval, seconds.
    #[clap(long, default_value_t = 30)]
    refresh_secs: u64,
}

fn default_refresh_secs() -> u64 {
    30
}

/// Effective settings, from a TOML config file (daemon) or the CLI flags.
#[derive(Debug, serde::Deserialize)]
struct Config {
    /// Dedicated cgroup v2 path (never the root cgroup).
    cgroup_path: std::path::PathBuf,
    #[serde(default)]
    allow: Vec<Ipv4Addr>,
    #[serde(default)]
    allow_domain: Vec<String>,
    #[serde(default = "default_refresh_secs")]
    refresh_secs: u64,
}

impl Opt {
    fn into_config(self) -> anyhow::Result<Config> {
        if let Some(path) = self.config {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read config {}", path.display()))?;
            toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))
        } else {
            let cgroup_path = self
                .cgroup_path
                .context("--cgroup-path is required (or pass --config <file>)")?;
            Ok(Config {
                cgroup_path,
                allow: self.allow,
                allow_domain: self.allow_domain,
                refresh_secs: self.refresh_secs,
            })
        }
    }
}

impl From<Config> for GuardConfig {
    fn from(cfg: Config) -> Self {
        GuardConfig {
            cgroup_path: cfg.cgroup_path,
            allow: cfg.allow,
            allow_domain: cfg.allow_domain,
            refresh_secs: cfg.refresh_secs,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Opt::parse().into_config()?;
    env_logger::init();
    guard::run(cfg.into()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_toml_parses_with_defaults() {
        let cfg: Config = toml::from_str(
            "cgroup_path = \"/sys/fs/cgroup/pasu-agent\"\n\
             allow = [\"1.0.0.1\"]\n\
             allow_domain = [\"api.openai.com\"]\n",
        )
        .expect("valid config");
        assert_eq!(
            cfg.cgroup_path,
            std::path::PathBuf::from("/sys/fs/cgroup/pasu-agent")
        );
        assert_eq!(cfg.allow, vec![Ipv4Addr::new(1, 0, 0, 1)]);
        assert_eq!(cfg.allow_domain, vec!["api.openai.com".to_string()]);
        assert_eq!(cfg.refresh_secs, 30); // serde default
    }

    #[test]
    fn config_requires_cgroup_path() {
        // cgroup_path is mandatory — no accidental root-cgroup default.
        let parsed: Result<Config, _> = toml::from_str("allow = []\n");
        assert!(parsed.is_err());
    }
}
