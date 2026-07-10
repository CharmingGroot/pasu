# Packaging — pasu egress guard as a systemd service

Deploy the kernel egress guard (`pasu-egress`) as a config-driven daemon.

> Linux only. Build needs nightly + `bpf-linker` (see the repo README).

## Install

```bash
# 1. build (release) on the target host or a matching toolchain
cargo build --release -p pasu-egress
sudo install -m 0755 target/release/pasu-egress /usr/local/bin/

# 2. config — edit the cgroup path and allowlist first
sudo install -Dm 0644 packaging/pasu-egress.toml /etc/pasu/egress.toml

# 3. systemd unit
sudo install -m 0644 packaging/pasu-egress.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pasu-egress
```

## The dedicated cgroup

The guard is **default-deny**: anything not in the allowlist is dropped. Attach it
to a **dedicated** cgroup and place only the agent's processes there — **never the
root cgroup** (that would cut the host's own egress, SSH included). Loopback and
non-IPv4 always pass.

A simple way to run an agent inside the cgroup:

```bash
sudo mkdir -p /sys/fs/cgroup/pasu-agent
sudo bash -c 'echo $$ > /sys/fs/cgroup/pasu-agent/cgroup.procs; exec my-agent ...'
```

(A systemd slice per agent is the cleaner long-term option.)

## Config

See [`pasu-egress.toml`](pasu-egress.toml): `cgroup_path`, `allow` (IPv4),
`allow_domain` (resolved + refreshed), `refresh_secs`.
