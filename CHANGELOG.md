# Changelog

All notable changes to pasu are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
for [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches
its first tagged release.

## [Unreleased]

### Added
- **One policy file for both layers** — `pasu-daemon --policy rules.yaml` lowers
  the same ruleset the proxy evaluates into the kernel egress allowlist
  (IPv4 → static, exact host → DNS-resolved, `.suffix` → reported as
  cooperative-layer-only, `default: allow` → refused fail-closed).
- **Control-plane admin socket** — `pasu-egress --admin-socket` exposes
  `status` / `allow <ip>` / `deny <ip>` for live inspection and edits.
- **Egress dashboard UI** (`/egress`) — kernel filter coverage, live allowlist
  add/remove, and a read-only policy view (per-rule verdict + tool/host guard).
- **Containerization** — `deploy/Dockerfile`, a self-guard demo, a sidecar
  `docker-compose.yml`, Kubernetes sidecar/DaemonSet examples, and a **Helm
  chart** (`deploy/helm/pasu-egress`).
- **Release pipeline** — multi-arch (amd64 + arm64) GHCR image on version tags.
- **Supply-chain gate** — `cargo-deny` CI (advisories · licenses · sources).
- `examples/ui_demo` to run the UI against a mock guard with no kernel.
- README: dependency-pin table, container/Helm quickstart.

### Fixed
- `pasu-ebpf` was missing a `license` field; `pasu-egress` was missing the
  `io-util`/`sync` tokio features (surfaced by a clean build).
