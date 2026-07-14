# syntax=docker/dockerfile:1
#
# pasu-proxy — LLM-API guard proxy, containerized (pure userspace, no eBPF).
#
# A slim sidecar image: build the stable `pasu-proxy` binary and run it next to
# your agent. The agent points its base_url at this container; the proxy
# forwards to the real provider and blocks denied tool calls. Unlike the eBPF
# egress image, this needs NO privileges, NO cgroup, NO host mounts.
#
#   docker build -f deploy/proxy/Dockerfile -t pasu-proxy:latest .

########## builder ##########
FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
# Portable/stable build — the proxy crate needs no eBPF toolchain.
RUN cargo build --release -p pasu-proxy --bin pasu-proxy

########## runtime ##########
FROM debian:bookworm-slim
# CA roots for TLS to the real provider (https upstream).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/pasu-proxy /usr/local/bin/pasu-proxy

# Policy is mounted at /etc/pasu/rules.yaml (ConfigMap / bind mount). Override
# --upstream / --provider / --listen as needed.
ENTRYPOINT ["pasu-proxy"]
CMD ["--policy", "/etc/pasu/rules.yaml", "--listen", "0.0.0.0:8788", "--upstream", "https://api.openai.com", "--provider", "openai"]
