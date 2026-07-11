# syntax=docker/dockerfile:1
#
# pasu-egress — kernel eBPF egress guard, containerized.
#
# The builder needs nightly + rust-src (aya-build compiles the eBPF object with
# `-Z build-std`) and a matching LLVM for bpf-linker. The runtime image is a
# slim Debian with just the loader; the eBPF bytecode is embedded in the binary.
#
#   docker build -f deploy/Dockerfile -t pasu-egress:latest .
#
# See docs/deployment.md for how to run it (it needs CAP_BPF + CAP_NET_ADMIN,
# a cgroup v2 mount, and a DEDICATED cgroup to attach to).

########## builder ##########
FROM rust:1-bookworm AS builder

# eBPF build toolchain: nightly + rust-src (build-std for the bpf target).
RUN rustup toolchain install nightly --profile minimal --component rust-src \
 && rustup default nightly

# LLVM for bpf-linker. The major must match what bpf-linker expects (21 here);
# pin this if you pin bpf-linker.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates wget gnupg lsb-release software-properties-common make \
 && wget -qO /tmp/llvm.sh https://apt.llvm.org/llvm.sh \
 && chmod +x /tmp/llvm.sh && /tmp/llvm.sh 21 \
 && ln -sf /usr/bin/llvm-config-21 /usr/bin/llvm-config \
 && rm -rf /var/lib/apt/lists/*

RUN cargo install bpf-linker --locked

WORKDIR /src
COPY . .
# pasu: wrap-any-agent CLI · pasu-egress: flag/TOML loader · pasu-daemon: policy daemon
RUN cargo build -p pasu-egress -p pasu-daemon -p pasu-cli --release

########## runtime ##########
FROM debian:bookworm-slim AS runtime

# ca-certificates for DNS/TLS metadata; curl + iproute2 + socat make the image
# useful for the demo / admin CLI. Drop them for a smaller production image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl iproute2 socat \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/pasu-egress /usr/local/bin/pasu-egress
COPY --from=builder /src/target/release/pasu-daemon /usr/local/bin/pasu-daemon
COPY --from=builder /src/target/release/pasu /usr/local/bin/pasu

# Args are passed at run time (see docs/deployment.md), e.g.:
#   --cgroup-path /sys/fs/cgroup/pasu-agent --allow-domain api.openai.com
# or run the policy-driven daemon (one YAML for both layers):
#   docker run --entrypoint pasu-daemon ... --policy /etc/pasu/rules.yaml --cgroup-path ...
ENTRYPOINT ["/usr/local/bin/pasu-egress"]
