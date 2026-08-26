# syntax=docker/dockerfile:1
#
# pasu-egress — kernel eBPF egress guard, containerized.
#
# The builder needs nightly + rust-src (aya-build compiles the eBPF object with
# `-Z build-std`). The runtime image is a slim Debian with just the loader; the
# eBPF bytecode is embedded in the binary.
#
#   docker build -f deploy/Dockerfile -t pasu-egress:latest .
#
# See docs/deployment.md for how to run it (it needs CAP_BPF + CAP_NET_ADMIN,
# a cgroup v2 mount, and a DEDICATED cgroup to attach to).

########## builder ##########
FROM docker.io/library/rust:1-bookworm AS builder

# eBPF build toolchain: nightly + rust-src (build-std for the bpf target).
RUN rustup toolchain install nightly --profile minimal --component rust-src \
 && rustup default nightly

# bpf-linker 는 CI 와 같은 버전으로 고정한다(.github/workflows/ci.yml).
# 0.11.0(2026-08-12)부터 시스템 LLVM(llvm-sys 21~23)을 요구하는데, 0.10.4 는
# 그것 없이 빌드된다 — CI 의 eBPF 잡이 LLVM 설치 없이 통과하는 것이 그 증거다.
#
# 이전에는 apt.llvm.org 의 llvm.sh 로 LLVM 21 을 깔았으나, 그 스크립트가
# Debian 12(bookworm) 지원을 끊어 빌드가 깨졌다. 0.10.4 를 쓰는 한 필요 없는
# 단계라 통째로 걷어냈다. 0.11 이상으로 올릴 때 LLVM 조달 방법을 다시 정한다.
RUN cargo install bpf-linker --locked --version 0.10.4

WORKDIR /src
COPY . .
# pasu: wrap-any-agent CLI · pasu-egress: flag/TOML loader · pasu-daemon: policy daemon
RUN cargo build -p pasu-egress -p pasu-daemon -p pasu-cli --release

########## runtime ##########
FROM docker.io/library/debian:bookworm-slim AS runtime

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
