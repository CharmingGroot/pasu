# Deploying pasu

pasu has two layers with very different deployment stories:

- **Cooperative layer** (`pasu-proxy`, `pasu-rules`, `pasu-ui`, `pasu-audit`) — a
  Rust *library* you link into your agent. It ships in your agent's own
  container like any other dependency. No special privileges, any OS.
- **Enforcing layer** (`pasu-egress` + `pasu-ebpf`) — a kernel eBPF guard. This
  page is about running *that* in a container.

## The one rule: attach to the target's cgroup

`pasu-egress` attaches a `cgroup_skb` (egress) program to a **cgroup v2** node.
The program then filters egress for **every process in that cgroup subtree**
(default-deny; only allow-listed IPs/domains pass).

So the only hard requirement is:

> **pasu-egress must be able to attach to the cgroup where your agent runs.**

It does **not** have to share that cgroup — it just needs to reach it. That
gives three placements:

| Placement | How it reaches the target cgroup |
|---|---|
| **Same container (self-guard)** | attaches to its own cgroup (`/sys/fs/cgroup` under a private cgroupns) |
| **Sidecar** | attaches to the pod / shared parent slice the agent runs in |
| **Node-level (DaemonSet)** | mounts the host cgroup tree and attaches to the agent's slice |

⚠️ Attach to a **dedicated** cgroup, never the host root cgroup — default-deny on
the root would cut the host's own egress (SSH included).

## Requirements

- **Linux, cgroup v2** (`stat -fc %T /sys/fs/cgroup` → `cgroup2fs`)
- Kernel with BPF cgroup support (≈5.8+ for `CAP_BPF`; older kernels need `CAP_SYS_ADMIN`)
- Capabilities: **`CAP_BPF` + `CAP_NET_ADMIN`** (+ `CAP_PERFMON` on some kernels).
  `--privileged` is the easy path; the least-privilege set is `--cap-add`.
- The **`bpf()` syscall must not be blocked by seccomp** — Docker's (and Podman's)
  default seccomp profile blocks it, so use `--privileged` or a profile that
  allows `bpf`.
- A **cgroup v2 mount** in the container (`/sys/fs/cgroup`) covering the target.

## 1. Build

```bash
docker build -f deploy/Dockerfile -t pasu-egress:latest .
```

The builder needs nightly + `rust-src` and a matching LLVM for `bpf-linker`
(handled inside the Dockerfile); the eBPF bytecode is embedded in the binary, so
the runtime image is a slim Debian.

## 2. Self-guard (one container) — quickest proof

```bash
./deploy/demo.sh
```

Runs pasu-egress inside a single privileged container, attached to the
container's own cgroup (allow only `1.1.1.1`), then shows the kernel dropping a
call to a non-allowed IP while the allowed one succeeds — **regardless of the
app**. This is the enforcing property: a process opening its own socket can't
opt out.

Manual equivalent:

```bash
docker run --rm --privileged --entrypoint /bin/sh pasu-egress:latest -c '
  pasu-egress --cgroup-path /sys/fs/cgroup --allow 1.1.1.1 &
  sleep 3
  curl -s --max-time 6 http://1.1.1.1  && echo "1.1.1.1 OK"        # allowed
  curl -s --max-time 6 http://1.0.0.1  || echo "1.0.0.1 dropped"   # blocked
'
```

## 3. Sidecar (guard a separate workload)

```bash
docker compose -f deploy/docker-compose.yml up --build
```

`agent` runs in a dedicated slice; `pasu-egress` (in its own cgroup) attaches the
guard to that slice. The agent log shows `1.1.1.1` allowed and `1.0.0.1`
`DROPPED`. See [`deploy/docker-compose.yml`](../deploy/docker-compose.yml).

## 4. Kubernetes

- **Per-pod sidecar** — [`deploy/k8s/sidecar.yaml`](../deploy/k8s/sidecar.yaml):
  a privileged sidecar attaches to the pod cgroup.
- **Node-level DaemonSet** — [`deploy/k8s/daemonset.yaml`](../deploy/k8s/daemonset.yaml):
  one privileged pod per node attaches to a dedicated agent slice (Cilium/Falco
  pattern).

Both are examples — set the image, allowlist, and attach path for your runtime's
cgroup layout.

## 5. Podman

The "one rule" is runtime-agnostic: pasu-egress needs a **cgroup v2** node and the
capability to attach a `cgroup_skb` program to it — not Docker specifically.
Podman is **cgroup-v2-native and daemonless**, so the requirements above map
cleanly. Run it **rootful** (`sudo podman`); see the rootless note below.

Podman's default seccomp profile blocks `bpf()` just like Docker's, so
`--privileged` is the easy path (or grant `CAP_BPF` + `CAP_NET_ADMIN`
(+ `CAP_PERFMON`) with a profile that allows `bpf`).

**Self-guard (one container)** — attaches to the container's own cgroup, so use
Podman's **default (private) cgroupns**; `/sys/fs/cgroup` is then the container's
own cgroup. Build with `podman build` (same [`deploy/Dockerfile`](../deploy/Dockerfile)),
then:

```bash
sudo podman run --rm --privileged --entrypoint /bin/sh \
  pasu-egress:latest -c '
    pasu-egress --cgroup-path /sys/fs/cgroup --allow 1.1.1.1 &
    sleep 3
    curl -s --max-time 6 http://1.1.1.1 && echo "1.1.1.1 OK"       # allowed
    curl -s --max-time 6 http://1.0.0.1 || echo "1.0.0.1 dropped"  # blocked
'
```

> ⚠️ **Do _not_ add `--cgroupns host` to the self-guard command.** With the host
> cgroupns, `/sys/fs/cgroup` is the **host root cgroup**, and default-deny there
> cuts the whole host's egress (verified: the host itself lost egress to
> non-allowed IPs). `--cgroupns host` is only for the sidecar case below, and
> then you attach to a **dedicated** cgroup path, never `/sys/fs/cgroup`.

**Sidecar (guard a separate container)** — the guard needs `--cgroupns host` to
reach the target's cgroup, and attaches to that **specific** cgroup path (from
`podman inspect`), which scopes enforcement to the target and leaves the host
untouched:

```bash
sudo podman run -d --name agent ...                 # your agent workload
AGCG=$(sudo podman inspect agent --format '{{.State.CgroupPath}}')
sudo podman run -d --privileged --cgroupns host --entrypoint pasu-egress \
  pasu-egress:latest --cgroup-path "/sys/fs/cgroup$AGCG" --allow 1.1.1.1
# agent now reaches 1.1.1.1 but not 1.0.0.1; the host's own egress is unaffected.
```

A Podman **pod** shares a cgroup across its containers, so `podman play kube` on
the [k8s manifests](../deploy/k8s/) maps onto the same sidecar model (§4) — the
privileged pasu-egress container attaches to the pod's cgroup slice.

> ⚠️ **Rootless Podman is the hard case.** A rootless container runs in a user
> namespace with a delegated cgroup subtree, and attaching a cgroup-BPF program
> generally still needs real (host) privilege — so the enforcing layer expects
> **rootful** Podman. (The cooperative `pasu-proxy` layer, being an unprivileged
> userspace library/binary, runs fine rootless — `podman run` it and point the
> agent's `base_url` at it.)

> **Verified** on Lima (Ubuntu 24.04, kernel 6.8, cgroup v2, **Podman 4.9.3**,
> arm64): the self-guard and sidecar commands above both enforce the allowlist in
> the kernel while leaving host egress intact; `--cgroupns host` on a
> `/sys/fs/cgroup` attach cuts the host, as warned. `podman play kube` is inferred
> from the shared-cgroup model, not separately run.

### Two gotchas we hit validating this (so you don't have to)

- **cgroup namespace**: even privileged, a container gets a *private* cgroupns by
  default and only sees its own subtree — the guard can't find the target cgroup.
  Run the guard container with the **host cgroup namespace** (`cgroup: host` in
  compose, `--cgroupns host` for `docker run`).
- **systemd slice nesting**: with the systemd cgroup driver, a dash in a slice
  name means nesting — `cgroup_parent: pasu-guarded.slice` lands at
  `/sys/fs/cgroup/pasu.slice/pasu-guarded.slice`, not at the cgroup root.

## 6. WireGuard와 함께 쓰기 (VPN 우회 차단)

커널 WireGuard를 쓰면 pasu는 **터널 안쪽 목적지**를 본다. `cgroup_skb`는 소켓
계층이라 라우팅(=캡슐화)보다 앞에서 돌기 때문이다. 그래서 "이 에이전트는 VPN
너머 이 대역에만 접근한다"를 정책으로 쓸 수 있다.

```bash
# VPN 대역만 허용 — 인터넷 직행은 커널이 drop
pasu-egress --cgroup-path /sys/fs/cgroup/pasu-agent --allow 10.10.0.0/24
```

**`AllowedIPs`는 방화벽이 아니다.** WireGuard의 `AllowedIPs = 10.0.0.0/8`은
"10.x로 갈 때 이 터널을 쓴다"는 **라우팅 규칙**이지, "10.x 외에는 나가지 마라"가
아니다. 목적지가 거기 없으면 그냥 기본 경로로 나간다. pasu의 default-deny가
그 자리를 채운다.

### 실측 (Lima · Ubuntu 24.04 · 커널 6.8 · 커널 WireGuard)

두 netns를 WireGuard로 묶고 `--allow 10.10.0.0/24` 만 준 상태:

| 목적지 | 성격 | 결과 |
|---|---|---|
| `10.10.0.2` | 터널 **안쪽**, 허용 대역 | 통과 — pasu가 안쪽 주소를 본다 |
| `1.1.1.1` | 인터넷 직행 | **차단** — VPN 우회가 막힌다 |
| `192.168.99.2` (ICMP) | WG 엔드포인트로 직접 | 차단 |

감사 로그에는 `1.1.1.1:80` 과 `192.168.99.2:0` 만 남고 **WireGuard의 바깥 UDP
(`…:51820`)는 남지 않는다.** 그 패킷은 커널이 자기 소켓으로 보내므로 에이전트의
cgroup에 속하지 않는다 — 터널 트래픽 자체는 필터를 거치지 않고, 정책은 안쪽
주소로만 판단된다.

> ⚠️ **유저스페이스 WireGuard(`wireguard-go`·`boringtun`, Tailscale 포함)에서는
> 성립하지 않는다.** 캡슐화가 그 프로세스 안에서 일어나 pasu 눈에는 UDP
> 엔드포인트 하나만 보인다. 안쪽 목적지로 정책을 쓰려면 **커널 WireGuard**여야 한다.

## 7. 두 계층을 함께 쓸 때의 권장 구성

프록시(도구 가드)와 커널 egress 를 함께 쓴다면, **에이전트 cgroup 의 커널
allowlist 에 LLM 주소를 넣지 않는다.**

커널 계층은 **목적지만** 본다 — 그 연결이 프록시를 거쳤는지, 도구가 직접 연
소켓인지 구분하지 못한다. 따라서 에이전트 cgroup 에서 LLM 주소를 허용하면
도구가 프록시를 건너뛰고 LLM 에 직접 도달할 수 있고, 그 경로에는 도구 가드도
HITL 승인도 적용되지 않는다.

프록시를 `127.0.0.1` 에 두면 루프백 예외로 통과하므로, **커널 allowlist 에서
LLM 대역을 빼는 것만으로** 에이전트가 프록시를 반드시 경유하게 된다.

```yaml
# 권장: 에이전트 정책에 LLM 호스트를 넣지 않는다.
# 프록시(127.0.0.1)는 루프백 예외로 통과하고, 프록시가 LLM 으로 포워딩한다.
rules:
  - name: allow-bash
    match: { tool: bash }
    action: allow
default: deny
```

```bash
# 프록시는 가드 밖에서 돌린다(또는 별도 cgroup). 여기서만 LLM 에 도달한다.
pasu-proxy --policy rules.yaml --listen 127.0.0.1:8788 \
           --upstream http://vllm.internal:8000 --provider openai

# 에이전트는 가드 안. LLM 주소를 열지 않는다.
sudo pasu run --policy rules.yaml -- <에이전트 명령>
```

> ⚠️ **LLM 이 에이전트와 같은 호스트에서 도는 경우에는 이 구성이 성립하지
> 않는다.** 루프백은 커널 가드가 무조건 통과시키므로, 커널 allowlist 에서
> 무엇을 빼든 도구가 `127.0.0.1:<LLM 포트>` 로 직접 갈 수 있다. 이때는 LLM 을
> 별도 호스트·네트워크 네임스페이스·컨테이너 네트워크로 분리해야 한다.

`sudo pasu run` 은 자식을 root 로 실행한다. 에이전트가 사용자 홈에 상태를 두면
그 파일들이 root 소유가 되어, **가드를 떼도 에이전트가 정상 동작하지 않는다.**
cgroup 배치 후 uid 를 되돌린다 — uid 를 바꿔도 cgroup 소속은 유지되므로 가드는
그대로 적용된다.

```bash
sudo pasu run --policy rules.yaml -- \
  setpriv --reuid=$(id -u) --regid=$(id -g) --init-groups \
  env HOME=$HOME PATH=$HOME/.local/bin:/usr/bin:/bin \
  <에이전트 명령>
```

실측 근거는 [opencode 연동 E2E](opencode-e2e.md) 에 있다.

## Notes

- **DNS / `--allow-domain`** re-resolves on an interval; because that lookup runs
  *after* attach, allow your DNS resolver's IP too, or prefer static `--allow`
  IPs where you can.
- Both IPv4 and IPv6 egress are filtered (default-deny). Loopback (`127.0.0.0/8`,
  `::1`) and v6 infrastructure prefixes (link-local `fe80::/10`, multicast
  `ff00::/8`) always pass so basic networking keeps working.
- This guards **egress**; it is not an ingress firewall.
