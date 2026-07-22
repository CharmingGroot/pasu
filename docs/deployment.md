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
cleanly. Two paths, mirroring the Docker ones:

**Rootful, privileged** (the direct analog of §2/§3) — build with `podman build`
(same [`deploy/Dockerfile`](../deploy/Dockerfile)), then:

```bash
sudo podman run --rm --privileged --cgroupns host --entrypoint /bin/sh \
  pasu-egress:latest -c '
    pasu-egress --cgroup-path /sys/fs/cgroup --allow 1.1.1.1 &
    sleep 3
    curl -s --max-time 6 http://1.1.1.1 && echo "1.1.1.1 OK"       # allowed
    curl -s --max-time 6 http://1.0.0.1 || echo "1.0.0.1 dropped"  # blocked
'
```

The same two gotchas from §4 apply: pass **`--cgroupns host`** (Podman also gives a
private cgroupns by default), and Podman's default seccomp profile blocks `bpf()`
too — `--privileged` clears it, or grant `CAP_BPF` + `CAP_NET_ADMIN` (+ `CAP_PERFMON`)
with a seccomp profile that allows `bpf`.

**Pod sidecar** — a Podman pod shares a cgroup across its containers, so it maps
directly onto the Kubernetes sidecar model (§4). The [k8s manifests](../deploy/k8s/)
also run under Podman via `podman play kube`: the privileged pasu-egress container
attaches to the shared pod cgroup and guards the agent container.

> ⚠️ **Rootless Podman is the hard case.** A rootless container runs in a user
> namespace with a delegated cgroup subtree, and attaching a cgroup-BPF program
> generally still needs real (host) privilege — so the enforcing layer expects
> **rootful** Podman. (The cooperative `pasu-proxy` layer, being an unprivileged
> userspace library/binary, runs fine rootless — `podman run` it and point the
> agent's `base_url` at it.)

> These Podman commands follow the same shape as the verified Docker paths but
> have **not been run against a live Podman host** — treat them as a starting
> point, like the Kubernetes examples above.

### Two gotchas we hit validating this (so you don't have to)

- **cgroup namespace**: even privileged, a container gets a *private* cgroupns by
  default and only sees its own subtree — the guard can't find the target cgroup.
  Run the guard container with the **host cgroup namespace** (`cgroup: host` in
  compose, `--cgroupns host` for `docker run`).
- **systemd slice nesting**: with the systemd cgroup driver, a dash in a slice
  name means nesting — `cgroup_parent: pasu-guarded.slice` lands at
  `/sys/fs/cgroup/pasu.slice/pasu-guarded.slice`, not at the cgroup root.

## Notes

- **DNS / `--allow-domain`** re-resolves on an interval; because that lookup runs
  *after* attach, allow your DNS resolver's IP too, or prefer static `--allow`
  IPs where you can.
- Both IPv4 and IPv6 egress are filtered (default-deny). Loopback (`127.0.0.0/8`,
  `::1`) and v6 infrastructure prefixes (link-local `fe80::/10`, multicast
  `ff00::/8`) always pass so basic networking keeps working.
- This guards **egress**; it is not an ingress firewall.
