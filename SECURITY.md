# Security Policy

pasu loads eBPF programs into the kernel and gates an agent's egress. Bugs here
are high-impact, so please treat them accordingly.

## Reporting a vulnerability

**Please do not open a public issue for security problems.** Instead:

- Use GitHub's **private vulnerability reporting** (repo → *Security* → *Report a
  vulnerability*), or
- contact the maintainer via their GitHub profile.

Include what you can:

- affected component (`proxy` / `egress` / `ebpf` / `rules` / `ui` / `daemon`),
- reproduction steps or a proof of concept,
- impact (what a guard bypass would allow).

We'll acknowledge the report, investigate, and coordinate a fix and disclosure.

## What we especially care about

- **Guard bypass** — egress that policy says should be denied but isn't.
- **Policy-evaluation flaws** — a rule that matches (or fails to match) incorrectly.
- **fail-open behavior** — the guard silently allowing traffic when it should deny.
- **Privilege issues** in the eBPF loader / daemon (cgroup, CAP_BPF, config parsing).

## Supported versions

Pre-1.0: security fixes land on `main`. Pin a commit if you need stability.
