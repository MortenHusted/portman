# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status: implemented, under active hardening

The workspace contains the Rust daemon, CLI/TUI, embedded web dashboard, protocol/core crates, and an additive native `portman-netbridge` (macOS). Treat the current phase as hardening and polish, not a blank scaffold.

## What portman is

**The single local-dev daemon**: an OSS macOS-native replacement for **OrbStack's networking/DNS features** without the container-runtime baggage, grown into the one daemon that also **runs host services** — supervision, hermetic env composition, and secrets resolution — so the foreman/overmind/pitchfork layer retires.

What people miss from OrbStack when they run colima/lima/Docker Desktop:

1. **Automatic wildcard DNS** — `<name>.orb.local` routed to the right container without `/etc/hosts` edits.
2. **No port-forwarding** — host hits the container's own port directly (container IP is routable from the host).
3. **A dashboard** — something that shows what's running and where.

OrbStack does this with a closed-source bundle that also includes the runtime. portman decouples: bring your own runtime (colima/limactl/Docker Desktop), portman handles the networking & DNS glue.

Beyond networking, portman owns the **service definition itself**: per-repo `portman.toml` files (public schema, documented in the README) declare host services once — run command, port, host, dependencies, readiness, env files, secrets provider refs — and everything else derives from that one record: the supervisor spawns and restarts them as the login user, the env composer builds their environment hermetically from declared sources only, secrets resolve through machine identities (Infisical universal auth, 1Password service accounts — no interactive logins), DNS/proxy routes appear on `portman up` and disappear on `portman down`, and logs + resource gauges show up in the CLI (`portman logs -f`), TUI, and dashboard.

## Toolchain

- **Daemon: Rust.** `tokio` async runtime. Key crates: `bollard` (Docker API), `boringtun` (Cloudflare WireGuard), `hickory-dns` (DNS server), `httparse` + byte-level tokio streams (HTTP/TLS proxy). `pingora`/`hyper` remain future options if the proxy needs higher-level HTTP behavior.
- **UI: Embedded web dashboard** at `http://portman.localhost` plus ratatui TUI. The built-in route proxies to the loopback-only dashboard listener. Single UI codebase for macOS and Linux.
- **IPC: Unix socket** at `~/Library/Application Support/portman/portman.sock`, length-prefixed JSON frames (`portman_protocol::transport`).
- **Two processes, never one monolith.** Daemon owns all privileged / long-lived state; UI is a thin client.

## Target architecture

One Rust daemon does **everything**; the embedded web dashboard and the TUI are the only surfaces.

1. **Docker event watcher** — `bollard` subscription to the Docker socket, namespace-filtered. Reads `dev.portman.*` labels on each start/stop event.
2. **Label parser + static rule store** — both feed the same internal registry. Label schema: `dev.portman.host=crm.test`, `dev.portman.port=3000`. Static rules via `portman add crm.acme 127.0.0.1:3070` for Rails/Node apps running directly on the host.
3. **Embedded DNS server** — `hickory-dns` authoritative for configured TLDs. macOS resolver integration via `/etc/resolver/<tld>` files pointing at `127.0.0.1:5335` (default; configurable). Avoid 5353 — mDNSResponder and common apps bind `*:5353` for AirPlay/local device discovery, which blocks even loopback binds.
4. **Embedded HTTP proxy** — on `:80`/`:443`, routes by Host header to the target's real IP:port.
5. **WireGuard-based VM↔host bridge** — native `portman-netbridge` using `boringtun`. Makes container IPs routable from macOS.
6. **Privileged runtime/install path** — `portman install` installs a **root LaunchDaemon only**. The daemon owns low-port bind and bridge orchestration; the CLI owns sudo-gated resolver/install mutations with marker checks.
7. **UI surfaces: embedded web dashboard + TUI only.** They list hostnames and services, open HTTP entries, show TLD/TLS/bridge state, and route mutations through daemon IPC or the canonical CLI, staying thin even when they trigger actions.
8. **Native service runner** — the supervisor subsystem runs services from per-repo `portman.toml`: spawned by the root daemon **as the login user** (uid + primary gid), each in its own process group with a hermetically composed env (base allowlist + env_files + secrets + inline, later wins). Crash-restart with exponential backoff; TERM→KILL stop; desired state persists in `services.json`; boot reconciliation is terminate-and-respawn only (identity-checked, never adopt). Captured output lands in `logs.db` (SQLite); secrets resolve behind one `SecretsSource` seam; a `host` + `port` declaration derives the registry route (`Source::Service`).

## The three hard parts (OrbStack's moat)

Don't hide these. Solve in order:

1. **Container IPs routable from the host.** Kills port-forwarding. Needs a macOS route pointing the VM's container IP range at a WireGuard tunnel. The native additive bridge (`portman-netbridge`) creates its own docker network (`portman`, `192.168.99.0/24`) and must coexist with third-party bridges (e.g. `chipmk/docker-mac-net-connect`) without mutating routes/services/resources it does not own. Safety beats convenience: if it cannot operate without touching foreign resources, it must fail rather than silently take over. (OrbStack uses `192.168.138.0/23` by default — don't collide.)
2. **Entitlements to touch `/etc/resolver/` + bind low ports.** `/etc/resolver/` is root-owned; `:80`/`:443` require root. Current path: root LaunchDaemon installed by `portman install`; CLI performs sudo-gated resolver/launchd mutations with marker checks. A narrower helper split remains a future packaging option.
3. **Container-to-container DNS.** Each container needs to resolve peer hostnames, not just the host. Deferred; see `docs/c2c-implementation-brief.md`.

## Data model: Docker labels **and** static host rules, across **multiple TLDs**

Three things are first-class:

1. **Docker-label-driven entries** (primary): `dev.portman.host=crm.test`, `dev.portman.port=3000` on a container. Auto-registered on `container.start`, removed on stop.
2. **Static host rules**: `portman add crm.acme 127.0.0.1:3070`. For apps running directly on the host — a real differentiator; OrbStack is container-only. Wildcards are supported (`*.demo.test`, RFC 6125 one-label matching, HTTP-only).
3. **Multiple managed TLDs**: users register any number of TLDs (`test`, `acme`, `example.com`, …). Each managed TLD gets its own `/etc/resolver/<tld>` file. The DNS server answers for any name in the registry regardless of TLD.

All sources produce the same internal record: `{hostname, ip, port, source}`. DNS and proxy don't know or care which source or TLD it came from. Keep this abstraction clean.

**TLD registration is explicit, not auto.** A container with `dev.portman.host=foo.crm` where `.crm` is not a managed TLD is *ignored with a warning*. Rationale: `/etc/resolver/` writes are a shared-resource change and can clobber Tailscale/VPN split-DNS. Users must opt in per TLD via `portman tld add`. The one exception is HTTP-only `.localhost`: the operating system already resolves it to loopback, so Portman routes it without installing a resolver.

## TLD selection — what's safe on macOS

| TLD | Status |
|-----|--------|
| `.test` | RFC 2606 reserved. **Recommended default.** Safe everywhere. |
| `.localhost` | Native HTTP-only Portman route. The OS resolves it to loopback and the proxy dispatches by Host; no resolver file needed. Not available for TCP mode. |
| `.example`, `.invalid` | Reserved, fine technically, weird naming. |
| `.internal` | ICANN-reserved (2024) but mDNSResponder intercepts queries similarly to `.local` on some macOS builds. Verify before relying on it. |
| `.local` | **Do not use.** Bonjour/mDNS-reserved. mDNSResponder always wins. |
| `.dev` | Google-owned, HSTS-preloaded in Chromium. Plain HTTP impossible — forces TLS mode. |
| Custom (`.acme`, `.crm`, etc.) | Safe in practice. Accept the theoretical ICANN-allocation risk (near zero for made-up names, non-trivial for generic words). |

portman should warn when a TLD from the "avoid" rows is registered, and before writing `/etc/resolver/<tld>`, check whether one already exists with a different nameserver (likely VPN split-DNS) and surface a conflict warning instead of clobbering.

## TLS / HTTPS

**Design: per-TLD cert source, pluggable behind a `CertProvider` trait.**

| Mode | Cert source | Best for | CA install needed? | Container-trust? |
|------|-------------|----------|--------------------|------------------|
| `http` | — | Non-TLS dev | No | N/A |
| `mkcert` | Local root CA via `mkcert` CLI | `.test` quick-start, browser-only | Yes, once (`mkcert -install`) | **No** — each container needs the mkcert CA mounted, per-container boilerplate |
| `le` | Let's Encrypt wildcard via DNS-01 | User owns a real domain | **No** | **Yes** — public CA, trusted everywhere natively |
| `acme` (future) | User-supplied ACME URL (e.g. `step-ca`) | Custom / enterprise | Depends on CA | Depends |

**The mkcert container-trust limitation is real.** Service-to-service HTTPS inside containers fails out of the box because each language runtime has its own CA store that doesn't see the mkcert root. Tolerable for browser-only work; the reason Let's Encrypt mode matters as a first-class option later.

**Current scope:** mkcert mode ships (the daemon shells out to `mkcert`; the LaunchDaemon carries an explicit PATH so installed behavior matches dev mode). `le` is a reserved persisted mode, non-actionable until implemented.

## Cross-platform (Linux)

The daemon is ~90% portable; the platform boundary is designed in.

| Concern | macOS | Linux |
|---------|-------|-------|
| Container IPs routable from host | WireGuard bridge (`boringtun`) | **Native** — already routable when Docker runs on the host kernel |
| DNS integration | `/etc/resolver/<tld>` files | `systemd-resolved` split-DNS / `resolv.conf` / dnsmasq dropin. Distro-dependent. |
| Privileged install | `launchd` plist in `/Library/LaunchDaemons/` | `systemd` unit in `/etc/systemd/system/` |
| Low-port bind | root daemon | `CAP_NET_BIND_SERVICE` |
| UI | dashboard + TUI | same |

Anything touching `/etc/resolver/`, `launchd`, or `utun` stays behind the platform seam (`portman_core::platform`, `launchd.rs`/`systemd.rs`, cfg-gated daemon modules such as `bridge_health_stub.rs`). CI lints and tests both platforms; locally, `cargo clippy --target aarch64-unknown-linux-gnu` works for the crates that don't need a cross C toolchain (cli/core/protocol).

## Conventions

- **Label schema** `dev.portman.host` + `dev.portman.port` is the public API. Resist adding more until a user asks.
- **No container-runtime lock-in.** Docker socket path is configurable; candidates cover colima, Docker Desktop, OrbStack, and the classical default. Don't hard-code one runtime.
- **`portman.toml` + gitignored `portman.local.toml`** overlay is a **field-level patch**: a mentioned field replaces the committed value wholesale (including collection fields); an omitted field keeps it. Pinned by tests — changing this is a behavior break.
- **Wire compatibility**: protocol enums serialize as snake_case strings and deserialize lossily (unknown → `Unknown`) so newer daemons can't break older clients.
- **Commit after every logical step.** Small commits are recoverable.
- When adding any dependency, check it's actively maintained and has a real license.

## Working in this repo

- `CONCEPTS.md` defines portman-specific domain vocabulary.
- `docs/release-readiness.md` is the verification matrix.
- Gates before any push: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` — and for cfg-gated code, the Linux cross-lint above. CI (`.github/workflows/ci.yml`) runs both platforms and is authoritative for the crates that can't cross-compile locally.
