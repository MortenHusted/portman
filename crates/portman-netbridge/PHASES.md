# portman-netbridge — implementation phases

Port of `chipmk/docker-mac-net-connect` into native Rust inside the portman
workspace. Acceptance criteria for "done" live in `/PLAN.md § v1 roadmap`.
This file tracks **how** we get there, and — equally important — **how each
phase stays out of the way of the user's main-driver workflow**.

## Safety-first principle

The user runs portman v0 (wrapped bridge, brew-installed
`chipmk/tap/docker-mac-net-connect`) on their main-driver Mac. That stack
must keep working end-to-end throughout Phases A, B, C. Every commit in
this crate prior to Phase D is **additive and observation-only** — it may
register `utun` devices, bind sockets, watch events, and log, but it must
NOT modify any route the v0 bridge owns, must NOT stop any v0 service, and
must NOT claim any resource a container in the user's `~/dev` compose
stack could need.

Anything that touches those lines is Phase D and requires the cutover
window (see bottom of file).

## Phase 0 — scaffold

**Status: done (this commit).** Empty crate wired into the workspace,
`cargo check` passes, nothing references `portman-netbridge` yet.

Verification: `cargo check --workspace` green.

## Phase A — observation & primitives (safe to run alongside v0)

Estimated: 2–3 evenings. Zero risk to main driver.

Deliverables:

1. **A.1 `route_observer`** — Opens a `PF_ROUTE` socket in read-only mode,
   streams route-table add/delete events, emits them as a
   `tokio::sync::mpsc` channel. Verified by watching the chipmk bridge
   add `172.17.0.0/16 → utun0` at boot. **Shipped (commit `7fbcfce`,
   example binary validated 2026-04-23).**
2. **A.2 `docker_state`** — Subscribes to `bollard::events()` (reuses the
   daemon's existing docker-socket resolution), tracks "VM running" and
   "container on network X" sets, emits a state enum. Verified by
   restarting colima and observing VM-loss → VM-running transitions.
3. **A.3 `bridge_health` + menubar wire-up** — Combine A.1 + A.2 into a
   daemon-side `BridgeHealth` struct exposed via a new IPC request. The
   SwiftUI menubar polls it alongside the existing `Status` and renders
   a badge: green (healthy), yellow (drift — containers on subnet X but
   no route via utun), red (bridge offline). Gives the user visceral
   signal the instant the chipmk bridge flaps, not 20 minutes later when
   psql times out. This is Phase A paying dividends before Phase B
   starts.
4. **A.4 `wireguard`** — Wraps `boringtun` for handshake, encryption,
   keepalive. All off-wire unit tests (no utun, no network). Verified by
   the upstream boringtun test vectors passing.
5. **A.5 `utun` helper** — Uses the `tun` crate to allocate a scratch
   utun device by asking kernel for an unused unit (`ctl_id` dynamic).
   In tests only, brings it up with a private subnet (`10.200.200.1/24`
   — deliberately far from v0's `10.33.33.x`), assigns IP, tears it
   down. Never touches utun0/utun3 where v0's bridge lives.

Safety guarantees:
- No route modifications. The observer only *reads* the route table.
- utun devices allocated in Phase A are dynamic unit numbers assigned by
  the kernel; there is no way for them to collide with v0's utun0.
- No bollard calls that mutate container state (create/kill/restart).
  Only event subscription and inspect-for-read.
- No `brew services` invocations.
- Menubar wire-up in A.3 is read-only UI — no new mutation paths.

Deliverable verification script: `cargo test -p portman-netbridge` passes;
`cargo run -p portman-netbridge --example route_observer` tails the route
table and prints v0 bridge events as they happen; portman menubar shows
green badge when bridge is healthy.

## Phase B — parallel real docker network + tunnel

Estimated: 2–3 evenings. Very low risk (parallel, never touches v0).

Stand up a full WireGuard tunnel end-to-end AND a real docker network
that uses it, on a subnet no existing container touches. This is the
step that turns from "experiment" into "production-usable parallel
bridge" — new containers can opt into it, old containers keep running on
chipmk untouched. Key shift from the earlier design: we don't validate
on a throwaway test subnet first and then cut over later; we build
directly on the real-adoption subnet, because the "cutover" model no
longer exists.

### B.1 — WireGuard tunnel + host route

- Host side: new utun (dynamic unit), IP `192.168.99.1`.
- VM side: WireGuard interface `chip0` at `192.168.99.2`, configured by a
  one-shot setup container (`portman-netbridge-setup`) modeled on
  chipmk's setup-image. Inside the VM, policy routing sends container
  traffic on the portman-managed subnet out chip0.
- Host route installed: `192.168.99.0/24 → utun<N>`.

### B.2 — docker network creation

portman-netbridge creates a docker network named `portman` with:

- Driver `bridge` (standard Linux bridge inside colima's VM).
- Subnet `192.168.99.0/24`, gateway `192.168.99.2` (the chip0 interface
  inside the VM).
- Options that support the c2c/c2h hooks in the next section: DNS servers
  field reserved but initially pointing at Docker's embedded DNS
  (127.0.0.11) as a passthrough; `com.docker.network.driver.mtu=1420` for
  WireGuard overhead.
- Reserved IPs inside the subnet: `192.168.99.254` is never allocated to
  containers (reserved for the host-facing virtual IP — see c2c/c2h
  hooks).

### B.3 — adoption without migration

Users **do not move existing containers**. New projects opt in by adding:

```yaml
networks:
  portman:
    external: true
services:
  newapp:
    networks: [portman]
```

or by passing `--network portman` on `docker run`. The `dev_default`
network (chipmk-managed) keeps working for every existing container
exactly as before. chipmk's routes for 172.17/172.18 stay installed.
portman-netbridge's route for 192.168.99/24 is additive. Two bridges
coexist; containers choose which they attach to.

chipmk retires by natural attrition — when the user has no containers on
172.17/172.18 anymore (weeks, months, whenever), they stop the chipmk
service. No cutover window, no outage, no timeline pressure.

### B.4 — host-to-container and back

- Host → portman container: `http://<hostname>.acme.internal` works
  because portman DNS returns the container IP (192.168.99.x), host
  routes via utun, WireGuard delivers to chip0 inside VM, Linux bridge
  delivers to container. Same shape as chipmk, different subnet.
- Container → host: via `host.docker.internal` (Docker default) OR via
  the reserved `192.168.99.254` virtual IP (see hook 2).

Success criterion: `docker run --network portman --rm alpine wget -qO-
http://some-existing-container.acme.internal` succeeds from a portman
container reaching a chipmk container (through portman DNS which serves
the chipmk-side IP — the two bridges never talk to each other, but DNS +
host routing is enough to wire up traffic paths that cross).

And inverse: existing chipmk containers keep reaching their existing
peers unchanged throughout. Nothing about their network setup has
changed.

Safety guarantees:
- portman subnet is distinct from every subnet the v0 stack uses.
- Two bridges run in parallel. Neither's state affects the other.
- No writes to `/Library/LaunchDaemons/` or `~/Library/LaunchAgents/`.
- chipmk continues carrying all 172.17/172.18 traffic unchanged. Its
  routes are untouched. Its processes run unchanged.
- Failure rollback: `docker network rm portman` + tear down utun<N>.
  ~10 seconds, zero impact on anything that was working before.

## Phase C — shadow self-healing (log-only, opt-in)

Estimated: 2–3 hours. Zero risk.

Inside `portman-daemon`, gated behind `PORTMAN_SHADOW_BRIDGE=1` env var,
wire Phase A's `route_observer` + `docker_state` into a detector:

- When `docker_state` reports containers on a subnet AND the host's
  routing table shows no route via utun to that subnet → log
  `WARN: would restart chipmk bridge (containers-without-route detected)`.
- Never actually restart. Log-only. User watches `portman` logs for a week
  of normal work, calibrates how often the detector fires vs. actual
  outages.

Goals:
- Validate the Phase 12.5 middle-ground detection logic in production
  traffic without doing anything.
- Let the user decide, based on observed accuracy, whether to (a) ship
  Phase 12.5 as an auto-heal feature, or (b) commit fully to Phase D.

Safety guarantees:
- Feature is off by default. Only activates when `PORTMAN_SHADOW_BRIDGE=1`
  is set in the daemon plist's `EnvironmentVariables`.
- No mutations. Pure observation + log.

## Phase D — natural attrition (no cutover event)

Under the zero-migration adoption model established in Phase B, there is
no discrete "cutover" phase. chipmk retires when the user chooses to, at
zero risk. The earlier Phase D ("stop chipmk, start portman, hope
nothing breaks") is obsolete.

Replacement flow:

1. User has spun up at least some new projects on portman-net (Phase B).
2. Over weeks or months of normal dev work, containers get recreated.
   Whenever a user recreates one (`docker compose down && up`, image
   rebuild, Dockerfile change), they can opt the recreated version into
   portman-net at that natural moment — just add `networks: [portman]`
   to the compose file.
3. Eventually, chipmk's subnets (172.17/172.18) have no containers on
   them. `docker ps --filter network=dev_default` returns empty.
4. User runs `sudo brew services stop chipmk/tap/docker-mac-net-connect`
   + `sudo brew uninstall chipmk/tap/docker-mac-net-connect` whenever
   they feel like it. No impact — there's been nothing using chipmk for
   days/weeks.

**There is no outage window. There is no Saturday-morning session.
There is no rollback script needed, because there was never a switch
flipped.** The whole point of zero-migration adoption is that "Phase D"
becomes a no-op.

If portman-netbridge *does* turn out to have a bug during this long
tail, it's localized to containers that opted in — user drops that
project back to the default network (`networks: [default]` or remove
the stanza), recreates, everything else keeps humming. Blast radius is
one project, not the whole stack.

### What moves here that used to be D

- `portman bridge enable` / `disable` subcommands still ship in B, but
  they control whether portman-netbridge is *running* at all, not a
  migration state.
- A `portman bridge doctor` subcommand is worth shipping: inspects both
  bridges, reports what's on each subnet, flags drift. Optional — Phase
  C's menubar BridgeHealth already covers the UI side.

## Design hooks reserved for c2c DNS + c2h routing (Phase E candidates)

Container-to-container DNS (CLAUDE.md "third hard part", deferred past
v0) and richer container-to-host routing are explicit post-v1 work. But
Phase B's design decisions must not paint us into a corner. Three slots
are reserved in the `portman` docker network config so these can land
later without a rewrite.

### Hook 1 — DNS injection

**What it enables:** container on portman-net resolves
`pg.acme.internal` → real container IP (or host IP for static rules),
without the user configuring per-container DNS. Makes portman hostnames
first-class from inside containers, not just from the host.

**Reserved slot:** the `portman` docker network created in B.2 exposes a
`--dns <ip>` parameter. In Phase B we default it to Docker's embedded
`127.0.0.11` (effective no-op; containers still resolve peer service
names, and portman hostnames return NXDOMAIN as today). When the
c2c-DNS feature lands:

- portman-netbridge spawns a long-lived sidecar container
  `portman-dns-forwarder` inside colima's VM, attached to the portman
  network.
- The sidecar runs `hickory-server` (already a workspace dep), same
  crate as the daemon's DNS.
- It forwards `*.internal`, `*.acme`, `*.acme`, etc. (portman's
  managed TLDs) to the daemon's DNS through the WireGuard tunnel back
  to the macOS host. Everything else falls through to Docker's embedded
  DNS or 1.1.1.1.
- Network's default DNS flips from `127.0.0.11` to the sidecar's
  container IP.
- Containers attaching to portman-net inherit that DNS automatically.

**Why the slot works:** we don't have to wait for Phase E to wire this.
The network config field is already there. The flip from "passthrough"
to "sidecar-forwarded" is a runtime configuration change, not a
re-architecture.

### Hook 2 — host-facing virtual IP

**What it enables:** containers on portman-net reach macOS host services
by dialing a stable, documented IP, not by relying on Docker's
`host.docker.internal` magic (which is Docker-vendor-specific and flaky
on some runtimes).

**Reserved slot:** `192.168.99.254` is reserved from allocation on the
portman subnet in B.2. Containers never get that IP. When the feature
lands:

- portman-netbridge adds a route inside the VM: `192.168.99.254 →
  chip0` with SNAT to the host's loopback on the other end of the
  tunnel.
- Containers dialing `192.168.99.254:80` reach portman's HTTP proxy on
  the macOS host. Dialing `:<any-port>` reaches any service listening
  on macOS loopback.
- This becomes a documented stable interface — unlike
  `host.docker.internal` which can vary between Docker Desktop, Colima,
  Rancher Desktop, etc.

**Why the slot works:** the IP reservation is zero-cost. If we never
implement the feature, `.254` is just unused. If we do, the subnet
assignment doesn't need to change.

### Hook 3 — cross-bridge peering

**What it enables:** containers on portman-net reach containers on
chipmk-managed networks (172.17, 172.18) during the long attrition
period when some services still run on chipmk. Without this, portman-net
containers that want to talk to e.g. `pg` on `dev_default` have to go
back out through the host (via DNS → portman DNS → host routes → back
into chipmk tunnel), which works but is a weird path.

**Reserved slot:** portman-netbridge's setup container inside the VM
has a comment block in its routing configuration script marked "peering
route slot". A future implementation would add:

```
route add 172.17.0.0/16 via <chipmk-chip0-gateway> dev chip0-portman
route add 172.18.0.0/16 via <chipmk-chip0-gateway> dev chip0-portman
```

inside the VM, so portman-net containers see chipmk subnets as directly
reachable. Not implemented in B; the slot is documented so the future
change is mechanical, not architectural.

**Why the slot works:** Phase B deliberately doesn't install peering
routes. Portman-net containers CAN still reach chipmk containers — via
DNS + host-loop — it's just one extra hop. Adding the direct peering
route is pure optimization, not correctness.

### Summary of reserved slots

| Slot | Reserved in Phase B as | Implemented in Phase E as |
|---|---|---|
| Hook 1 | `--dns` parameter on network create, defaulting to 127.0.0.11 | Sidecar DNS forwarder container swaps the value |
| Hook 2 | `192.168.99.254` excluded from container IP pool | Virtual IP + SNAT in VM routing config |
| Hook 3 | Comment block in VM setup script | Peering routes added in-VM |

Each hook is an additive change in a future session. None requires
re-architecting Phase B.

## Phase E — c2c DNS, c2h virtual IP, cross-bridge peering

Implements the three reserved hooks above. Order is user-driven based on
which pain point bites first after Phase B ships. Each hook is
independently shippable.

## Phase F — Linux port, privileged-helper installer

Out of scope for the initial v1. Tracked for later. Linux doesn't need
the WireGuard bridge at all (containers are natively host-routable), so
most of Phases A–C collapse. What remains: `docker_state` state machine,
menubar BridgeHealth's equivalent (probably a local web dashboard since
menubar is macOS-only), and the privileged-helper story for
`/etc/resolver/` equivalents (`systemd-resolved` / dnsmasq integration).

## What this plan does NOT do

- Does not require any working-day interruption on the main driver. Phases
  A–C interleave with normal production-code work in evenings.
- Does not touch the v0 stack until Phase D, which happens on a scheduled
  non-working session with spare-laptop dry run first.
- Does not change portman's public API (CLI, IPC, static.json schema)
  until Phase D introduces `portman bridge enable`/`disable`.
