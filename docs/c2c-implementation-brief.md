# portman — container↔container / container↔host-static DNS implementation brief

## Context

portman v0 is shipped (commits `2d48c96`..`dfbbe04`). Host-side DNS + HTTP/TLS proxy work: a human at a terminal types `curl http://crm.test` and it reaches a container, or `http://crm.acme` and it reaches a host-local Rails app. The connectivity matrix *one direction* is solved.

This brief covers the **other direction** — making portman hostnames resolvable and reachable **from inside containers**. Three scenarios, all currently broken:

1. **Container → container** — app container calls `http://db.test` and gets the db container
2. **Container → host static service** — app container calls `http://crm.acme` (a `portman add` static rule pointing at host-local Rails on `127.0.0.1:3070`) and actually reaches the Rails process
3. **Service → container** — host-local Rails calls `http://api.test` and hits the api container (*already works in v0*, documented here for completeness + so the brief's reader understands it's not a gap)

## Current state of the matrix

| From → To | Works? | Mechanism |
|---|---|---|
| Host → container (HTTP) | ✅ | DNS → 127.0.0.1 → portman proxy on `:80`/`:443` → container IP:port via docker-mac-net-connect |
| Host → container (TCP, e.g. Postgres) | ✅ | DNS → container IP → direct via docker-mac-net-connect |
| Host → host static | ✅ | DNS → 127.0.0.1 → portman proxy (HTTP) or direct (non-HTTP) |
| **Container → container** | ❌ | Container DNS (127.0.0.11 → Docker embedded) doesn't know `.test` |
| **Container → host static** | ❌ | Same DNS issue, plus target `127.0.0.1` is the container itself |
| **Container → host container runtime's own domains** (e.g. `host.docker.internal`) | ✅ | Docker/colima injects this automatically |
| Service → container (via portman hostname) | ✅ | This is the Host→container path above |

## Why the brief exists separately

This is not a "finish v0" task. v0 shipped an end-to-end experience for the human-at-a-terminal UX. Container-to-container is a full additional pass that affects:

- How portman's DNS binds (needs to be reachable from inside the VM)
- How portman answers queries (needs upstream forwarding so it's usable as a container's *primary* DNS)
- How targets are computed (static rule to `127.0.0.1` means something different from inside a container)
- How users opt their containers in (compose `dns:` directive, or docker run `--dns`, or auto-injection)

Each has correctness-sensitive edge cases. Hence the brief — so the implementer has the full picture before touching DNS code.

## The three target scenarios in detail

### 1. Container → container

`app` container has label `dev.portman.host=app.test`. `db` container has label `dev.portman.host=db.test`. From inside `app`:

```
$ curl http://db.test
```

Should reach `db` container on its declared port.

**Why it's broken now:** `app` container's `/etc/resolv.conf` points at `127.0.0.11` (Docker's embedded DNS) or `192.168.65.7` (colima's equivalent). Neither knows `.test`. Query returns NXDOMAIN, curl fails.

### 2. Container → host static service

User runs Rails on the macOS host via `bin/dev` on `:3070`, registers `portman add crm.acme 127.0.0.1:3070`. An `app` container wants to call the Rails app:

```
$ curl http://crm.acme
```

**Why it's broken now:** two compounding problems.
  - (a) Container's DNS doesn't know `.acme` — same as scenario 1
  - (b) Even if DNS returned `127.0.0.1`, that's *the container's own loopback* from inside, not the macOS host's. The target address needs to be the macOS host from the container's perspective (`host.docker.internal` / VM gateway IP)

### 3. Service → container (already works; included for completeness)

Rails on host calls `http://api.test` where `api` is a container. This works in v0 because:
- `/etc/resolver/test` routes `.test` queries to portman's DNS on 127.0.0.1:5335
- Portman returns the container's IP (e.g. `172.17.0.5`)
- docker-mac-net-connect makes that IP routable from the host
- Rails's HTTP client hits the container directly (for port 80) or we proxy

**Implementation nothing to do here.** Listed so the designer/implementer doesn't accidentally regress it.

## Design space

### Where containers get their DNS from

Four things a container could be told to ask for DNS:

| Option | Pro | Con |
|---|---|---|
| **A.** Leave Docker's default embedded DNS (127.0.0.11) | Nothing for user to configure | portman never sees the query — can't fix this |
| **B.** Add portman DNS via `dns:` in docker-compose / `--dns` on `docker run` | Explicit, user-controlled | Per-service friction; user has to remember |
| **C.** Auto-inject `--dns` at container start via docker events | Transparent | Requires intercepting container create (race with start); not all runtimes allow post-create modification |
| **D.** Dedicated docker network with portman DNS baked in | Explicit opt-in at network level; works for compose stacks | One more network to manage; containers have to attach |

**Recommendation: B primary, C as a v2 enhancement, D documented as an alternative for compose-heavy users.**

Option A is a non-starter (it's the current broken state). Option C is elegant but hits a subtle problem: Docker's events fire *after* the container is created, and `--dns` is a create-time flag that can't be set retroactively. Making C work reliably would need a docker plugin or a shim runtime — out of scope.

Option B has the cleanest story: user adds one line per service in compose, or uses a `compose.override.yml` snippet. portman's job is to make that one line *work* by being a competent DNS server.

### What "competent DNS server" means for a container's primary resolver

portman's DNS today answers for registered hosts and returns `NXDOMAIN` for everything else. That's fine when it's a *supplemental* resolver reached via `/etc/resolver/<tld>` on macOS. It is **not** OK as a container's primary DNS — the container would fail to resolve `github.com`, `pypi.org`, Docker registries, etc.

**Fix: portman DNS forwards unknown queries upstream.** hickory-server supports this via a `ForwardAuthority` or the resolver framework. Implementation: when a query isn't for a registered portman host, forward to one of:
- A user-configured upstream (`PORTMAN_UPSTREAM_DNS`)
- `1.1.1.1` / `8.8.8.8` as built-in fallbacks
- The system's existing DNS (read from `/etc/resolv.conf` — but macOS's is mostly empty)

Reasonable default: `1.1.1.1, 8.8.8.8`. User overrides via env or CLI flag.

### Where portman DNS binds

Currently: `127.0.0.1:5335`. Loopback on the macOS host.

From inside a container, `127.0.0.1:5335` means the container's own loopback — not the macOS host. So the current bind is unreachable.

Container → host reachability mechanisms on macOS:
- **Docker Desktop**: `host.docker.internal` → a specific Docker-assigned IP that routes to the host
- **Colima (lima-based)**: `host.docker.internal` mapped to the VM's gateway (`192.168.5.2` etc.)
- **Bridge gateway** (e.g. `172.17.0.1`): only reachable from containers on the default bridge; not universal

For a container to reach a macOS host port, the port must be bound on an interface reachable from the VM. Options:

1. **Bind to `0.0.0.0:5335`**. Simplest. Exposes DNS on LAN too — low-risk for local dev, but worth noting.
2. **Bind to the docker-mac-net-connect utun IP** (e.g. the utun's macOS side). Only reachable from containers via the WireGuard tunnel. More private but depends on the bridge being up.
3. **Bind to both `127.0.0.1` and the `host.docker.internal` IP** — cleanest but the latter varies by runtime and may change.

**Recommendation: (1) — bind DNS to `0.0.0.0:5335`.** Add a `--dns-bind 127.0.0.1` flag for users who want to restrict. Document the LAN-exposure caveat in the CLAUDE.md TLD section.

### Scenario 2 resolution: rewriting `127.0.0.1` for containers

Static rule says `crm.acme → 127.0.0.1:3070`. When a container queries DNS, portman should return something the container can route to — not literal `127.0.0.1`.

Two-part fix:

**(a)** The DNS response should return the host's container-facing IP, not `127.0.0.1`, when the **query source** is a container. hickory-server exposes `request.src()`; from it we know the source IP. If the source is in a container subnet (e.g. anything that isn't `127.0.0.1`), rewrite the answer.

Source-aware answer:
```
if target_ip == 127.0.0.1 and query_src != 127.0.0.1:
    return bridge_gateway_ip()  # e.g. 172.17.0.1
else:
    return target_ip             # unchanged
```

**(b)** What's `bridge_gateway_ip()` ? Depends on runtime. Empirically:
- Docker Desktop: `192.168.65.254` or similar — the VM gateway as seen from containers
- Colima: same pattern — `host.docker.internal` resolves to it
- Default docker bridge (docker0): `172.17.0.1`

Detecting this robustly at runtime is messy. Reasonable approach:
- Query `host.docker.internal` through the runtime's own DNS at startup, cache the result
- Or: shell out to `docker network inspect bridge` and parse `IPAM.Config[].Gateway`
- Or: accept a `PORTMAN_CONTAINER_HOST_IP` env var set at install time

**Recommendation: try runtime detection via `docker network inspect bridge` at daemon startup; fall back to the env var; ship with `host.docker.internal` hard-coded as a last resort (resolved at each query).**

### Static rule target "kind" — an open question

Currently `portman add` validates target as `ip:port` or `host:port`. A rule with target `127.0.0.1:3070` is what the *host user* wants. For container→host static to work, portman needs to know that this loopback target is "the host" and should be rewritten when answering container queries.

Two possible protocols:
- **Infer**: if target host is `127.0.0.1` / `localhost` / `::1`, treat as "host loopback"
- **Explicit**: grow the target syntax: `portman add crm.acme host:3070` where `host` is a literal keyword meaning "the machine running portman"

**Recommendation: infer for v1 of this feature** (loopback target → rewrite for container source). Consider the explicit form later if it turns out to be ambiguous.

## Phased implementation

### Phase A — DNS forwarding + all-interfaces bind (smallest ship)

Ship criterion: a container explicitly configured with `dns: <portman-host-ip>` can:
- Resolve `github.com` (and any other public hostname) — forwarding works
- Resolve `app.test` if `app` is a registered container — returns container IP
- Resolve `.acme` etc. too

Changes:
- `portman-daemon/src/dns.rs`: on `NXDOMAIN` for host not in registry, forward to upstream
- `--dns-upstream 1.1.1.1,8.8.8.8` CLI flag + `PORTMAN_DNS_UPSTREAM` env
- `--dns-bind 0.0.0.0` (default) / configurable
- Docs: recipe for compose — `dns: <host.docker.internal-or-ip>`
- Warn at daemon startup if upstream resolves to something on 127.x (likely the user has local-only DNS config that won't work)

**Non-goals for phase A**: source-aware rewriting, auto-injection, anything about `127.0.0.1` static rules.

### Phase B — source-aware `127.0.0.1` rewriting

Ship criterion: after phase A, with a static rule `crm.acme → 127.0.0.1:3070` and Rails running on host `:3070`, a container can `curl http://crm.acme` and reach Rails.

Changes:
- In `dns.rs`, the `resolve` path checks `request.src()` — if source is not loopback and target is loopback, rewrite to bridge gateway IP
- Daemon discovers bridge gateway IP at startup via `docker network inspect bridge` (bollard supports this); caches it
- New `Status` field: `container_host_ip: Option<String>` — surfaces in the menubar About pane so users can see what portman thinks the host IP is from a container's perspective
- Handles the rewrite also for HTTP proxy: if a container hits portman's proxy via the bridge gateway IP, proxy needs to route the backend correctly (already works — proxy uses the stored target; no change)

### Phase C — compose-friendly docs + `portman compose snippet` helper

Ship criterion: user copies a snippet from `portman compose` and gets working container DNS without understanding any of the above.

Changes:
- New CLI command: `portman compose snippet [--for <stack>]`. Prints:
  ```yaml
  x-portman-dns: &portman-dns
    dns:
      - host.docker.internal
  services:
    app:
      <<: *portman-dns
      # ... your service
  ```
- Docs: README section on container-side DNS with copy-paste recipes for the three most common shapes:
  - Single container (`docker run --dns=host.docker.internal ...`)
  - Docker Compose (the YAML anchor above)
  - Colima cluster-wide (`colima start --dns ...`)
- Discovery: `portman doctor` command that checks:
  - Daemon reachable?
  - docker-mac-net-connect running?
  - mkcert installed + CA trusted?
  - DNS forwarding working? (Run a test query for a public name against our DNS.)
  - Bridge gateway IP discovered?

**Phase C is mostly docs + ergonomics. It's what makes the feature *usable* vs *theoretically working*.**

### Phase D — auto-injection (DEFERRED — document but don't build)

What it would be: portman watches `container.create` events and somehow injects `--dns` before container start. Not straightforwardly possible with vanilla docker; would need a plugin, a wrapper CLI, or intercepting docker-compose itself. OrbStack does a version of this by running its own VM.

Defer until the feature has traction and the friction of phase C's "add this snippet to your compose" is actually measurable pain.

## Non-goals

- IPv6 support for container DNS — stay IPv4-only until someone asks
- Per-container DNS customization (e.g. "this container gets `.test` but not `.acme`") — not worth the UI
- Replacing `host.docker.internal` — it already works, no need
- DNSSEC — way out of scope
- mDNS interop — portman and Bonjour can coexist without talking to each other

## Edge cases + gotchas to beware

1. **A container's query for `something.orb.local`** when OrbStack is partially active will be ambiguous. portman should NXDOMAIN (or forward-then-NXDOMAIN if forwarding) for anything not in its registry — don't try to be clever.
2. **DNS caching in containers**: some images (Alpine glibc variants, Java-based) cache DNS aggressively. Document TTL behavior (portman's 30s TTL is short enough; JVM may still need `-Dnetworkaddress.cache.ttl=0` for rapid iteration).
3. **`--dns` and multiple resolvers**: users may have existing DNS config (corporate VPN, Tailscale). `dns:` in compose *replaces* the default list. Document that if they need corporate DNS too, they pass both.
4. **macOS firewall on `0.0.0.0:5335`**: first time the daemon binds to 0.0.0.0, macOS may prompt "Do you want portman-daemon to accept incoming network connections". The app is signed by the brew formula / the user's dev identity — needs handling in the install flow.
5. **Daemon running under launchd as root + bridge IP discovery**: `docker network inspect` needs docker socket access, which the daemon already has. No new permission needed.
6. **Colima restart changes bridge IPs**: if user does `colima stop && colima start`, the bridge gateway IP might change. Daemon should refresh on docker events (specifically `network.create` for the `bridge` network) or on first `no matching entry` cache miss.
7. **Rewriting `localhost` too**: if user registers `portman add foo.test localhost:3000`, resolve `localhost` → `127.0.0.1` before storing. Already done in validation? Verify.

## Touchpoints in existing code

Not a line-by-line guide — just where to start reading:

- **`crates/portman-daemon/src/dns.rs`**: `DnsHandler::handle_request` is where phase A's forwarding and phase B's source rewrite both land
- **`crates/portman-daemon/src/main.rs`**: `connect_docker` auto-detects the docker socket — add a `discover_bridge_gateway` step after it for phase B
- **`crates/portman-daemon/src/docker_events.rs`**: watch for `network.create` on `bridge` to invalidate the cached gateway IP
- **`crates/portman-protocol/src/lib.rs`**: `Response::Status` grows `container_host_ip: Option<String>`
- **`crates/portman-cli/src/main.rs`**: new `compose`, `doctor` subcommands for phase C
- **`macos/Portman/Sources/Portman/*.swift`**: show container-host IP in the About pane; no other UI work needed for phases A+B

## Suggested ordering + timebox

A single engineer-session:

| Phase | Estimate | Dependencies |
|---|---|---|
| A: forwarding + 0.0.0.0 bind | 3-4h | none |
| B: source-aware rewriting | 3-5h | phase A |
| C: docs + `portman compose` + `portman doctor` | 2-3h | phases A+B |
| D: auto-injection | (deferred) | |

Total phases A+B+C: one intense day or two moderate sessions. Each phase is committable and shippable on its own.

## Ship criterion for the whole feature

Running on a clean macOS + colima + portman install:

```bash
# Phase A: forwarding works
$ docker run --rm --dns=host.docker.internal alpine sh -c 'nslookup github.com'
# resolves

# Phase A: container resolves portman hostname
$ portman tld add test
$ docker run -d --label dev.portman.host=db.test --label dev.portman.port=5432 postgres
$ docker run --rm --dns=host.docker.internal alpine sh -c 'nslookup db.test'
# returns the db container's IP

# Phase B: container → host static
$ portman add rails.acme 127.0.0.1:3070
$ (host) bin/dev  # rails listening on :3070
$ docker run --rm --dns=host.docker.internal alpine sh -c 'wget -qO- http://rails.acme'
# returns rails's response

# Phase C: a fresh user reads `portman compose snippet`, pastes into their
# docker-compose.yml, runs `docker compose up`, and cross-service calls work
```

Those three commands, working end-to-end, are v0.3.
