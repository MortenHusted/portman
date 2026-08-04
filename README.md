# portman

**The single local-dev daemon**: automatic wildcard DNS, an HTTP/TLS proxy, direct-to-container routing, and a native service runner — for macOS (and, experimentally, Linux).

Name your Docker containers with two labels and browse to `http://myapp.test` — no port-forwarding, no `/etc/hosts` edits. Declare host services (Rails, Node, your Rust binaries) in a per-repo `portman.toml` and one daemon supervises them, composes their environment hermetically, resolves their secrets through machine identities, derives their DNS/proxy routes, and shows their logs and resource gauges in a CLI, a TUI, and a web dashboard.

Positioned against OrbStack's networking/DNS features — but open source, with **no container-runtime lock-in** (bring colima, lima, Docker Desktop, or native Docker on Linux) and **no subscription**. The service runner side replaces the foreman/overmind/pitchfork layer: one daemon owns the service record, and everything else derives from it.

## Why

Three things OrbStack users miss the moment they switch runtime, plus one thing OrbStack never did:

1. **Automatic DNS** — a container labelled `dev.portman.host=myapp.test` resolves instantly. Stop the container, the name stops resolving. No stale state.
2. **No port-forwarding** — a native WireGuard bridge makes container IPs routable from the host, so you hit the container's real port directly.
3. **A dashboard** — see everything that's running, where it routes, and what it's consuming, at `http://127.0.0.1:7341`.
4. **Host services are first-class** — apps running directly on the host get the same hostnames, TLS, supervision, and visibility as containers. OrbStack is container-only.

## Quickstart

### Containers: two labels, done

```bash
git clone https://github.com/MortenHusted/portman && cd portman
portman install            # builds release binaries, installs the launchd daemon (sudo)
portman tld add test       # manage the .test TLD (writes /etc/resolver/test)
portman bridge mode docker && portman bridge enable   # macOS: route container IPs

docker run -d -l dev.portman.host=myapp.test -l dev.portman.port=80 nginx
open http://myapp.test     # no port, no /etc/hosts, no compose file
```

### Host services: one `portman.toml`

In any repo, declare your stack once:

```toml
[service.web]
run = "bin/rails server -p 3000"
port = 3000
host = "myapp.test"        # DNS + proxy route derives from this
depends = ["db"]

[service.db]
run = ["postgres", "-D", "data"]
port = 5432
mode = "tcp"
```

```bash
portman up          # start in dependency order, wait for readiness
portman logs web -f # live tail
portman down        # stop the repo's stack
```

`http://myapp.test` now hits your Rails server, the daemon restarts it if it crashes, and it shows up in the TUI (`portman tui`) and dashboard with CPU/memory gauges next to your containers.

## Install

Prereqs: a Rust toolchain (`rustup` or [mise](https://mise.jdx.dev) — the repo pins one via `mise install`), a Docker runtime if you want container routing, and [`mkcert`](https://github.com/FiloSottile/mkcert) if you want local TLS.

### macOS

```bash
portman install          # builds binaries, installs a root LaunchDaemon, builds the bridge setup image
portman tld add test
portman dashboard        # opens http://127.0.0.1:7341
```

`portman uninstall` removes the launchd service and binaries. portman's data dir (`~/Library/Application Support/portman`) holds `static.json`, `tls.json`, `certs/`, and — for the service runner — `services.json` (definitions + desired state), `logs.db` (captured service output), and `credentials.json` (secrets-provider machine credentials, 0600). Delete it yourself if you want a clean slate.

### Linux (experimental)

Requires Docker, systemd, and (recommended) systemd-resolved. Container IPs are natively routable, so there is no bridge — DNS and proxy work the same way.

```bash
portman install          # builds binaries and installs a systemd unit
sudo portman tld add test
portman dashboard
```

TLD registration writes a portman-managed drop-in under `/etc/systemd/resolved.conf.d/` and reloads `systemd-resolved`. Linux compiles and passes CI but has had far less end-to-end mileage than macOS.

## Security model

Local-dev networking needs privileges; portman keeps them explicit and inspectable:

- **The daemon runs as root** (a LaunchDaemon on macOS) — that's what binding `:80`/`:443` and owning the bridge requires. Supervised services are spawned **as your login user**, never as root, each in its own process group with a hermetic environment.
- **The CLI performs the privileged filesystem writes** (`/etc/resolver/<tld>`, launchd plists) via explicit `sudo`, with marker checks so portman only ever overwrites files portman wrote. A resolver file managed by something else (e.g. VPN split-DNS) is a refusal, not a clobber.
- **TLD registration is opt-in per TLD** — a container label under an unmanaged TLD is ignored with a warning rather than silently reshaping your DNS.
- **The IPC socket** (`portman.sock`) is mode 0660 and peer-credential-gated to root and the owning user. **The dashboard** binds loopback only and validates Host/Origin.
- **Secrets** never live in repo config — `portman.toml` carries provider *coordinates* only; machine credentials (Infisical universal-auth, 1Password service accounts) are stored 0600 in the daemon's data dir, written via `portman secrets set-*` reading from stdin.
- **Optional:** `scripts/setup-sudoers.sh` installs a narrow NOPASSWD sudoers fragment so `portman install` runs unattended. Read it before installing it; nothing requires it.

## Service runner (`portman.toml`)

Declare host services in a committed `portman.toml` at your repo root; a gitignored `portman.local.toml` beside it overlays personal changes as a **field-level patch**: a local `[service.<name>]` only needs the fields it changes, and everything it omits keeps the committed value. The patch is per *field*, not per element — a collection field the overlay mentions (`env`, `env_files`, `depends`, `secrets`, `groups`) replaces the committed value wholesale. A service only the local file declares must carry `run`. Either file alone is valid.

```bash
portman up            # sync config, start in dependency order, wait for readiness
portman status        # daemon status + every supervised service
portman status --repo # only this repo's services
portman logs web -f   # live tail (also in the TUI [4] panel and the dashboard)
portman down          # stop this repo's stack
portman down --forget # stop and remove this repo's synced definitions
portman down --forget --root /old/worktree # forget a moved/deleted checkout
```

The full field set:

```toml
[service.web]
run = "bin/server --config conf/dev.toml"   # string (shell-split, no shell) or argv array
dir = "app"              # working dir, relative to this file (default: repo root)
port = 3000              # the port the service listens on
host = "web.test"        # optional: derive the DNS/proxy route while the service is up
mode = "http"            # "http" (default, proxied by Host header) or "tcp"
ready_port = 3000        # readiness gate (default: `port`); or ready_delay_ms = 500
depends = ["db"]         # started first, gated on their readiness
retry = true             # true = restart forever (default), false = never, N = max retries
stop_grace_ms = 5000     # SIGTERM → SIGKILL grace
env_files = ["deploy/base.env", ".env"]     # applied in order, later wins
env = { RAILS_ENV = "development" }         # inline env — the last (winning) layer
secrets = ["myapp"]      # [secrets.<name>] blocks to pull from
secrets_optional = true  # provider failure ⇒ start from env_files only, flagged in status
watch = ["dist/bin/server", "conf/*.toml"]  # respawn when these change (relative to `dir`)
watch_mode = "poll"      # "poll" (default) or "native" (FSEvents/inotify)
watch_debounce_ms = 500  # quiet period after the last change before respawning
groups = ["backend"]     # free-form tags for dashboard/TUI grouping

[service.db]
run = ["postgres", "-D", "data"]
port = 5432
mode = "tcp"

# Provider coordinates only — machine credentials live in portman's own
# 0600 store, never in repo config:
#   portman secrets set-infisical --client-id <id>     # secret read from stdin
#   portman secrets set-op                             # token read from stdin
[secrets.myapp]
provider = "infisical"                       # or "1password" with a `refs` table
url = "https://secrets.example.com"          # self-hosted or cloud
project_id = "…"
environment = "dev"
paths = ["/apps/myapp", "/shared"]           # first path wins on duplicate keys
# api_version = "v4"                         # default "v3" (works on self-hosted)
# mode = "cli"                               # fall back to `infisical export`

# [secrets.op]
# provider = "1password"
# [secrets.op.refs]
# API_KEY = "op://vault/item/field"          # resolved via `op` + service-account token
```

**Hermetic environments.** A service's env is a minimal base (fixed PATH, HOME, USER, TMPDIR) plus only the declared sources — nothing inherited from the daemon, your shell, mise, or ambient `.env` files. Composition is deterministic: base → `env_files` (in order) → secrets providers → inline `env`, later wins. A missing `env_file` fails the start; a secrets-provider outage retries under the restart policy (transient) or fails the service (auth rejection) — unless `secrets_optional` opts into the env-files-only fallback, flagged in `portman status`.

**Watch = intentional respawn.** A service that declares `watch` respawns when any of those paths changes — rebuild the binary and portman cycles it. A watch hit spends no restart budget, skips pending backoff, and revives a service that had reached `Failed`. The one state it won't act on is a service you stopped yourself — `portman down` is sticky until you bring it back up. `poll` is the default backend because builds replace their output by rename, which native watchers follow to the old inode; polling compares mtime at whole-second resolution, so use `native` if you need finer.

**Supervision.** Services run as your login user in their own process group, restart with exponential backoff, and survive daemon restarts (desired state persists; orphaned process groups from an unclean daemon exit are identity-checked, terminated, and respawned — never adopted). Captured stdout/stderr lands in a queryable store with retention; CPU/mem/pid gauges appear next to the Docker containers in the TUI and dashboard. Service names are global across repos; the `host` field is gated on managed TLDs exactly like `portman add`.

## Static rules and wildcards

Anything not in a `portman.toml` can still get a hostname:

```bash
portman add myapp.test 127.0.0.1:3070        # HTTP, routed by Host header
portman add db.test 172.17.0.2:5432 --tcp    # TCP, dedicated loopback front
portman add api.test 127.0.0.1:9000 --project acme   # joins the dashboard's project filter
portman remove myapp.test
```

A rule can cover a whole label with `*`, so a fleet of names reaches one backend without registering each:

```bash
portman add "*.demo.acme.internal" 127.0.0.1:3070   # quote it — the shell eats bare *
portman add ingress.acme.internal  127.0.0.1:3070
```

`1.demo…`, `7.demo…` and anything else under that label now resolve, and the backend sees the `Host:` it was sent — a host-routing gate behind portman keeps doing its own dispatch, exactly as it would behind real DNS. Matching follows DNS and RFC 6125 rather than glob habits:

- **One label, leftmost only.** `*.demo.test` covers `1.demo.test`, but not the apex `demo.test` and not `a.b.demo.test`.
- **Exact beats wildcard**, and the longest matching wildcard wins — `*.demo.acme.internal` outranks `*.acme.internal`.
- **HTTP mode only.** TCP entries need a dedicated loopback front per hostname, which a pattern can't supply; `--tcp` with a wildcard is rejected rather than half-working.

## TLS

TLS is configured per TLD, backed by [`mkcert`](https://github.com/FiloSottile/mkcert)'s local CA:

```bash
mkcert -install                    # once: trust the local CA in your browsers
portman tld add test --tls mkcert  # every hostname under .test gets HTTPS
```

Certs are issued automatically as hostnames appear, including **one wildcard cert per wildcard rule** — the cert covers exactly what the route covers. Note mkcert's inherent limit: the CA lives in *your* trust store, so container-to-container HTTPS needs the CA mounted into each container. A Let's Encrypt DNS-01 mode for real domains is designed but not yet implemented.

## Containers calling the host

For host services from inside a container, Docker's normal callback name works: `host.docker.internal:<port>`. On macOS with the native bridge enabled, portman also exposes container-facing DNS/HTTP/TLS on `192.168.99.1`. See [`docs/release-readiness.md`](./docs/release-readiness.md).

## Status & roadmap

Daily-driven on macOS (the author's full multi-repo stack runs under it). Honest edges:

- **Linux**: compiles, tested in CI, structurally supported (systemd-resolved, `CAP_NET_BIND_SERVICE`) — but young end-to-end.
- **Container-to-container DNS** (containers resolving each other's portman names): designed, not yet built — see [`docs/c2c-implementation-brief.md`](./docs/c2c-implementation-brief.md).
- **Let's Encrypt TLS mode**: reserved, not yet implemented.
- Architecture and design decisions: [`CLAUDE.md`](./CLAUDE.md) and [`CONCEPTS.md`](./CONCEPTS.md); verification matrix: [`docs/release-readiness.md`](./docs/release-readiness.md).

## Repo layout & development

```
crates/
  portman-protocol/  # IPC types + framing shared between daemon, CLI, and dashboard
  portman-core/      # Registry, config, stores, platform abstraction
  portman-daemon/    # Docker watcher, DNS, proxy, TLS, supervisor, web dashboard
  portman-cli/       # `portman` command-line client + TUI
  portman-netbridge/ # macOS-only native WireGuard bridge
```

Development runs through [mise](https://mise.jdx.dev):

```bash
mise install        # pinned Rust
mise run ci         # fmt + clippy -D warnings + tests + setup-image check (the CI gate)
mise run daemon     # run the daemon locally
mise run dashboard  # open http://127.0.0.1:7341
```

GitHub Actions runs the same checks on Ubuntu and macOS.

## License

MIT — see [LICENSE](./LICENSE).
