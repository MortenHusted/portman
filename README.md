# portman

A local-dev daemon for macOS (and, experimentally, Linux). It gives your containers and host apps real hostnames with wildcard DNS, proxies HTTP/TLS to them, routes traffic to container IPs directly, and can supervise the host services you declare in a per-repo `portman.toml`.

The short version: label a Docker container with `dev.portman.host=myapp.test` and `dev.portman.port=3000`, and `http://myapp.test` works in your browser. No port-forwarding, no `/etc/hosts` edits. Put a `portman.toml` in a repo and `portman up` starts that stack in dependency order, restarts crashes, composes each service's environment from declared sources only, pulls secrets through machine identities, and shows logs and resource gauges in the CLI, a TUI, and a web dashboard.

portman exists because OrbStack's networking is genuinely nice, and I wanted those conveniences while running colima. OrbStack bundles them with its own container runtime; portman is just the networking and supervision glue, so it works with whatever runtime you already use (colima, lima, Docker Desktop, native Docker on Linux). It also grew into a replacement for the foreman/overmind/pitchfork layer, since the same daemon that owns the routes can own the processes behind them.

## What it does

1. **Automatic DNS.** A container labelled `dev.portman.host=myapp.test` resolves as soon as it starts, and stops resolving when it stops.
2. **No port-forwarding.** On macOS, a WireGuard-based bridge makes container IPs routable from the host, so you reach the container's own port. On Linux the kernel already does this.
3. **Host services too.** Apps running directly on the host (Rails, Node, your own binaries) get the same hostnames, TLS, supervision, and visibility as containers.
4. **A dashboard.** Everything that's running, where it routes, and what it's consuming, at `http://127.0.0.1:7341`.

## Quickstart

### Containers

```bash
brew install MortenHusted/tap/portman
portman install            # wires up the system daemon (sudo)
portman tld add test       # manage the .test TLD (writes /etc/resolver/test)
portman bridge mode docker && portman bridge enable   # macOS: route container IPs

docker run -d -l dev.portman.host=myapp.test -l dev.portman.port=80 nginx
open http://myapp.test
```

### Host services

In any repo, declare the stack once:

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

`http://myapp.test` now reaches your Rails server. The daemon restarts it if it crashes, and it shows up in the TUI (`portman tui`) and dashboard with CPU/memory gauges next to your containers.

## Install

Three ways to get the binaries; all of them are followed by `portman install`, which wires up the system service (a root LaunchDaemon on macOS, a systemd unit on Linux). `portman install` works from installed binaries — no checkout needed.

```bash
# Homebrew (macOS and Linux)
brew install MortenHusted/tap/portman

# Shell installer
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/MortenHusted/portman/releases/latest/download/portman-installer.sh | sh

# From source (needs a Rust toolchain — rustup, or mise via `mise install`)
git clone https://github.com/MortenHusted/portman && cd portman && cargo build --release -p portman
```

Optional extras: a Docker runtime if you want container routing, and [`mkcert`](https://github.com/FiloSottile/mkcert) if you want local TLS.

### macOS

```bash
portman install          # installs binaries + root LaunchDaemon, builds the bridge setup image
portman tld add test
portman dashboard        # opens http://127.0.0.1:7341
```

`portman uninstall` removes the launchd service and binaries. portman's data dir (`~/Library/Application Support/portman`) holds `static.json`, `tls.json`, `certs/`, and, for the service runner, `services.json` (definitions + desired state), `logs.db` (captured service output), and `credentials.json` (secrets-provider machine credentials, 0600). Delete it yourself if you want a clean slate.

### Linux (experimental)

Requires Docker, systemd, and (recommended) systemd-resolved. Container IPs are natively routable, so there is no bridge; DNS and proxy work the same way.

```bash
portman install          # builds binaries and installs a systemd unit
sudo portman tld add test
portman dashboard
```

TLD registration writes a portman-managed drop-in under `/etc/systemd/resolved.conf.d/` and restarts `systemd-resolved` (reload does not re-read drop-ins). There's a step-by-step walkthrough in [`docs/install-linux.md`](./docs/install-linux.md). CI runs an end-to-end job on Ubuntu (install, resolved integration, proxy, service runner, container routing), but Linux has had much less real-world use than macOS. Expect rough edges and please file what you hit.

## Security model

Local-dev networking needs privileges. Here is exactly what portman takes and why:

- The daemon runs as root (a LaunchDaemon on macOS), because binding `:80`/`:443` and owning the bridge requires it. Supervised services are spawned as your login user, never as root, each in its own process group with a hermetic environment.
- The CLI performs the privileged filesystem writes (`/etc/resolver/<tld>`, launchd plists) via explicit `sudo`, with marker checks so portman only ever overwrites files portman wrote. A resolver file managed by something else (a VPN's split-DNS, say) is a refusal, not a clobber.
- TLD registration is opt-in per TLD. A container label under an unmanaged TLD is ignored with a warning rather than silently reshaping your DNS.
- The IPC socket (`portman.sock`) is mode 0660 and peer-credential-gated to root and the owning user. The dashboard binds loopback only and validates Host/Origin.
- The dashboard's `/api/*` routes require a bearer token (0600 in the daemon's data dir, owned by your login user). Loopback keeps the network out, not other local processes, and those routes read captured logs and write repo config. `portman dashboard` passes the token to the browser; scripts send `Authorization: Bearer $(cat …/dashboard-token)`. `--dashboard-auth=false` turns it off for development.
- Secrets never live in repo config. `portman.toml` carries provider coordinates only; machine credentials (Infisical universal-auth, 1Password service accounts) are stored 0600 in the daemon's data dir, written via `portman secrets set-*` reading from stdin.
- Values portman hands a service are masked in that service's captured output before it is stored, so the log store never becomes a second copy of a secret. Exact-value matching, so a value the service transforms before printing is not caught.
- Optionally, `scripts/setup-sudoers.sh` installs a narrow NOPASSWD sudoers fragment so `portman install` runs unattended. Read it before installing it; nothing requires it.

## Service runner (`portman.toml`)

Declare host services in a committed `portman.toml` at your repo root. A gitignored `portman.local.toml` beside it overlays personal changes as a field-level patch: a local `[service.<name>]` only needs the fields it changes, and everything it omits keeps the committed value. The patch is per field, not per element, so a collection field the overlay mentions (`env`, `env_files`, `depends`, `secrets`, `groups`) replaces the committed value wholesale. A service only the local file declares must carry `run`. Either file alone is valid.

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

### Authenticated egress (`[egress.<name>]`)

An egress route is a local hostname that proxies to an **external** upstream
with a credential attached — the caller never holds the value. This is the
same shape as an authenticated reverse proxy in front of a REST API: a local
process that can reach the hostname gets an authenticated request without the
token ever entering its environment, a config file, or a log.

```toml
[secrets.github]
provider = "1password"
[secrets.github.refs]
TOKEN = "op://dev/github/token"

[egress.github]
host = "github.api.test"          # local hostname callers address (managed TLD)
target = "api.github.com:443"     # external upstream host:port
secrets = "github"                # [secrets.<name>] block the value comes from
key = "TOKEN"                     # key within that block
# header = "Authorization"        # default
# format = "Bearer {value}"       # default; must contain {value}
# upstream_host = "api.github.com" # Host header the upstream sees (default: target hostname)
tls = true                        # required unless target is the local machine
```

Calling `curl http://github.api.test/user` forwards to `api.github.com` over
TLS as `Authorization: Bearer <token>` with `Host: api.github.com`; the
caller's own auth headers are stripped first, so the injected credential is
the only one that arrives. Routes are reached over plain `http://` on `:80`
— portman originates TLS to the upstream itself; the `:443` listener refuses
egress hosts.

Semantics worth knowing:

- **The credential is resolved at proxy time**, per request, through the
  same secrets cache services use, and registered with the log masker. If
  the block, key, or value is unavailable (or the value resolves empty), the
  route refuses with `502` before connecting — it never forwards
  unauthenticated.
- **TLS is required for non-loopback targets.** Sending a credential
  cleartext across a real network boundary is refused at config load, not
  just discouraged. Loopback targets (e.g. a local mock) may set
  `tls = false`.
- **The caller is not authenticated.** Any local process that can reach the
  proxy port can use the route — that is the point. What portman refuses is
  *cross-origin* callers: a browser page from another site (`Origin` /
  `Sec-Fetch-Site: cross-site`) gets `403` before the credential is
  resolved, mirroring the Start-button guard.
- Route names are global like service names (a second repo claiming the
  same name is refused), and the `host` must sit under a managed TLD, like
  service routes. A changed `host` releases the old hostname; removing the
  block unregisters the route on the next `portman up`.

A few semantics worth knowing before you rely on them:

**Environments are hermetic.** A service's env is a minimal base (fixed PATH, HOME, USER, TMPDIR) plus only the declared sources. Nothing is inherited from the daemon, your shell, mise, or ambient `.env` files. Composition is deterministic: base, then `env_files` in order, then secrets providers, then inline `env`, later wins. A missing `env_file` fails the start. A secrets-provider outage retries under the restart policy if it looks transient, or fails the service on auth rejection, unless `secrets_optional` opts into the env-files-only fallback (flagged in `portman status`).

**Watch means an intentional respawn, not a crash.** A service that declares `watch` respawns when any of those paths changes; rebuild the binary and portman cycles it. A watch hit spends no restart budget, skips pending backoff, and revives a service that had reached `Failed`. The one state it won't act on is a service you stopped yourself: `portman down` is sticky until you bring it back up. `poll` is the default backend because builds replace their output by rename, which native watchers follow to the old inode. Polling compares mtime at whole-second resolution, so use `native` if you need finer.

**Supervision survives the daemon.** Services run as your login user in their own process group and restart with exponential backoff. Desired state persists across daemon restarts; orphaned process groups from an unclean daemon exit are identity-checked, terminated, and respawned, never adopted. Captured stdout/stderr lands in a queryable store with retention. Service names are global across repos, and the `host` field is gated on managed TLDs exactly like `portman add`.

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

`1.demo…`, `7.demo…` and anything else under that label now resolve, and the backend sees the `Host:` it was sent, so a host-routing gate behind portman keeps doing its own dispatch exactly as it would behind real DNS. Matching follows DNS and RFC 6125 rather than glob habits:

- One label, leftmost only. `*.demo.test` covers `1.demo.test`, but not the apex `demo.test` and not `a.b.demo.test`.
- Exact beats wildcard, and the longest matching wildcard wins: `*.demo.acme.internal` outranks `*.acme.internal`.
- HTTP mode only. TCP entries need a dedicated loopback front per hostname, which a pattern can't supply; `--tcp` with a wildcard is rejected rather than half-working.

## TLS

TLS is configured per TLD, backed by [`mkcert`](https://github.com/FiloSottile/mkcert)'s local CA:

```bash
mkcert -install                    # once: trust the local CA in your browsers
portman tld add test --tls mkcert  # every hostname under .test gets HTTPS
```

Certs are issued automatically as hostnames appear, including one wildcard cert per wildcard rule, so the cert covers exactly what the route covers. mkcert has an inherent limit worth knowing: the CA lives in your trust store, so container-to-container HTTPS needs the CA mounted into each container. A Let's Encrypt DNS-01 mode for real domains is designed but not yet implemented.

## Containers calling the host

For host services from inside a container, Docker's normal callback name works: `host.docker.internal:<port>`. On macOS with the native bridge enabled, portman also exposes container-facing DNS/HTTP/TLS on `192.168.99.1`. See [`docs/release-readiness.md`](./docs/release-readiness.md).

## Status

I run my full multi-repo stack under portman daily on macOS; that is the main body of testing it has. Known limits:

- Linux compiles, passes unit tests, and has an end-to-end CI job, but very little real-world use. Treat it as experimental.
- Container-to-container DNS (containers resolving each other's portman names) is designed but not built. See [`docs/c2c-implementation-brief.md`](./docs/c2c-implementation-brief.md).
- Let's Encrypt TLS mode is reserved in the config schema but not implemented.

Architecture and design decisions live in [`CLAUDE.md`](./CLAUDE.md) and [`CONCEPTS.md`](./CONCEPTS.md); the verification matrix is [`docs/release-readiness.md`](./docs/release-readiness.md).

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

GitHub Actions runs the same checks on Ubuntu and macOS, plus the Ubuntu end-to-end job.

## Authorship

This project is written end to end by LLMs (Claude), evolved over long working sessions and used daily as my own dev stack. I direct, review, and run everything; the code, tests, and docs are machine-written. Read it with the same skepticism you'd apply to any code you didn't write — the test suite and the CI jobs are there to be checked.

## License

MIT — see [LICENSE](./LICENSE).
