# portman

The single local-dev daemon: DNS + HTTP proxy **and** a native service runner for macOS and Linux development. Automatic wildcard hostnames for your Docker containers **and** for apps running directly on the host, plus per-repo `portman.toml` service definitions that drive process supervision, hermetic env composition (env files + secrets providers), derived routes, and logs/resource visibility. OSS, no container-runtime lock-in, no subscription.

Positioned against OrbStack's networking/DNS features — bring your own runtime (colima, limactl, Docker Desktop, native Docker on Linux) and let portman handle the networking glue. The service runner replaces the pitchfork/overmind/foreman layer for host services: one daemon owns the service record, and DNS, proxy, supervision, and secrets all derive from it.

## Status

**Prototype implementation.** The Rust daemon, CLI/TUI, embedded web dashboard, DNS/HTTP/TLS paths, and native netbridge (macOS) are present. Linux support uses systemd-resolved drop-ins and skips the VM bridge entirely. See [`PLAN.md`](./PLAN.md) for the shipping roadmap and [`CLAUDE.md`](./CLAUDE.md) for architectural decisions.

## Repo layout

```
crates/
  portman-protocol/  # IPC types shared between daemon, CLI, and dashboard
  portman-core/      # Registry, platform abstraction
  portman-daemon/    # Docker watcher, DNS, HTTP proxy, web dashboard
  portman-cli/       # `portman` command-line client + TUI
  portman-netbridge/ # macOS-only native WireGuard bridge
```

## Development

Requires [mise](https://mise.jdx.dev) for toolchain + tasks.

```bash
mise install        # install pinned Rust
mise run check      # fast type-check
mise run lint       # clippy -D warnings
mise run test       # cargo test
mise run setup-image:check
mise run ci         # Rust fmt/lint/tests + setup-image check
mise run daemon     # run the daemon locally
mise run cli -- list
mise run dashboard  # open http://127.0.0.1:7341
```

## Web dashboard

When the daemon is running, open the embedded UI at `http://127.0.0.1:7341` or run:

```bash
portman dashboard
```

The dashboard lists entries, supports adding/removing static rules, shows TLD/TLS state, and displays Docker resource usage.

## Install

### macOS

```bash
portman install          # builds binaries, launchd daemon, setup image
portman tld add test
portman dashboard
```

portman's data dir (`~/Library/Application Support/portman`) holds
`static.json`, `tls.json`, `certs/`, and — for the service runner —
`services.json` (definitions + desired state), `logs.db` (captured service
output), and `credentials.json` (secrets-provider machine credentials,
0600). `portman uninstall` removes the launchd service; delete the data dir
yourself if you want a clean slate.

### Linux

Requires Docker, systemd, and (recommended) systemd-resolved.

```bash
portman install          # builds binaries and installs systemd unit
sudo portman tld add test
portman dashboard
```

TLD registration writes a portman-managed drop-in under `/etc/systemd/resolved.conf.d/` and reloads `systemd-resolved`.

## Default Docker Bridge Driver (macOS)

For the recommended docker-mac-net-connect replacement path, keep services
labelled with `dev.portman.host` and switch Portman into Docker bridge mode:

```bash
portman install
portman bridge mode docker
portman bridge enable
portman doctor
```

`docker` mode routes Docker bridge networks that contain Portman-labelled
containers. On Linux, container IPs are natively routable — bridge commands are
macOS-only.

## Service runner (`portman.toml`)

Declare host services in a committed `portman.toml` at your repo root; a
gitignored `portman.local.toml` beside it overlays personal services as a
**field-level patch**: a local `[service.<name>]` only needs the fields it
changes (`env_files = [".env"]` alone is enough), and everything it omits keeps
the committed value. The patch is per *field*, not per element — a collection
field the overlay mentions (`env`, `env_files`, `depends`, `secrets`, `groups`)
replaces the committed value wholesale, so a local `env` must restate any
committed vars it still wants. A service only the local file declares must
carry `run`.
Either file alone is valid. Then:

```bash
portman up            # sync config, start in dependency order, wait for readiness
portman status        # daemon status + every supervised service
portman status --repo # daemon status + only this repo's services
portman logs web -f   # live tail (also in the TUI [4] panel and the dashboard)
portman down          # stop this repo's stack
portman down --forget # stop and remove this repo's synced definitions
portman down --forget --root /old/worktree # forget a moved/deleted checkout
```

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
secrets = ["pacer"]      # [secrets.<name>] blocks to pull from
secrets_optional = true  # provider failure ⇒ start from env_files only, flagged in status
watch = ["dist/bin/server", "conf/*.toml"]  # respawn when these change (relative to `dir`)
watch_mode = "poll"      # "poll" (default) or "native" (FSEvents/inotify)
watch_debounce_ms = 500  # quiet period after the last change before respawning

[service.db]
run = ["postgres", "-D", "data"]
port = 5432
mode = "tcp"

# Provider coordinates only — machine credentials live in portman's own
# 0600 store, never in repo config:
#   portman secrets set-infisical --client-id <id>     # secret read from stdin
#   portman secrets set-op                             # token read from stdin
[secrets.pacer]
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

### Wildcard hostnames

A rule can cover a whole label with `*`, so a fleet of names reaches one backend
without registering each:

```sh
portman add "*.demo.acme.internal" 127.0.0.1:3070   # quote it — the shell eats bare *
portman add ingress.acme.internal    127.0.0.1:3070
```

`1.demo…`, `7.demo…` and anything else under that label now resolve with no
further registration, and the backend sees the `Host:` it was sent — so a
host-routing gate behind portman keeps doing its own dispatch, exactly as it
would behind real DNS.

Matching follows DNS and RFC 6125 rather than glob habits:

- **One label, leftmost only.** `*.demo.test` covers `1.demo.test`, but not
  the apex `demo.test` and not `a.b.demo.test`. Give the apex its own entry
  if it needs to resolve.
- **Exact beats wildcard**, and the longest matching wildcard wins — so
  `*.demo.acme.internal` outranks `*.acme.internal`.
- **HTTP mode only.** TCP entries get a dedicated loopback front per hostname,
  which a pattern can't supply; `--tcp` with a wildcard is rejected rather than
  half-working.

Under a TLS-enabled TLD, portman issues **one** wildcard cert for the pattern
rather than a cert per name — matching the routing rule exactly, so any name that
routes is a name the cert covers.

Service environments are **hermetic**: a minimal base (fixed PATH, HOME,
USER, TMPDIR) plus only the declared sources — nothing inherited from the
daemon, your shell, mise, or cwd-ambient `.env` files. Composition order is
deterministic: base → `env_files` (in order) → secrets providers → inline
`env`, later wins. A missing `env_file` fails the start; a secrets-provider
outage retries under the restart policy (transient) or fails the service
(auth rejection) — unless `secrets_optional` opts into the env-files-only
fallback, which is flagged in `portman status`.

A service that declares `watch` respawns when any of those paths changes —
rebuild the binary and portman cycles it for you. A watch hit is an
*intentional* respawn, not a crash: it spends no restart budget, skips any
pending backoff, and revives a service that had already reached `Failed`. The
one state it will not act on is a service you stopped yourself — `portman
down` is sticky until you bring it back up. `poll` is the default backend
because a build replaces its output by rename, which a native watcher follows
to the old inode; note that polling compares mtime at whole-second resolution,
so two rebuilds inside the same second look identical to it. Use `native` when
you need finer resolution or are watching a large directory.

Services run as your login user in their own process group, restart with
exponential backoff, and survive daemon restarts (desired state persists;
orphaned process groups from an unclean daemon exit are identity-checked,
terminated, and respawned — never adopted). Captured stdout/stderr lands in
a queryable store with retention (`portman logs`, TUI, dashboard); CPU/mem/
pid gauges appear next to the Docker containers in the TUI Activity panel
and dashboard. Service names are global across repos; the `host` field is
gated on managed TLDs exactly like `portman add`.

## Containers Calling The Host

For arbitrary host services from a container, use Docker's normal callback
name:

```text
host.docker.internal:<port>
```

On macOS with the native bridge enabled, Portman exposes container-facing services on `192.168.99.1` for DNS/HTTP/TLS. See [`docs/release-readiness.md`](./docs/release-readiness.md) for details.

## Verification

The safe local baseline is `mise run ci`. GitHub Actions runs the same Rust checks on Ubuntu and macOS.

Release readiness is tracked in [`docs/release-readiness.md`](./docs/release-readiness.md).

## License

MIT — see [LICENSE](./LICENSE).
