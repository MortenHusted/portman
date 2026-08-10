# Release Readiness

Portman is still an implemented prototype under quality review. This document
is the durable verification contract: it states what the safe CI baseline
proves, what still needs live manual validation, and which risks block calling
the project main-driver safe.

## Safe Baseline

Run before every commit:

```bash
mise run ci
```

`mise run ci` covers:

- `mise run fmt:check`
- `mise run lint`
- `mise run test`
- `mise run ci`
- `mise run setup-image:check`

This baseline is intentionally safe. It does not write `/etc/resolver`, run
`launchctl`, call `sudo`, enable the native bridge, mutate route tables, create
Docker networks/containers, or build Docker images.

## Netbridge Modes

The native netbridge is intentionally mode-gated:

- `opt-in` is the default and only routes Portman's dedicated `portman` Docker
  network (`192.168.99.0/24`). Existing compose default networks are untouched.
- `docker` is the docker-mac-net-connect replacement path. It discovers running
  containers with `dev.portman.host`, finds their Docker bridge networks, and
  routes those bridge subnets through Portman's tunnel without requiring
  `networks: [portman]`.
- `all` is explicit full-replacement mode for every active Docker bridge
  network with containers. It is available as an escape hatch, not a default.

Migration path for labelled services on existing compose/default networks:

```bash
portman install
portman bridge mode docker
portman bridge enable
portman doctor
```

`portman install` builds the `portman-netbridge/setup:local` image from the
checkout. If the image needs to be refreshed without reinstalling launchd
services, run `portman bridge prepare`.

Route installation is conservative while docker-mac-net-connect is still
running: if a subnet already has a specific `utun` route, Portman leaves it in
place and keeps reconciling. After the legacy bridge stops and the route
disappears, Portman can claim the missing labelled-network route without
mutating chipmk resources or Docker containers.

`portman doctor` is the read-only default-driver check. It reports daemon
reachability, bridge health/mode, setup-image status, docker-mac-net-connect
presence/service status, labelled Docker networks, route interfaces for their
subnets, and explicit commands for stopping the legacy bridge. It does not stop
or uninstall any legacy service.

## Container-Facing Host Access

The regular Docker callback path for arbitrary host services remains
`host.docker.internal:<port>`.

Portman additionally exposes tunnel-side surfaces while the native bridge is
enabled:

- `192.168.99.1:53` for Portman-managed DNS.
- `192.168.99.1:80` for the HTTP proxy.
- `192.168.99.1:443` for the TLS proxy.

This is the Portman-managed path for containers on routed networks: query
`@192.168.99.1` for a managed hostname, then connect normally. HTTP-mode
answers that would be `127.0.0.1` on the host are rewritten to `192.168.99.1`
for containers, so static host apps like `127.0.0.1:3070` flow through the
container-facing proxy. Raw TCP callbacks to arbitrary host ports still use
`host.docker.internal:<port>` until the reserved stable host-callback IP is
implemented.

## Current Evidence

Latest local review evidence, gathered on 2026-04-24:

- `mise run ci` passed: formatter check, clippy with `-D warnings`, 80 Rust
  unit tests plus doctests, and setup-image shell
  syntax check.
- Container resource monitoring is covered by protocol default tests and
  daemon calculation tests for CPU deltas, memory working-set accounting,
  network totals, block IO totals, per-second counter rates, and short/full
  container ID attribution.
- `docker build -t portman-netbridge/setup:local
  crates/portman-netbridge/setup-image` passed for the Portman-owned setup
  image.
- Installed daemon/CLI were refreshed manually. `/usr/local/bin/portman`,
  `/usr/local/bin/portman-daemon`, and
  `/Library/LaunchDaemons/dev.portman.daemon.plist` are `root:wheel`; the
  LaunchDaemon plist and active launchd job include
  `/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin` in `PATH`.
- `portman cert-health` reported mkcert available, CAROOT
  `/Users/dev/Library/Application Support/mkcert`, CAROOT status valid, and 0
  issued certs.
- `/etc/resolver/internal` still starts with `# managed by portman` and points
  at `127.0.0.1` port `5335`.
- `portman status` and `portman bridge status` reported `bridge: healthy` and
  `netbridge: enabled` after install restart.
- The new setup container env no longer exposes `PEER_PRIVKEY`; it emits
  `VM_PUBKEY=<base64>` in logs. `wg show chip0` showed a current handshake.
- Host data-plane probes passed: `ping 192.168.99.2`, `ping 192.168.99.130`,
  `dig @127.0.0.1 -p 5335 pg.acme.internal A`, and
  `nc -vz 192.168.99.131 5432`.
- Docker bridge replacement cutover passed in `docker` mode after stopping
  `homebrew.mxcl.docker-mac-net-connect`: `netstat -rn -f inet` showed
  `172.18` and `192.168.99` routed via Portman's `utun10`, `portman status`
  reported `bridge: healthy`, `netbridge: enabled`, `netbridge mode: docker`,
  and direct probes succeeded for labelled TCP services on both networks:
  `dig @127.0.0.1 -p 5335 mysql84.acme.internal A` -> `172.18.0.4`,
  `dig @127.0.0.1 -p 5335 mysql.archival.internal A` -> `172.18.0.3`,
  `nc -vz mysql84.acme.internal 3306`, `nc -vz mysql.archival.internal 3306`,
  and `nc -vz pg.acme.internal 5432`.
- `cargo run -p portman-cli -- doctor` reported `replacement: ready`, setup
  image `portman-netbridge/setup:local` present, legacy bridge stopped, and
  labelled `dev_default` (`172.18.0.0/16`) plus `portman`
  (`192.168.99.128/25`) routes via `utun10`. `cargo run -p portman-cli --
  bridge status` showed the same labelled route summary.
- New daemon tests pin container-facing service bindings on `192.168.99.1`:
  DNS `:53`, HTTP `:80`, and TLS `:443`. Live container-internal HTTP/TLS
  probes still need to be run after reinstalling this branch.
- Setup image forwarding verification is best-effort: Docker exposes
  `net.ipv4.ip_forward` read-only in this Colima VM, but the value was already
  `1`; the setup container must not exit solely because `sysctl -w` cannot
  rewrite an already-enabled kernel setting.

Not run in that review: uninstall cleanup, fresh TLD resolver add/remove, live
TLS certificate issuance through mkcert, browser HTTPS trust verification, a
container-internal DNS query against `192.168.99.1`, or live comparison of
`portman resources` against `docker stats --no-stream`. Those remain manual
gates because they intentionally mutate local system or Docker networking state
or require a running local workload for useful comparison.

## Flow Matrix

| Flow | Automated evidence | Manual probe before release | Status |
|---|---|---|---|
| TLD add/remove | `tld.rs` validation/marker tests; CLI TLS-mode ordering test | `portman tld add test`, inspect `/etc/resolver/test` marker, `dig foo.test`, `portman tld remove test` | Manual gate |
| Static HTTP | `StaticStore` tests; HTTP proxy routing test | Start local server on `127.0.0.1:3070`, `portman add app.test 127.0.0.1:3070`, `curl http://app.test` | Manual gate |
| Static TCP | `StaticStore` TCP tests; DNS TCP-mode answer test; proxy TCP rejection test | `portman add --tcp db.test 127.0.0.1:5432`, verify raw client connects and browser path is rejected | Manual gate |
| Docker label HTTP | Docker label normalization test; DNS/proxy registry tests | Run disposable labelled container on a managed TLD and `curl http://<host>` | Manual gate |
| Docker label TCP | Docker label normalization test; DNS TCP-mode answer test | Run disposable labelled TCP service with `dev.portman.mode=tcp` and verify raw client connection | Manual gate |
| DNS host-facing | Hickory response tests for HTTP loopback, TCP target IP, and loopback rewrite | `dig <host>`, `dig @127.0.0.1 -p 5335 <host>` | Manual gate |
| HTTP proxy | Unit test for Host normalization and upstream forwarding; unit test for TCP-mode rejection | Browser/curl through `:80` with reachable and unreachable targets | Manual gate |
| TLS mkcert | `TlsStore`, launchd PATH, SNI allow-list tests, and `portman cert-health` against installed daemon | `mkcert -install`, `portman tld add test --tls mkcert`, `curl https://app.test` | Partial: daemon mkcert visibility verified; cert issuance still manual |
| Install/uninstall | Launchd plist tests; CLI straggler/kill-argv tests | `portman install`, verify LaunchDaemon/LaunchAgent ownership/mode/status, then `portman uninstall` | Partial: install verified; uninstall still manual |
| Bridge enable/disable | Netbridge route/network/setup ownership tests; daemon status polling tests; setup env excludes VM private key | `portman bridge enable`, inspect status/setup container/chip0, then disable and verify cleanup | Partial: enable/restart/data-plane verified; disable cleanup still manual |
| Docker bridge replacement | Mode persistence tests; Docker route-planning tests; health scope excludes unrelated networks; CLI doctor fixture tests for setup image, legacy bridge guidance, route parsing, and labelled-network rendering | `portman bridge mode docker`, `portman doctor`, stop docker-mac-net-connect, verify labelled containers on compose/default bridge networks resolve and connect | Partial: labelled TCP cutover verified on `dev_default`; broader disposable matrix still manual |
| Container resources | Protocol defaults tests; daemon CPU/memory/network/block-IO calculation tests; per-second counter-rate test; Swift release build | `portman resources`, open Swift Resources pane, compare top rows with `docker stats --no-stream` and confirm network/block IO display as rates rather than lifetime totals | Manual comparison gate |
| Container-facing DNS/proxy | DNS loopback rewrite test; host-facing service bind-plan test for `192.168.99.1:53/:80/:443`; host-facing retry test | Run disposable container on a routed network, query `@192.168.99.1`, then `curl http://<managed-host>` and `curl https://<managed-host>` where TLS is enabled | Manual gate |
| Setup image | Shell syntax check; runtime ownership tests | Docker build/run in a disposable context, inspect `wg show chip0` and `ip addr show chip0` | Manual gate |
| Web dashboard | `portman dashboard`; dashboard Host/Origin tests; protected registry-entry test | Open `http://portman.localhost`, verify status, entries, static add/remove, TLD list, resource usage | Manual gate |

## Risk Register

Release blockers before main-driver-safe use:

- Uninstall cleanup has not been run after the latest launchd/permission
  remediation. Run it in a controlled session and record LaunchDaemon,
  LaunchAgent, binary, socket, and process cleanup.
- Fresh resolver mutation has not been re-run after TLD/TLS ordering changes.
  Verify marker ownership and non-Portman resolver refusal before recommending
  daily use.
- Native bridge trust still requires disable cleanup, daemon restart, VM
  restart, and sleep/wake probes. Current evidence proves installed-daemon
  restart, route restoration, setup container replacement, and host data-plane
  reachability.
- TLS mkcert still needs live certificate issuance and browser/curl trust
  verification. Current evidence proves the installed daemon can find mkcert
  and the user's CAROOT.

High-priority hardening after release blockers:

- Add Swift unit or UI tests for protocol decoding and HTTP-vs-TCP actions.
- Add end-to-end daemon tests around Docker label ingestion with a fake Docker
  event stream or fixture-based integration harness.
- Add a non-destructive install planner/dry-run test so launchd command
  construction and plist destinations can be verified without system mutation.
- Add TLS proxy request-path tests comparable to the HTTP proxy tests, with a
  fixture certificate resolver instead of mkcert.
- Add a safe live-probe harness that records bridge state before/after and never
  sends `BridgeDisable` without explicit confirmation.

Accepted residual risk for now:

- Docker image build is not part of CI because it mutates local Docker image
  state and can depend on external package availability. Keep shell syntax in
  CI; use `portman install` or `portman bridge prepare` to build the setup
  image outside the safe baseline.
