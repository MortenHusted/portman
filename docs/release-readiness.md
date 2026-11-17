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
  network (`192.168.99.128/25`, inside the routed `192.168.99.0/24`). Existing
  compose default networks are untouched.
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

Portman reconciles its dedicated `192.168.99.0/24` route to the current bridge
every five seconds, even if the route points at another live `utun` (for example,
a recycled interface name now used by a VPN). For other Docker subnets, route
installation is conservative while docker-mac-net-connect is still running:
Portman leaves specific routes through foreign live `utun` interfaces in place
and keeps reconciling. After the legacy bridge stops and the route
disappears, Portman can claim the missing labelled-network route without
mutating chipmk resources or Docker containers.

Bridge health asks for a route to the `portman` network alone for a labelled
container that the registry routes to its address on that network, and for a
route to each network of any other labelled container. So a missing route to
the second network of a container on `portman` leaves the health at `healthy`.
While the native bridge is up, health reports `routes_missing` when one of the
routes it asks for goes through a different live interface; interface existence
alone does not prove the route reaches Portman's bridge.

`portman doctor` is the default-driver check. It reports daemon
reachability, bridge health/mode, setup-image status, docker-mac-net-connect
presence/service status, labelled Docker networks, route interfaces for their
subnets, and explicit commands for stopping the legacy bridge. Its verdict on
the routes is the bridge health that the daemon reports, so `replacement:
ready` needs `bridge: healthy`. The daemon assesses the health every 5 s, when
the engine connects or goes, and each time the bridge loop publishes its
state. That loop publishes on every pass: for each `portman bridge mode`,
`enable` and `disable`, each start and stop of a bridge, each failed start and
its retry, each check and retry of the DNS forwarder, and each change of the
managed TLDs. For a bridge that is up in `docker` mode with a health other
than `healthy`, doctor reads the status again for up to 6 s and gives the
verdict of the last reading, so that a run right after `portman bridge enable`
or a mode change does not give a verdict from before the bridge. A read that
the daemon does not answer ends at that bound too. Doctor prints nothing while
it waits. In `opt-in` and `all` mode doctor reads the status once. Against a
daemon up to 0.1.7, its `bridge:` word can then be up to 5 s old. The
labelled-network lines show what the `docker` CLI and the routing table say.
It does not stop
or uninstall any legacy service. On macOS it also reports the DNS forwarder. For a
forwarder that runs while the bridge is up, it starts one short-lived
container that looks a registered hostname up through `192.168.99.129`. The
engine removes that container when the lookup ends. Doctor ends a lookup that
takes longer than 8 s and removes the container by its name. Nothing else
that doctor does changes Docker state.

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

The DNS listener on `192.168.99.1:53` answers `REFUSED` for a name that the
registry does not hold, for every query type. Do not give it to a container as
its resolver: the container's other lookups would fail. It is the first
upstream of the forwarder below.

## Container DNS Forwarder

While the native bridge is up, the daemon keeps one container in the VM,
`portman-netbridge-dns`, from the setup image. It runs `dnsmasq` on the VM's
host network and listens on `192.168.99.129:53`, the gateway address of the
`portman` Docker network. A container opts in with `--dns 192.168.99.129` or
the compose line `dns: [192.168.99.129]`.

- A name under a managed TLD goes to `192.168.99.1` first and to the VM's own
  resolver second, in strict order. That holds for a query with or without
  EDNS options from dnsmasq 2.91 on, which is why the setup image is built on
  Alpine 3.22 or later. Over TCP dnsmasq asks the first server only, so a
  name that portman does not hold gets `REFUSED` there.
- `host.docker.internal` and every other name go to the VM's own resolver
  only.
- The daemon looks at the container at each bridge start, at each change of
  the managed TLD set, and once more a minute after it started one. It replaces a container that does not run, runs
  another command, or comes from another build of the setup image, and leaves
  it as it is otherwise.
- A container with the right command from the current image that the engine
  starts again and again is also left as it is. The daemon log says so once
  and names `docker logs portman-netbridge-dns`.
- The forwarder keeps no answer (`--cache-size=0`), so neither an answer nor
  a denial from the VM's resolver hides a name that portman registers
  afterwards.
- A daemon stop, a lost Docker session, and a bridge mode change leave the
  container running. `portman bridge disable` removes it before it removes the
  `portman` network, also when the engine then keeps a network that is in
  use. A forwarder that could not be removed beside such a network stays
  until the next disable. With no engine reachable at the disable, the daemon
  removes both in the next Docker session, unless the daemon restarts first.
- `portman uninstall` removes the setup container, the forwarder and the
  network by the same rules, and leaves the saved bridge state as it is. It
  removes the plist and the daemon's binary first and waits up to 30 s for
  the daemon to exit. It then asks the engine whether or not the daemon is
  gone. A daemon that still runs a bridge holds the bridge's UDP port, and
  nothing is removed then.
- The uninstall gives the engine 35 s for the removal. When the engine gives
  no answer in that time, when another process holds the port, or when the
  engine refuses a removal, the uninstall prints the commands that remove the
  forwarder and the network by hand, says when not to run them, and
  completes. With no engine reachable it prints them only when the saved
  bridge state is on.
- A setup image without the label `dev.portman.dns-forwarder=1` cannot run the
  forwarder. The bridge then works as before, the daemon log and `portman
  doctor` name `portman bridge prepare` as the fix, and the daemon looks at
  the image again every minute while the bridge is up.

Manual gates, on an installed build with the bridge up and a registered HTTP
route `web.demo.test` and a TCP route `db.demo.test` to a container on the
`portman` network:

1. Start a container with no `dns` option, before and after the upgrade.
   Confirm that `example.com` resolves in both and that `/etc/resolv.conf` in
   the container is the same in both.
2. Start a container on a compose network with `--dns 192.168.99.129`.
   Confirm that `web.demo.test` resolves and `curl http://web.demo.test`
   returns 200. Confirm that `db.demo.test` resolves and that a TCP connection
   to it fails. Attach the container to the `portman` network too, and confirm
   that the connection opens.
3. In the same container, confirm that `example.com` and
   `host.docker.internal` each resolve in under 1 s, to the answers that a
   container without the option gets.
4. Repeat gates 2 and 3 on the default `bridge` network with an Alpine image
   and with a Debian or Ubuntu image. With a managed TLD that also holds names
   portman does not own, look one such name up and confirm the answer that a
   container without the option gets.
5. Run `portman tld add` for another TLD and add a static rule under it.
   Confirm that the new hostname resolves through the forwarder within 10 s.
6. Stop the daemon. Confirm that `example.com` and `host.docker.internal`
   still resolve in under 1 s and that only `web.demo.test` fails.
7. Restart the VM. Confirm that `portman-netbridge-dns` runs again with no
   portman command, and that `example.com` resolves through it before the
   bridge reports healthy.
8. Save `scutil --dns`, `/etc/resolv.conf`, the file list of `/etc/resolver`,
   and `netstat -rn` before the upgrade and after gates 2 to 7. Confirm that
   the only differences are routes on portman's own `utun`.
9. Run `portman bridge disable`. Confirm that `portman-netbridge-dns` is gone
   and that `portman doctor` prints `dns forwarder: absent`. Run `portman
   bridge enable`. Confirm that the container runs and that doctor prints
   `dns forwarder: running at 192.168.99.129`.
10. Build `portman-netbridge/setup:local` from the `setup-image` folder of
    the release before this feature, and enable the bridge. Confirm that the
    bridge comes up and that doctor prints `dns forwarder: unavailable`. Run
    `portman bridge prepare`. Confirm that `portman-netbridge-dns` runs within
    a minute.
11. From a container with `--dns 192.168.99.129`, look `late.demo.test` up
    before it is registered. Register it, and confirm that the next lookup
    resolves it.
12. Stop the VM, run `portman bridge disable`, and start the VM. Confirm that
    `portman-netbridge-dns` and the `portman` network are gone.

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
| Container-facing DNS/proxy | DNS loopback rewrite test; response-code test of both DNS listeners for held and unheld names; host-facing service bind-plan test for `192.168.99.1:53/:80/:443`; host-facing retry test | Run disposable container on a routed network, query `@192.168.99.1`, then `curl http://<managed-host>` and `curl https://<managed-host>` where TLS is enabled | Manual gate |
| Container DNS forwarder | Forwarder argument tests; entrypoint `dns` mode tests with a stand-in `dnsmasq`; replace-or-keep decision tests; removal tests against a fake engine; control-loop tests under paused time; doctor line tests | The twelve gates under "Container DNS Forwarder" | Manual gate |
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


## Managed broker qualification (2026-09-19)

The protected-route implementation passed 341 workspace tests, native all-target
Clippy with warnings denied, and formatting. A static `x86_64-unknown-linux-musl`
daemon built with `cargo zigbuild` passed the standalone
`crates/portman-daemon/tests/managed_broker_probe.py` on a Linux x86_64 dev box
without Docker. The probe uses a temporary home/XDG directory, explicit ephemeral
ports, a synthetic local upstream and synthetic credentials, then stops its
processes and deletes its state. No installed services or agent profiles change.

Verified through actual IPC and HTTP: separate admin authentication; rejection
before upstream connection for missing, wrong, duplicate and wrong-route bearers;
provider injection without forwarding the local bearer; persisted route
protection; denied service/bridge starts; revocation and expiry after restart;
clock rollback denial after restart; legacy-mode reopening refusal; and absence
of synthetic credentials from daemon logs. Unit tests separately cover denying
service definitions/watchers and existing service state.

Qualified binary SHA-256:
`cd6a20da0fee6dff46acef0a0da8001b65357753de2546186a30b54d8f78668c`.
The linker emitted its existing deprecated optimization-setting warning; the
build and Linux runtime checks succeeded. This qualifies the broker contract,
not Landlock/harness launch integration or deployment.

After rebasing onto fresh `origin/main`, Clippy remained green. A parallel suite
run hit two existing supervisor timing assertions (`stop_terms_then_kills_a_term_ignoring_child`
and `sync_restarts_changed_and_stops_removed`); the full serial suite passed all
341 tests. The revision-aware Linux probe was repeated successfully against the
binary above. The inherited instruction-file-only commit was excluded from this
feature branch while the root checkout retained it.
