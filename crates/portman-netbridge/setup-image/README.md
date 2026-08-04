# portman-netbridge setup image

Tiny alpine-based container that configures a WireGuard interface
(`chip0`) inside colima's VM, peered with the macOS-host tunnel
managed by the `portman-netbridge` crate. One-shot bring-up, then
blocks so the interface persists for the life of the container.

Runtime:

```sh
docker build -t portman-netbridge/setup:local crates/portman-netbridge/setup-image
docker run -d --rm --name portman-netbridge-setup \
  --network host \
  --cap-add NET_ADMIN \
  -e HOST_PUBKEY="<host base64 pubkey>" \
  -e HOST_ENDPOINT="host.lima.internal:51820" \
  -e PEER_CIDR="192.168.99.2/25" \
  -e ALLOWED_IPS="192.168.99.0/24" \
  portman-netbridge/setup:local
```

The setup container generates the VM-side private key internally and prints
`VM_PUBKEY=<base64>` on startup. The host runtime reads that public key from
container logs; the private key is not passed through Docker env.

The setup container also marks `chip0` as Portman's trusted VM ingress
interface in iptables. Docker bridge networks install isolation rules that
otherwise block direct routing to container IPs; accepting packets that arrive
from the private WireGuard interface keeps host-to-container TCP working while
host-side routes still decide which Docker subnets are reachable.

For rolling upgrades, the image also accepts legacy `PEER_PRIVKEY` from older
installed daemons and derives the same `VM_PUBKEY` from it. New daemon code does
not set `PEER_PRIVKEY`.

From the crate directory, the build context is `./setup-image`:

```sh
cd crates/portman-netbridge
docker build -t portman-netbridge/setup:local ./setup-image
```

Safe static check, used by repository CI:

```sh
sh -n crates/portman-netbridge/setup-image/entrypoint.sh
```

The Docker build/run commands above mutate local Docker state and may pull
packages, so they are manual verification probes, not part of `mise run ci`.

Verify:

```sh
docker exec portman-netbridge-setup wg show chip0
docker exec portman-netbridge-setup ip addr show chip0
```

From the macOS host, with the B.1d `tunnel_encrypt` example running
(or the daemon's Phase B.2b wire-up), pinging `192.168.99.2` should
trigger a handshake that completes inside WireGuard's ~100 ms budget,
at which point subsequent pings get echo replies through the tunnel.

## Why `--network host`?

The setup image runs in the VM's root network namespace on purpose.
`chip0` needs to be reachable from *other* docker networks' containers
(Phase B.3 onwards — the `portman` docker network's containers route
their gateway traffic through chip0 via VM-side iptables). A
container-local netns would isolate chip0 from them.

## Why `NET_ADMIN`?

Required by `ip link add ... type wireguard`, `wg set`, and
`ip addr`/`ip link` operations on chip0. The image is otherwise
minimal and intentionally single-shot; the alpine base has no running
services.

## Idempotency

The entrypoint deletes any stale `chip0` before creating a fresh one.
Safe to re-run across container restarts or colima VM restarts
(the latter wipes chip0 anyway; this just handles the former).

On graceful container stop, the entrypoint deletes `chip0` before exit.
That matters because the image runs in the VM host network namespace:
Docker removing the container is not, by itself, proof that kernel
interfaces created there were removed.
