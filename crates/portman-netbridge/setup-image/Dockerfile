# portman-netbridge VM-side setup container.
#
# One-shot image that runs inside colima's Linux VM, configures a
# WireGuard interface `chip0` that peers with the macOS-host tunnel
# (see `src/tunnel.rs` in the portman-netbridge crate for the
# counterparty), then blocks so the interface persists for the life
# of the container.
#
# Runtime requirements (passed by the caller — Phase B.2b wires
# these via bollard):
#
#   - `--network host`       — use the colima VM's root netns so chip0
#                              is visible to containers on other docker
#                              networks and to the WG kernel module.
#   - `--cap-add NET_ADMIN`  — required to create WG interface + set
#                              routes.
#   - `-e HOST_PUBKEY=...`   — base64 public key from portman-netbridge
#                              host tunnel.
#   - `-e HOST_ENDPOINT=...` — where the host's UDP listener is
#                              reachable from inside the VM, typically
#                              `host.lima.internal:51820` (or
#                              `host.docker.internal:51820`).
#   - `-e PEER_CIDR=...`     — VM-side tunnel IP with mask, e.g.
#                              `192.168.99.2/25`.
#   - `-e ALLOWED_IPS=...`   — what the host will send us, e.g.
#                              `192.168.99.0/24`.
#
# The image generates the VM-side private key internally and prints only
# `VM_PUBKEY=<base64>` for the host runtime to consume. It also accepts
# legacy `PEER_PRIVKEY` so already-installed daemons keep working during
# rolling upgrades; new runtimes do not pass that env var.
#
# The image stays tiny on purpose: no shell beyond what alpine ships,
# no extra tools. If anything goes wrong, exit non-zero with a clear
# message — the caller parses our stderr to surface it.

FROM alpine:3.21

RUN apk add --no-cache \
    wireguard-tools \
    iproute2 \
    iptables

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
