#!/bin/sh
# portman-netbridge VM-side setup.
#
# Reads keys + endpoints from env, brings up chip0, stays alive.
# Every failure path exits non-zero so bollard sees it and the
# macOS-side supervisor can surface a clear error.

set -eu

PRIVKEY_FILE=""
RULE_COMMENT="portman-netbridge"

iptables_has() {
    table="$1"
    chain="$2"
    shift 2
    iptables -t "$table" -C "$chain" "$@" >/dev/null 2>&1
}

iptables_insert() {
    table="$1"
    chain="$2"
    shift 2
    if ! iptables_has "$table" "$chain" "$@"; then
        iptables -t "$table" -I "$chain" 1 "$@"
    fi
}

iptables_delete_all() {
    table="$1"
    chain="$2"
    shift 2
    while iptables_has "$table" "$chain" "$@"; do
        iptables -t "$table" -D "$chain" "$@" || break
    done
}

install_forwarding_rules() {
    # Docker Engine 29 installs raw-table direct-routing drops for bridge
    # container IPs before filter/FORWARD can see the packet. Portman's
    # WireGuard interface is the trusted VM ingress path, so accept chip0
    # packets before those Docker isolation drops and allow forwarding through
    # the bridge firewall. Host-side route ownership still limits which Docker
    # subnets macOS can send into the tunnel.
    iptables_insert raw PREROUTING -i chip0 -m comment --comment "$RULE_COMMENT" -j ACCEPT
    iptables_insert filter FORWARD -i chip0 -m comment --comment "$RULE_COMMENT" -j ACCEPT
    iptables_insert filter FORWARD -o chip0 -m comment --comment "$RULE_COMMENT" -j ACCEPT
}

cleanup_forwarding_rules() {
    iptables_delete_all raw PREROUTING -i chip0 -m comment --comment "$RULE_COMMENT" -j ACCEPT
    iptables_delete_all filter FORWARD -i chip0 -m comment --comment "$RULE_COMMENT" -j ACCEPT
    iptables_delete_all filter FORWARD -o chip0 -m comment --comment "$RULE_COMMENT" -j ACCEPT
}

cleanup_chip0() {
    if ip link show chip0 >/dev/null 2>&1; then
        ip link delete chip0 || true
    fi
}

cleanup_privkey() {
    if [ -n "${PRIVKEY_FILE:-}" ] && [ -f "$PRIVKEY_FILE" ]; then
        shred -u "$PRIVKEY_FILE" 2>/dev/null || rm -f "$PRIVKEY_FILE"
    fi
}

cleanup() {
    cleanup_privkey
    cleanup_forwarding_rules
    cleanup_chip0
}

stop() {
    cleanup
    exit 0
}

trap stop INT TERM
trap cleanup EXIT

req() {
    # req VAR_NAME — fail unless $VAR_NAME is set + non-empty.
    eval "val=\${$1:-}"
    if [ -z "${val:-}" ]; then
        echo "portman-netbridge-setup: env var $1 is required but unset" >&2
        exit 2
    fi
}

req HOST_PUBKEY
req HOST_ENDPOINT
req PEER_CIDR
req ALLOWED_IPS

PRIVKEY_FILE="$(mktemp)"
chmod 600 "$PRIVKEY_FILE"

if [ -n "${PEER_PRIVKEY:-}" ]; then
    # Backward compatibility for already-installed daemons that still pass the
    # VM private key in Docker env. New runtimes omit PEER_PRIVKEY.
    printf '%s\n' "$PEER_PRIVKEY" > "$PRIVKEY_FILE"
else
    # Generate the VM-side private key inside the setup container so it never
    # appears in Docker inspect output, process env, or host-side logs.
    wg genkey > "$PRIVKEY_FILE"
fi

VM_PUBKEY="$(wg pubkey < "$PRIVKEY_FILE")"

# Clean up any stale chip0 from a previous container — the VM keeps
# WG interfaces across container lifetimes, so we idempotently
# replace it.
if ip link show chip0 >/dev/null 2>&1; then
    cleanup_chip0
fi

ip link add dev chip0 type wireguard

# Configure before bringing the link up: WG rejects traffic until
# private-key is set.
wg set chip0 \
    listen-port 51820 \
    private-key "$PRIVKEY_FILE" \
    peer "$HOST_PUBKEY" \
    endpoint "$HOST_ENDPOINT" \
    allowed-ips "$ALLOWED_IPS" \
    persistent-keepalive 25

ip addr add "$PEER_CIDR" dev chip0
ip link set up dev chip0

# Docker usually enables forwarding in the VM. Some Docker hosts expose this
# sysctl read-only to containers even with NET_ADMIN, so assert it best-effort
# without failing setup when the VM already has forwarding enabled.
if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
        echo "portman-netbridge-setup: warning: could not verify net.ipv4.ip_forward=1" >&2
    fi
fi

install_forwarding_rules

# Shred the tmpfile — the key is now held only by kernel WG state.
cleanup_privkey
PRIVKEY_FILE=""

echo "VM_PUBKEY=$VM_PUBKEY"
echo "portman-netbridge-setup: chip0 up, peered with host at $HOST_ENDPOINT"
echo "portman-netbridge-setup: chip0 forwarding rules installed"
wg show chip0

# Tail forever so the container keeps running + the WG interface
# persists. Keep the shell as PID 1 so SIGTERM can delete chip0 before
# Docker removes the container.
tail -f /dev/null &
wait "$!"
