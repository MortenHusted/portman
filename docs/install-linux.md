# Installing portman on Linux

A walkthrough for getting portman running on a Linux box. Tested on Ubuntu 24.04; other systemd distros should behave the same, but expect small differences and please file what you hit.

## What you need

- systemd, with **systemd-resolved** running (`systemctl is-active systemd-resolved`). Most Ubuntu/Fedora/Arch setups have it; if your distro resolves DNS some other way, portman's TLD integration won't apply and you'd need to point `.test` (or your chosen TLD) at `127.0.0.1:5335` yourself.
- **Docker**, if you want container routing (`dev.portman.host` labels). Not required for the service runner or static rules.
- `sudo` access. The daemon runs as root (it binds `:80`/`:443`); services you declare run as your login user.

## 1. Get the binaries

Any one of these:

```bash
# Homebrew on Linux
brew install MortenHusted/tap/portman

# Shell installer (installs into ~/.cargo/bin or $PORTMAN_INSTALL_DIR)
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/MortenHusted/portman/releases/latest/download/portman-installer.sh | sh

# From source (needs a Rust toolchain and a C compiler)
git clone https://github.com/MortenHusted/portman && cd portman
cargo build --release -p portman
```

## 2. Install the system service

```bash
portman install
```

This copies `portman` and `portman-daemon` to `/usr/local/bin`, writes a systemd unit to `/etc/systemd/system/portman-daemon.service`, and starts it. It prompts for `sudo` where needed. No repo checkout is required — when run outside a checkout, it installs the binaries it's running from.

Check it took:

```bash
systemctl is-active portman-daemon   # active
portman status                       # daemon version, ports, socket
```

The daemon needs Docker reachable at startup if you plan to use container routing; without Docker it exits, so install Docker first or check `journalctl -u portman-daemon` if the unit flaps.

## 3. Register a TLD

```bash
sudo portman tld add test
```

This writes a drop-in at `/etc/systemd/resolved.conf.d/portman-test.conf` pointing `~test` at portman's DNS (`127.0.0.1:5335`) and restarts `systemd-resolved` — a restart, not a reload, because resolved does not re-read config drop-ins on reload.

Verify:

```bash
resolvectl status | grep -A 3 Global   # DNS Servers: 127.0.0.1:5335
```

`.test` is the safe default (RFC 2606 reserved). portman warns about TLDs with known conflicts and refuses to overwrite resolver config it didn't write (a VPN's split-DNS, say).

## 4. Route something

A static rule for anything listening on the host:

```bash
python3 -m http.server 8099 --bind 127.0.0.1 &
portman add web.test 127.0.0.1:8099
resolvectl query web.test    # 127.0.0.1
curl http://web.test/        # served through portman's :80 proxy
```

A container, via labels — on Linux the container's IP is natively routable, no bridge needed:

```bash
docker run -d -l dev.portman.host=ctr.test -l dev.portman.port=80 nginx:alpine
curl http://ctr.test/
```

A supervised service, from a `portman.toml` in any repo:

```toml
[service.web]
run = "bin/rails server -p 3000"
port = 3000
host = "myapp.test"
```

```bash
portman up
curl http://myapp.test/
portman logs web -f
```

The dashboard is at `http://127.0.0.1:7341` (`portman dashboard` opens it).

## Uninstall

```bash
portman uninstall            # stops and removes the unit + binaries
sudo portman tld remove test # removes the resolved drop-in
rm -rf ~/.local/share/portman  # optional: state, logs, certs
```

## Troubleshooting

- **`portman status` says permission denied on the socket** — the daemon chowns its data dir (`~/.local/share/portman`) to your login user at startup; if you installed as root without `SUDO_USER` set, check the unit file's `Environment=SUDO_USER=` line matches your user, then `sudo systemctl restart portman-daemon`.
- **Names don't resolve after `tld add`** — check `resolvectl status`; the Global section should list `127.0.0.1:5335`. If not, `sudo systemctl restart systemd-resolved`.
- **The unit won't stay up** — `journalctl -u portman-daemon --no-pager | tail -50`. The most common cause is Docker not running at daemon startup.
- **Port 80/443 already taken** — another proxy (nginx, traefik, caddy) owns them; stop it or expect the daemon to fail its bind.
