#!/usr/bin/env bash
# setup-sudoers.sh — write /etc/sudoers.d/portman so the routine
# `portman install` loop (build → copy binaries → reload daemon) runs without
# a password prompt.
#
# Run once:
#   ./scripts/setup-sudoers.sh          # self-elevates (asks for your password once)
#   sudo ./scripts/setup-sudoers.sh     # or run it under sudo directly
#
# Scope — deliberately narrow. Every rule is an exact command with pinned
# arguments; there is NO tee/chown/chmod rule, because a passwordless write of
# arbitrary content to a root launchd plist is a passwordless-root primitive.
# The installer skips the plist write when the installed plist is identical
# (the common case); a rare plist-template change prompts for a password once.
#
# There is likewise NO `kill` rule. `portman install` sweeps straggling
# root-owned portman-daemon processes between bootout and bootstrap, but pids
# are dynamic, so the only sudoers form that would cover it is a wildcard —
# i.e. passwordless "terminate any process on this machine as root". Not worth
# it for a convenience step: the sweep runs `sudo -n` and, if refused, prints
# the pids and the exact command to finish the job by hand. `launchctl bootout`
# has already stopped the launchd-managed daemon by that point, so the sweep
# only matters for a dev daemon left over from `mise run daemon-root`.
#
# Residual risk (inherent to the workflow): the pinned install rule turns the
# repo's build output into a root-run daemon, and the build output is writable
# by this user. That is the point of the tool — you build your own daemon — but
# it means passwordless install is only as trustworthy as this user account.
#
# The fragment is validated with `visudo -c` BEFORE it is installed, so a typo
# can never leave you with a broken sudoers file that locks you out of sudo.
set -euo pipefail

# The account that will run `portman install` — the invoking user even under sudo.
REAL_USER="${SUDO_USER:-$(id -un)}"

# Pin the build-output paths to this checkout (matches CARGO_TARGET_DIR in
# cmd_install). Rerun this script if the repo moves.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE_DIR="${REPO_ROOT}/target/portman-install/release"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# One command per line, no continuations — exact matches for what
# `portman install` / `portman uninstall` run under sudo.
cat > "$TMP" <<EOF
# Managed by portman scripts/setup-sudoers.sh — passwordless portman (re)install for ${REAL_USER}.
${REAL_USER} ALL=(root) NOPASSWD: /bin/mkdir -p /usr/local/bin
${REAL_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 0755 ${RELEASE_DIR}/portman-daemon /usr/local/bin/portman-daemon
${REAL_USER} ALL=(root) NOPASSWD: /usr/bin/install -m 0755 ${RELEASE_DIR}/portman /usr/local/bin/portman
${REAL_USER} ALL=(root) NOPASSWD: /bin/launchctl bootout system/dev.portman.daemon
${REAL_USER} ALL=(root) NOPASSWD: /bin/launchctl bootout system/dev.portman.menubar
${REAL_USER} ALL=(root) NOPASSWD: /bin/launchctl bootstrap system /Library/LaunchDaemons/dev.portman.daemon.plist
${REAL_USER} ALL=(root) NOPASSWD: /bin/rm -f /usr/local/bin/portman-daemon
${REAL_USER} ALL=(root) NOPASSWD: /bin/rm -f /usr/local/bin/portman-menubar
EOF

# Validate the fragment on its own before it touches /etc.
if ! visudo -cf "$TMP" >/dev/null; then
  echo "refusing to install: sudoers fragment failed validation" >&2
  exit 1
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi

# Install atomically with the correct owner/mode, then re-validate in place.
$SUDO install -m 0440 -o root -g wheel "$TMP" /etc/sudoers.d/portman
$SUDO visudo -cf /etc/sudoers.d/portman >/dev/null

echo "OK: /etc/sudoers.d/portman installed for ${REAL_USER} — the routine 'portman install' loop is passwordless."
echo "    (A plist-template change still prompts once; that's intentional.)"
