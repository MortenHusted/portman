#!/bin/bash
#
# Minimal macOS sudo askpass helper.
#
# Usage: set SUDO_ASKPASS to the absolute path of this file, then run
#   sudo -A <command>
# macOS pops a native password dialog. Password flows: dialog -> osascript
# -> stdout of this script -> sudo. Never touches the caller's shell or
# Claude Code's context.
#
# Install globally:
#   chmod 700 ~/projects/portman/.tools/sudo-askpass.sh
#   # Add to ~/.zshrc (or whichever rc file is active):
#   export SUDO_ASKPASS="$HOME/projects/portman/.tools/sudo-askpass.sh"
# Then sudo -A works everywhere.
#
# If you'd rather not export the var globally, prefix one-off commands:
#   SUDO_ASKPASS=~/projects/portman/.tools/sudo-askpass.sh sudo -A <command>
#
# Security notes:
# - The dialog is unmistakable (native Cocoa, caution icon, says "sudo
#   password"). You see every request.
# - The script is owned by you, mode 700 -> only you can read/execute.
# - The password is never written to a file, never persisted, never logged.

osascript \
  -e 'tell application "System Events" to display dialog "sudo password:" with hidden answer default answer "" with icon caution with title "sudo (via askpass)"' \
  -e 'text returned of result' \
  2>/dev/null
