#!/usr/bin/env bash
set -euo pipefail

# Installs Nix from its official release tarball, checked against a pinned hash, and fails unless
# Nix applies exactly the settings in nix.conf, which the image builds rely on

NIX_VERSION=2.35.2
NIX_TARBALL_SHA256=0c3960a9792331a22081c3c7a5d8465db9b17c50b3acdf18587fa4c6f2cb1158

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE="nix-$NIX_VERSION-x86_64-linux"
TMP_DIR="$(mktemp -d)"
NIX=/nix/var/nix/profiles/default/bin/nix

curl -fsSL -o "$TMP_DIR/$RELEASE.tar.xz" "https://releases.nixos.org/nix/nix-$NIX_VERSION/$RELEASE.tar.xz"
echo "$NIX_TARBALL_SHA256  $TMP_DIR/$RELEASE.tar.xz" | sha256sum -c
tar -xJf "$TMP_DIR/$RELEASE.tar.xz" -C "$TMP_DIR"
"$TMP_DIR/$RELEASE/install" --daemon --yes --no-channel-add --nix-extra-conf-file "$SCRIPT_DIR/nix.conf"

# Nix merges settings from several files and environment variables, and only warns about a
# misspelled one. So compare the settings it applies for the calling user, who evaluates the
# builds, and for root, whose daemon runs them, warnings included, with those it derives from
# nix.conf alone
expected_settings() {
  "$@" env -i NIX_CONF_DIR="$SCRIPT_DIR" NIX_USER_CONF_FILES= "$NIX" config show | sed "s|$SCRIPT_DIR|/etc/nix|"
}
diff <(expected_settings) <("$NIX" config show 2>&1)
diff <(expected_settings sudo) <(sudo env -i "$NIX" config show 2>&1)

# The daemon doesn't trust the calling user, so it ignores the settings the user sends, and
# neither its command line nor its environment changes its settings
"$NIX" store info --json | grep -xF "{\"trusted\":false,\"url\":\"daemon\",\"version\":\"$NIX_VERSION\"}"
DAEMON_PID="$(systemctl show --property MainPID --value nix-daemon.service)"
ps -o args= -p "$DAEMON_PID" | grep -xF 'nix-daemon --daemon'
DAEMON_ENV="$(sudo cat "/proc/$DAEMON_PID/environ" | tr '\0' '\n')"
if grep -E '^(_?NIX_|XDG_|HOME=)' <<< "$DAEMON_ENV"; then exit 1; fi

# Nor does the calling user's environment point Nix at another daemon or store
if env | grep -E '^_?NIX_'; then exit 1; fi
